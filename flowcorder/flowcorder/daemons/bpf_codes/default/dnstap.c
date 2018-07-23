#define KBUILD_MODNAME "dns_bpf_exporter"
#include <uapi/linux/bpf.h> /* __sk_buff */
#include <uapi/linux/in.h> /* IPPROTO_UDP */
#include <net/ipv6.h> /* NEXTHDR */
#include <bcc/proto.h> /* ethernet_t, ... */


#define DROP (0)
#define ACCEPT (-1)

#ifndef MAX_IPV6_DEPTH
#define MAX_IPV6_DEPTH 5
#endif

#ifndef DNS_DST_PORT
#define DNS_DST_PORT (53)
#endif

enum dns_status {
	STATUS_QUERY = 1,
	STATUS_ANSWER = 2,
	STATUS_FAIL = 3,
};

struct dnshdr
{
	u16 id;
	u16 flags;
	u16 qdcount;
	u16 ancount;
	u16 nscount;
	u16 arcount;
} BPF_PACKET_HEADER;

struct dns_conn {
	u16 sport;
	u16 id;
	unsigned __int128 saddr;
	unsigned __int128 daddr;
};

#define GET_VERSION(version) ((version) & 0x8)
#define MASK_RETRIES(retry) ((retry) & 0x7F)
#define INC_RETRIES(retry) ((GET_VERSION(retry) | MASK_RETRIES(retry)) + 1)
#define IPV4_ID 0x0
#define IPV6_ID 0x8

struct dns_info {
	/* first bit is IP version (1 for v6, 0 for v4), 7 next bits retries */
	u8 version_retries;
	u8 status;
	u16 query_size;
	u16 reply_size;
	u64 first_ts;
	u64 sent_ts;
	u64 reply_ts;
};

BPF_HASH(connection_map, struct dns_conn, struct dns_info);

static inline int demux_dns(struct __sk_buff *skb, u16 udp_cursor,
		struct dns_conn *dns_conn, u8 version, u16 payload_len,
		u16 dport)
{
#define READ_DNS(field) load_half(skb, udp_cursor + sizeof(struct udp_t) +\
		offsetof(struct dnshdr, field))
	dns_conn->id = READ_DNS(id);
	u16 dns_flags = READ_DNS(flags);
	u64 now = bpf_ktime_get_ns() / 1000;  /* in us */
	if (!(dns_flags & (1 << 15))) {
		/* queries should be *sent* to port 53 and
		 * replies *received from* port 53.
		 * I.e. the port to match is the source one for queries and
		 * destination one for answers */
		struct dns_info *previous_info = connection_map.lookup(dns_conn);
		if (!previous_info) {
			struct dns_info info = {0};
			info.sent_ts = now;
			info.first_ts = now;
			info.version_retries = version;
			info.status = STATUS_QUERY;
			info.query_size = payload_len;
			connection_map.insert(dns_conn, &info);
		} else {
			/* This is a retry */
			previous_info->sent_ts = now;
			previous_info->version_retries =
				INC_RETRIES(previous_info->version_retries);
		}
		return ACCEPT;
	}
	/* We're handling a reply, swap values */
	unsigned __int128 temp = dns_conn->saddr;
	dns_conn->saddr = dns_conn->daddr;
	dns_conn->daddr = temp;
	dns_conn->sport = dport;
	struct dns_info *info = connection_map.lookup(dns_conn);
	if (!info) {
#ifdef _DEBUG
		bpf_trace_printk("Dropping DNS reply with not matching query %u\n",
				dns_conn->id);
#endif
		return DROP;
	}
	info->reply_ts = now;
	/* non zero rcode (last 4 bits) indicates and error; empty responses
	 * as well */
	info->status = (dns_flags & 0x000F || !READ_DNS(ancount)) ?
		STATUS_FAIL : STATUS_ANSWER;
	info->reply_size = payload_len;
	/* We assume here that the user-space timeout is large enough that
	 * we _never_ get a reply at about that time (i.e. RTT <<< timeout) as
	 * we would otherwise have a data race between user and kernel space
	 * for the map entry when switching from QUERY->ANSWER if the reply
	 * was arriving late. */
	return ACCEPT;
#undef READ_DNS
}
static inline int demux_udp(struct __sk_buff *skb, u16 cursor,
		struct dns_conn *dns_conn, u8 version, u16 payload_len)
{
#define READ_UDP(field) load_half(skb, cursor + offsetof(struct udp_t, field))
	u16 sport = READ_UDP(sport);
	u16 dport = READ_UDP(dport);
	if (dport == DNS_DST_PORT || sport == DNS_DST_PORT) {
		dns_conn->sport = sport;
		return demux_dns(skb, cursor, dns_conn, version, payload_len,
				dport);
	}
#ifdef _DEBUG
	bpf_trace_printk("Dropping UDP packet on wrong ports %u->%u\n",
			cursor, (u32)dns_conn->daddr);
#endif
	return DROP;
#undef READ_UDP
}

static inline int demux_ip(struct __sk_buff *skb, u16 cursor,
		struct dns_conn *dns_conn)
{
#define READ_IP(method, field) method(skb, cursor +\
		offsetof(struct ip_t, field))
	u8 nextp = READ_IP(load_byte, nextp);
	if (nextp == IPPROTO_UDP) {
		/* Extract IP layer params */
		uint32_t *ptr = (uint32_t *)&dns_conn->saddr;
		*ptr = htonl(READ_IP(load_word, src));
		ptr = (uint32_t *)&dns_conn->daddr;
		*ptr = htonl(READ_IP(load_word, dst));
		u16 payload_len = READ_IP(load_half, tlen);
		/* hlen is last 4bits of the first byte */
		u8 hlen = load_byte(skb, cursor) & 0x0F;
		return demux_udp(skb, cursor + (hlen << 2), dns_conn, IPV4_ID,
				payload_len);
	}
#ifdef _DEBUG
	bpf_trace_printk("Dropping unwanted IP packet protocol %u\n",
			nextp);
#endif
	return DROP;
}

static inline void store_v6_address(unsigned __int128 *dst,
		struct __sk_buff *skb, u16 offset)
{
	/* We need to convert back to big endian */
	u32 *ptr = (u32*)dst;
	/* As we read words in sequence, no need to swap them back */
	ptr[0] = ntohl(load_word(skb, offset));
	ptr[1] = ntohl(load_word(skb, offset + 4));
	ptr[2] = ntohl(load_word(skb, offset + 8));
	ptr[3] = ntohl(load_word(skb, offset + 12));
}

static inline int demux_ipv6(struct __sk_buff *skb, u16 cursor,
		struct dns_conn *dns_conn)
{
	u8 nexthdr = load_byte(skb, cursor +
			offsetof(struct ip6_t, next_header));
	u8 iter_cnt = 0;
	/* Must bound the loop */
	u16 ip6_cursor = cursor;
	cursor += sizeof(struct ip6_t);
	while (iter_cnt < MAX_IPV6_DEPTH) {
		switch (nexthdr) {
			case NEXTHDR_UDP:
				{
					/* Defer copy until we can accept the packet */
					store_v6_address(&dns_conn->saddr, skb,
							ip6_cursor + offsetof(struct ip6_t, src_hi));
					store_v6_address(&dns_conn->daddr, skb,
							ip6_cursor + offsetof(struct ip6_t, dst_hi));
					u16 payload_len = load_half(skb,
							ip6_cursor + offsetof(struct ip6_t, payload_len));
					return demux_udp(skb, cursor, dns_conn, IPV6_ID,
							payload_len);
				}
			case NEXTHDR_FRAGMENT:
				{
					/* Frag headers have fixed 8 bytes size,
					 * i.e. plain ip6_opt_t */
					nexthdr = load_byte(skb, cursor +
							offsetof(struct ip6_opt_t, next_header));
					cursor += sizeof(struct ip6_opt_t);
					break;
				}
			case NEXTHDR_ROUTING:
			case NEXTHDR_DEST:
			case NEXTHDR_MOBILITY:
			case NEXTHDR_HOP:
				{
					nexthdr = load_byte(skb, cursor +
							offsetof(struct ip6_opt_t, next_header));
					cursor += load_byte(skb, cursor +
							offsetof(struct ip6_opt_t, ext_len));
					break;
				}
			default: goto ip6_nxthdr_out;
		}
		++iter_cnt;
	}
ip6_nxthdr_out:
#ifdef _DEBUG
	bpf_trace_printk("Dropping unwanted IPv6 packet next header %u\n",
			nexthdr);
#endif
	return DROP;
}
/* NOTES:
 * - bcc auto replace the header struct read with the bpf LD_ABS, ... insns and
 *   checks for out-of-bounds access (i.e. drop)
 * - read values are put in the host machine endianness!
 * - this requires to read in variables with a 'packet' anotation, i.e. a
 *   struct marked with BPF_PACKET_HEADER
 * - We must unroll any loop, i.e. can only process a finite amount of ipv6 ext
 *   headers.
 * - bpf_htonll appears to generate bugged bpf code?
 * - Using the cursor bbc-based approach generates suboptimal code.
 */
int forward_dns(struct __sk_buff *skb)
{
	struct dns_conn dns_conn = {0};
	u16 frame_type = load_half(skb, 12);
	switch (frame_type) {
		case ETH_P_IP:
			return demux_ip(skb, 14, &dns_conn);
		case ETH_P_IPV6:
			return demux_ipv6(skb, 14, &dns_conn);
#ifdef DOT1Q_SUPPORT
		case ETH_P_8021Q:
			{
				frame_type = load_half(skb, 16);
				switch (frame_type) {
					case ETH_P_IP:
						return demux_ip(skb, 18,
							&dns_conn);
					case ETH_P_IPV6:
						return demux_ipv6(skb, 18,
							&dns_conn);
					default:
						break;
				}
			}
#endif
	}
#ifdef _DEBUG
	bpf_trace_printk("Dropping unknown ethernet/VLAN frame type %u\n",
			frame_type);
#endif
	return DROP;
}
