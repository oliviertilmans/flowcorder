#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "multihoming_tcp_exporter" /* Required yet unused */
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <bcc/proto.h>

#ifdef __HAS_MPTCP
#include <net/mptcp.h>
#endif

/* A lot of forward declarations that come from other files */

struct pt_regs; /* Make the linter happy (BCC/bpf intrinsic) */

/* The transition in the connection lifecycle  */
enum fsm_state;

/* Flow descriptor structure */
struct flow_t;
/* Statistics on a connection that are not kept by the native stack */
struct sock_stats_t;
/* The event reported to user-space */
struct transition_event_t;

/* @@COMPATCHECK linux/tcp.h // Access the nonagle etc bitfield  */
struct repair_byte;
/* struct to access the bit field describing the ca_state */
struct inet_ca_state;

/* Report events to user-space through this perf buffer */
BPF_PERF_OUTPUT(transition_events);

/* Map a pointer to a full pid */
static void store_ptr(u64 pid, u64 ptr);
#define STORE_PTR(ptr) store_ptr(bpf_get_current_pid_tgid(), (ptr))

/* Retrieve a pointer from a pid*/
static u64 fetch_ptr(u64 pid);
#define FETCH_PTR() fetch_ptr(bpf_get_current_pid_tgid())


/* Get the FSM state corresponding to the socket closing status */
static enum fsm_state close_status(int sk_err);
/* Check if a socket is in the namespace assigned to the user-space daemon */
static bool is_in_current_netns(struct sock *sk);

/* Imports from net/ipv4/tcp.c as we need to infer whether an error is going
 * to be triggered or not as the function resets (?) the sk_err flag */
/* @@COMPATCHECK linux/tcp.h || Needed leading _ as mptcp was exporting it */
static bool _tcp_need_reset(int state);

/* Inspect the socket to determines its closing status in terms of errno val */
static int disconnect_get_sk_err(struct sock *sk);

/* Fill a struct flow_t from a socket*/
static void fill_flow(struct flow_t *key, struct sock *sk);

/* Complete a transition by extracting the missing fields from the sk.
 * @evt the struct to complete
 * @sk the socket
 * @new_state the final state for the transition
 */
static void stats_for_transition(struct transition_event_t *evt,
		struct sock *sk, enum fsm_state new_state);

/* report a transition to user-space (gracefully handle mptcp properties) */
static int report_transition(struct pt_regs *ctx, struct sock *sk,
			      enum fsm_state new_state,
			      struct sock_stats_t *stats);

/* Register a new connection attempt on a socket */
static int register_new_connection(struct pt_regs *ctx, struct sock *sk,
		struct transition_event_t *evt);

/* Address-family agnostic connect handler */
static int handle_tcp_connect(struct pt_regs *ctx, struct sock *sk);

/* Address-family post-connect handler */
static int handle_tcp_ret_connect(struct pt_regs *ctx);

/* Track out-of-order segments */
static void handle_ofo_skb(struct sk_buff *skb, struct sock *sk,
		u64 *reordering_bytes, u32 *reordering_dist,
		u32 *reordering_var, u32 *reordering);

/* Return skb->cb.seq */
static u32 skb_tcp_cb_seq(struct sk_buff *skb);

/* Return skb->cb.end_seq */
static u32 skb_tcp_cb_end_seq(struct sk_buff *skb);

/* Return the length of the skb, as given by end_seq - seq, taking into account
 * the extra bytes for SYN/FIN */
static u32 _skb_len(u32 seq, u32 end_seq, struct sk_buff *skb);
static u32 skb_len(struct sk_buff *skb);

/* Return tcp_sock(sk)->snd_nxt */
static u32 tcp_snd_nxt(struct sock *sk);

/* Return tcp_sock(sk)->rcv_nxt */
static u32 tcp_rcv_nxt(struct sock *sk);
/* Return tcp_sock(sk)->bytes_acked */
static u64 tcp_bytes_acked(struct sock *sk);
/* Return tcp_sock(sk)->bytes_rcv */
static u64 tcp_bytes_rcv(struct sock *sk);
/* Return tcp_sock(sk)->total_retrans */
static u32 tcp_total_retrans(struct sock *sk);
/* Return tcp_sock(sk)->rtt_us */
static u32 tcp_rtt_us(struct sock *sk);
/* Return tcp_sock(sk)->mdev_us */
static u32 tcp_mdev_us(struct sock *sk);
/* Return tcp_sock(sk)->rx_opt.mss_clamp */
static u16 tcp_mss(struct sock *sk);
/* return sk->sk_rcvbuf */
static int tcp_sk_rcvbuf(struct sock *sk);
/* return tcp_sock(sk)->packets_out */
static u32 tcp_packets_out(struct sock *sk);
/* Return sk->sk_err */
static int sock_sk_err(struct sock *sk);
/* Return skb->sk */
static struct sock* skb_sk(struct sk_buff*);

/* Return whether a is before (true) b, treated as sequence number */
static bool tcp_before(u32 a, u32 b);

#ifdef __HAS_MPTCP
/* tcp_sock(sk)->mpc == 1*/
static bool is_mptcp(struct sock *sk);
/* Report an mptcp transition */
static int mptcp_report_transition(struct pt_regs *ctx, struct sock *sk,
		enum fsm_state new_state, struct sock_stats_t *stats);
/* Finish connecting a new MPTCP connection */
static int mptcp_finish_new_connect(struct pt_regs *ctx, struct sock *sk);
/* Move the meta_sk to TCP_CLOSE */
static int mptcp_meta_set_state(struct pt_regs *ctx, struct sock *sk, int s);
/* Return mptcp(sk) && mptcp_meta(sk) == sk */
static bool mptcp_is_meta_sk(struct sock *sk);
/* Handle reordering happening on the meta-socket */
static int mptcp_handle_data_queue_ofo(struct sock *sk, struct sk_buff *skb);
static void mptcp_update_procinfo(struct sock *sk);
#endif

enum fsm_state {
	/* Reserve 0 */
	/* New connection */
	TCP_EVENT_NEW = 1,
	/* Established connection, working 'normally' */
	TCP_EVENT_ESTABLISHED,
	/* Fast retransmit */
	TCP_EVENT_FXMIT,
	/* Already acked packet */
	TCP_EVENT_INCAST_DUP,
	/* Oout-of-order event */
	TCP_EVENT_OO,
	/* MPTCP new subflow */
	TCP_EVENT_ADD_FLOW,
	/* MPTCP del subflow */
	TCP_EVENT_REM_FLOW,
	/* RTO timer expiration */
	TCP_EVENT_RTO,  /* Preserve order so states > RTO == terminals */
	/* Connection is over */
	TCP_EVENT_DONE,
	/* Network-related error (as in routing) */
	TCP_EVENT_NET_ERR,
	/* Protocol error */
	TCP_EVENT_PROTO_ERR,
	/* CRITICAL - Instrumentation failure */
	TCP_EVENT_DESYNC_ERR,
};

struct flow_t {
	/* Source address, IPv4 is in the lower 32b */
	unsigned __int128 saddr;
	/* Destination address */
	unsigned __int128 daddr;
	/* Source TCP port */
	u16 sport;
	/* Destination TCP port */
	u16 dport;
	/* Address family (AF_INET/AF_INET6) */
	u16 family;
} __attribute__((packed));

struct sock_stats_t {
	char task[TASK_COMM_LEN]; /* Process name */
	u64 pid; /* TGID/PID */
	u64 duplicate_bytes; /* Bytes already ack'ed yet received again */
	u64 reordering_bytes; /* reordering counter in bytes */
	u64 retransmitted_bytes; /* bytes retransmitted */
	/* Last state that caused the flow to not be TCP_CA_Open */
	u64 transition_start; /* timestamp of when that state was entered */
	u32 duplicate_segments; /* Packets containing duplicate data */
	u32 reordering; /* reordering counter */
	u32 reordering_dist; /* mean reordering distance */
	u32 reordering_var; /* variance reordering distance */
	u16 rto_events; /* number of RTO expiration; cumulative */
	u8 starting_state;
} __attribute__((packed));

struct transition_event_t {
	u64 transition_end; /* Time at which the event was generated */
	u64 bytes_acked; /* Sent bytes */
	u64 bytes_rcv; /* Received bytes */
	struct flow_t flow;
	u16 mss; /* Maximal MSS for the connection, fix alignment */
	struct sock_stats_t stats;
	u8 end_state; /* Final state for this transition */
	u32 rtt_us; /* Current smoothed RTT estimation */
	u32 rtt_dev_us; /* RTT mean deviation */
	u32 retransmitted_segments; /* rentransmitted segment count */
} __attribute__((packed));

/* Map pid to the function param to map kprobe to kretprobe */
BPF_HASH(param_map, u64, u64);
/* Map a tcp connection to its statistics */
BPF_HASH(sock_stats_map, struct sock *, struct sock_stats_t);

static void store_ptr(u64 pid, u64 ptr)
{
	param_map.update(&pid, &ptr);
}

static u64 fetch_ptr(u64 pid)
{
	u64 *ptr = param_map.lookup(&pid);
	if (!ptr) {
		return 0;
	}
	u64 val = *ptr;
	param_map.delete(&pid);
	return val;
}

static enum fsm_state close_status(int sk_err)
{
	if (!sk_err)
		return TCP_EVENT_DONE;
	sk_err = sk_err >= 0 ? sk_err : -sk_err;
	/* Identify error */
	switch (sk_err) {
	case ENONET:
	case ENETDOWN:
	case ENETUNREACH:
	case ENETRESET:
	case ENOLINK:
	case EPIPE:
	case ETIMEDOUT:
		return TCP_EVENT_NET_ERR;
	/* case ECONNRESET: */
	/* case ECONNREFUSED: */
	/* case EHOSTUNREACH: */
	/* case EPROTO: */
	/* case EOPNOTSUPP: */
	/* case ECONNABORTED: */
	default:
		return TCP_EVENT_PROTO_ERR;
	}
}

static bool is_in_current_netns(struct sock *sk)
{
#ifdef CONFIG_NET_NS
	struct net *net = NULL;
	u32 net_num = 0;
	bpf_probe_read(&net, sizeof(net), ((const char *)sk) +
		       offsetof(struct sock, __sk_common.skc_net.net));
	bpf_probe_read(&net_num, sizeof(net_num), ((const char *)net) +
		       offsetof(struct net, ns.inum));
	/* Filter to exporter netns only if available */
	if (net_num != CURRENT_NET_NS)
		return false;
#endif
	return true;
}

static void fill_flow(struct flow_t *key, struct sock *sk)
{
#define skc_off(field) (((const char *)sk) +\
		offsetof(struct sock, __sk_common.skc_##field))

	bpf_probe_read(&key->sport, sizeof(key->sport), ((const char *)sk)
			+ offsetof(struct inet_sock, inet_sport));
	bpf_probe_read(&key->dport, sizeof(key->dport), skc_off(dport));
	key->sport = ntohs(key->sport);
	key->dport = ntohs(key->dport);
	bpf_probe_read(&key->family, sizeof(key->family), skc_off(family));
	if (key->family == AF_INET) {
		bpf_probe_read(&key->saddr, 4, skc_off(rcv_saddr));
		bpf_probe_read(&key->daddr, 4, skc_off(daddr));
	} else {
		bpf_probe_read(&key->saddr, sizeof(key->saddr),
			       skc_off(v6_rcv_saddr.in6_u.u6_addr32));
		bpf_probe_read(&key->daddr, sizeof(key->daddr),
			       skc_off(v6_daddr.in6_u.u6_addr32));
	}

#undef skc_off
}

static void stats_for_transition(struct transition_event_t *evt,
		struct sock *sk, enum fsm_state new_state)
{
	u64 now = bpf_ktime_get_ns() / 1000;

	fill_flow(&evt->flow, sk);

	/* scale down moving average */
	evt->stats.reordering_dist >>= 3;
	evt->stats.reordering_var >>= 2;

	evt->transition_end = now;
	evt->end_state = new_state;
	evt->bytes_acked = tcp_bytes_acked(sk);
	evt->bytes_rcv = tcp_bytes_rcv(sk);
	evt->retransmitted_segments = tcp_total_retrans(sk);
	evt->rtt_us = tcp_rtt_us(sk) >> 3;
	evt->rtt_dev_us = tcp_mdev_us(sk) >> 2;
	evt->mss = tcp_mss(sk);
}

static int report_transition_with_buf(struct pt_regs *ctx, struct sock *sk,
		enum fsm_state new_state, struct transition_event_t *evt,
		struct sock_stats_t *stats)
{
	__builtin_memcpy(&evt->stats, stats, sizeof(evt->stats));
	stats_for_transition(evt, sk, new_state);
	/* Track the state change stats */
	transition_events.perf_submit(ctx, evt, sizeof(*evt));

	if (new_state > TCP_EVENT_RTO) {
		/* Terminal state, cleanup connection */
		sock_stats_map.delete(&sk);
	} else {
		stats->transition_start = evt->transition_end;
		stats->starting_state = evt->end_state;
	}
	return 0;
}

static int report_transition(struct pt_regs *ctx, struct sock *sk,
			      enum fsm_state new_state,
			      struct sock_stats_t *stats)
{
	struct transition_event_t evt = {0};
	return report_transition_with_buf(ctx, sk, new_state, &evt, stats);
}

static int register_new_connection(struct pt_regs *ctx, struct sock *sk,
		struct transition_event_t *evt)
{
	if (is_in_current_netns(sk) == false)
		return 0;
	struct sock_stats_t *prev_entry;
	if ((prev_entry = sock_stats_map.lookup(&sk))) {
#ifdef _DEBUG
		bpf_trace_printk("register_new_connection: new socket already "
				 "present in the map!\n");
#endif
		report_transition_with_buf(ctx, sk, TCP_EVENT_DESYNC_ERR,
				evt, prev_entry);
	}
	/* Register new connection properties */
	evt->stats.pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&evt->stats.task, sizeof(evt->stats.task));
	/* Default-initializing loss/rto to 0 */
	evt->stats.starting_state = TCP_EVENT_NEW;
	evt->stats.transition_start = bpf_ktime_get_ns() / 1000;
#ifdef _DEBUG
	bpf_trace_printk("register_new_connection: New connection for "
			 "sk%lu(%s/%lu)\n", (u64)sk, evt->stats.task,
			 evt->stats.pid);
#endif
	return 0;
}

static int handle_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	struct transition_event_t evt = {0};
	if (register_new_connection(ctx, sk, &evt))
		return 0;
	sock_stats_map.update(&sk, &evt.stats);
	store_ptr(evt.stats.pid, (u64)sk);
	return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	return handle_tcp_connect(ctx, sk);
}

int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk)
{
	return handle_tcp_connect(ctx, sk);
}

static int handle_tcp_ret_connect(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)FETCH_PTR();
	if (!sk)
		return 0;
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		/* Non-zero retcode means the connection failed right away */
#ifdef _DEBUG
		bpf_trace_printk("connect() returned an error %d!\n", ret);
#endif
		struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
		if (!stats)
			return 0;
		report_transition(ctx, sk, close_status(ret), stats);
	}
	return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	return handle_tcp_ret_connect(ctx);
}

int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	return handle_tcp_ret_connect(ctx);
}

int kprobe__tcp_finish_connect(struct pt_regs *ctx, struct sock *sk,
			       struct sk_buff *skb)
{
	/* If mptcp, then sk is the master sk but we registered the meta ...
	 * so we cannot rely on the sock_stats_map */
#ifdef __HAS_MPTCP
	if (mptcp_finish_new_connect(ctx, sk)) {
		return 0;
	}
#endif
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats) {
#ifdef _DEBUG
		bpf_trace_printk("tcp_finish_connect: Unknown sock %lu\n",
				 (u64)sk);
#endif
		return 0;
	}
	return report_transition(ctx, sk, TCP_EVENT_ESTABLISHED, stats);
}

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
	if (!sk)
		return 0;
#ifdef __HAS_MPTCP
	/* MPTCP connections are handled through reqmaster/child */
	if (is_mptcp(sk)) {
		mptcp_update_procinfo(sk);
		return 0;
	}
#endif
	u8 proto = 0;
	/* @@COMPATCHECK net/sock.h */
	bpf_probe_read(&proto, sizeof(proto), ((const char*)sk) +
		       offsetof(struct sock, sk_wmem_queued) -
		       3 /* sk_protocol bitfield */);
	if (proto != IPPROTO_TCP)
		return 0;
	struct transition_event_t evt = {0};
	if (register_new_connection(ctx, sk, &evt))
		return 0;
	/* Approximate est. time to RTT */
	evt.stats.transition_start -= tcp_rtt_us(sk) * 1000;
	stats_for_transition(&evt, sk, TCP_EVENT_ESTABLISHED);

	transition_events.perf_submit(ctx, &evt, sizeof(evt));

	evt.stats.transition_start = evt.transition_end;
	evt.stats.starting_state = evt.end_state;
	sock_stats_map.update(&sk, &evt.stats);
	return 0;
}

static bool tcp_before(u32 a, u32 b)
{
	return (int32_t)(a - b) < 0;
}

/* Loss events */
int kprobe__tcp_retransmit_timer(struct pt_regs *ctx, struct sock *sk)
{
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats) {
#ifdef _DEBUG
		bpf_trace_printk("tcp_retransmit_timer: Unknown sk %lu\n",
				 (u64)sk);
#endif
		return 0;
	}
	++(stats->rto_events);
	/* RTO can also happen in SYN_SENT/SYN_RCVD/TIMEWAIT/... but we only
	 * care about those happening when the connection was 'normal' */
	if (stats->starting_state == TCP_EVENT_ESTABLISHED) {
#ifdef _DEBUG
		bpf_trace_printk("tcp_retransmit_timer: Moving sk %lu to LOSSY"
				 " state\n", (u64)sk);
#endif
#ifdef __HAS_MPTCP
		if (mptcp_report_transition(ctx, sk, TCP_EVENT_RTO, stats))
			return 0;
		/* Otherwise this is a pure TCP connection */
#endif
		report_transition(ctx, sk, TCP_EVENT_RTO, stats);
	}
	return 0;
}

/* The kernel does not maintain lost bytes counters */
int kprobe__tcp_retransmit_skb(struct pt_regs *ctx, struct sock *sk,
			       struct sk_buff *skb)
{
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats) {
#ifdef _DEBUG
		bpf_trace_printk("tcp_retransmit_skb: Unknown sk %lu\n",
				 (u64)sk);
#endif
		return 0;
	}
	stats->retransmitted_bytes += skb_len(skb);
	return 0;
}

int kprobe__tcp_fastretrans_alert(struct pt_regs *ctx, struct sock *sk,
				   const int acked, bool is_dupack,
				   int *ack_flag, int *rexmit)
{
	/* Defer connection filtering to the retprobe */
	STORE_PTR((u64)sk);
	return 0;
}

/* @@COMPATCHECK net/inet_connection_sock.h struct inet_connection_sock */
struct inet_ca_state {
	__u8  icsk_ca_state:6,
	      icsk_ca_setsockopt:1,
	      icsk_ca_dst_locked:1;
} __attribute__((packed));

int kretprobe__tcp_fastretrans_alert(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock*)FETCH_PTR();
	if (!sk)
		return 0;
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats) {
#ifdef _DEBUG
		bpf_trace_printk("tcp_fastretrans_alert: Unknown sk %lu\n",
				 (u64)sk);
#endif
		return 0;
	}
	if (stats->starting_state != TCP_EVENT_RTO)
		/* We only want to signal transitions from RTO -> ESTABLISHED
		 * */
		return 0;
	struct inet_ca_state new_state = {0};
	/* @@COMPATCHECK net/inet_connection_sock.h */
	bpf_probe_read(&new_state, sizeof(new_state), ((const char *)sk) +
		       offsetof(struct inet_connection_sock, icsk_retransmits)
		       - 1 /* Previous u8 field */);
	if (new_state.icsk_ca_state != TCP_CA_Open)
		return 0;
#ifdef __HAS_MPTCP
	if (mptcp_report_transition(ctx, sk, TCP_EVENT_ESTABLISHED, stats))
		return 0;
	/* Otherwise this is a pure TCP connection */
#endif
	return report_transition(ctx, sk, TCP_EVENT_ESTABLISHED, stats);
}

int kprobe__tcp_rcv_state_process(struct pt_regs *ctx,
		struct sock *sk, struct sk_buff *skb)
{
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats) {
#ifdef _DEBUG
		bpf_trace_printk("tcp_validate_incoming: Unknown connection %lu\n",
				 (u64)sk);
#endif
		return 0;
	}
	/* Fetch skb head seq */
	u32 seq = skb_tcp_cb_seq(skb);
	u32 rcv_nxt = tcp_rcv_nxt(sk);
	int32_t dist = (int32_t)(seq - rcv_nxt);
	if (dist < 0) {
		++(stats->duplicate_segments);
		/* Count number of duplicated bytes */
		u32 end_seq = skb_tcp_cb_end_seq(skb);
		u32 dist_seq_rcv_nxt = rcv_nxt - seq;
		u32 seg_len = _skb_len(seq, end_seq, skb);
		/* Either the segment overlaps with snd_nxt, or it completly
		 * consists in duplicated data */
		stats->duplicate_bytes += seg_len < dist_seq_rcv_nxt ?
			seg_len : dist_seq_rcv_nxt;
#ifdef __HAS_MPTCP
		if (mptcp_report_transition(ctx, sk, TCP_EVENT_INCAST_DUP, stats))
			return 0;
	/* Otherwise this is a pure TCP connection */
#endif
		return report_transition(ctx, sk, TCP_EVENT_INCAST_DUP, stats);
	} /* We'll handle ofo packets later */
#ifndef __HAS_MPTCP
	/* This is ugly but we need to ensure that the ofo segment
	 * can be accepted, thus need the result of this function.
	 * Some kernel builds have tcp_data_queue_ofo but available but not all
	 * so we can't rely on that (unless we have MPTCP which forces the
	 * symbol to exists).
	*/
	STORE_PTR((u64)skb);
#endif
	return 0;
}

#ifndef __HAS_MPTCP
int kretprobe__tcp_rcv_state_process(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff*)FETCH_PTR();
	if (!skb)
		return 0;
	bool ret = PT_REGS_RC(ctx);
	if (!ret)
		return 0;
	struct sock *sk = skb_sk(skb);
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats)
		return 0;
	u32 seq = skb_tcp_cb_seq(skb);
	u32 rcv_nxt = tcp_rcv_nxt(sk);
	int32_t dist = (int32_t)(seq - rcv_nxt);
	if (!dist)
		return 0;
	handle_ofo_skb(skb, sk, &stats->reordering_bytes,
			&stats->reordering_dist, &stats->reordering_var,
			&stats->reordering);
	return 0;
}
#endif

static void handle_ofo_skb(struct sk_buff *skb, struct sock *sk,
		u64 *reordering_bytes, u32 *reordering_dist,
		u32 *reordering_var, u32 *reordering)
{
	*reordering = *reordering + 1;
	*reordering_bytes = *reordering_bytes + skb_len(skb);
	/* We can only compute a rolling average as eBPF does not allow
	 * floating point operations. */
	/* This is similar to tcp_rtt_estimator */
	u32 prev_dist = *reordering_dist;
	u32 seq = skb_tcp_cb_seq(skb);
	u32 rcv_nxt = tcp_rcv_nxt(sk);
	int64_t d = (int32_t)(seq - rcv_nxt);
	if (prev_dist != 0) {
		d -= (prev_dist >> 3);
		prev_dist += d;
		if (d < 0) {
			d = -d;
			d -= (*reordering_var >> 2);
			if (d > 0)
				d >>= 3;
		} else {
			d -= (*reordering_var >> 2);
		}
		*reordering_var = *reordering_var + d;
	} else {
		prev_dist = d << 3;
		*reordering_var = d << 1;
	}
	*reordering_dist = 1U > d ? 1U : d;
}

/* This symbol is unavailable without mptcp ... */
#ifdef __HAS_MPTCP
int kprobe__tcp_data_queue_ofo(struct pt_regs *ctx, struct sock *sk,
		struct sk_buff *skb)
{
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats) {
		if (mptcp_handle_data_queue_ofo(sk, skb))
			return 0;
#ifdef _DEBUG
		bpf_trace_printk("tcp_data_queue_ofo: Unknown connection %lu\n",
			(u64)sk);
#endif
		return 0;
	}
	handle_ofo_skb(skb, sk, &stats->reordering_bytes,
			&stats->reordering_dist, &stats->reordering_var,
			&stats->reordering);
	return 0;
	/* return report_transition(ctx, sk, TCP_EVENT_OO, stats); */
}
#endif

/* Imports from net/ipv4/tcp.c as we need to infer whether an error is going
 * to be triggered or not as the function resets (?) the sk_err flag */
/* @@COMPATCHECK linux/tcp.h || Needed leading _ as mptcp was exporting it */
static bool _tcp_need_reset(int state)
{
	return (1 << state) &
	       (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_FIN_WAIT1 |
		TCPF_FIN_WAIT2 | TCPF_SYN_RECV);
}

/* @@COMPATCHECK linux/tcp.h */
struct repair_byte {
	u8	nonagle     : 4,/* Disable Nagle algorithm?             */
		thin_lto    : 1,/* Use linear timeouts for thin streams */
		thin_dupack : 1,/* Fast retransmit on first dupack      */
		repair      : 1,
		frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */
} __attribute__((packed));

static int disconnect_get_sk_err(struct sock *sk)
{
	int old_state = 0;
	bpf_probe_read(&old_state, sizeof(old_state), ((const char *)sk) +
		       offsetof(struct sock, sk_state));
	struct repair_byte repair = {0};
	/* @@COMPATCHECK linux/tcp.h */
	bpf_probe_read(&repair, sizeof(repair), ((const char *)sk) +
		       offsetof(struct tcp_sock, advmss) +
		       2 /* sizeof(advmss) */);
	u32 snd_nxt = tcp_snd_nxt(sk);
	u32 write_seq = 0;
	bpf_probe_read(&write_seq, sizeof(write_seq), ((const char *)sk) +
		       offsetof(struct tcp_sock, write_seq));

	/* @@COMPATCHECK net/ipv4/tcp.c ~ tcp_disconnect */
	if (old_state == TCP_LISTEN) {
		return 0;
	} else if (unlikely(repair.repair)) {
		return ECONNABORTED;
	} else if (_tcp_need_reset(old_state) ||
		   (snd_nxt != write_seq &&
		    (1 << old_state) & (TCPF_CLOSING | TCPF_LAST_ACK))) {
		return ECONNRESET;
	} else if (old_state == TCP_SYN_SENT)
		return ECONNRESET;
	return 0;
}

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
#ifdef _DEBUG
	bpf_trace_printk("tcp_set_state: Connection %lu state is now %d\n",
			 (u64)sk, state);
#endif
	/* Early exit for connections not closing */
	if (state != TCP_CLOSE)
		return 0;
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats) {
#ifdef __HAS_MPTCP
		if (mptcp_meta_set_state(ctx, sk, state)) {
			/* Was a meta socket, return*/
			return 0;
		}
#endif
#ifdef _DEBUG
		bpf_trace_printk("BUG tcp_set_state: Unknown connection %lu\n",
				 (u64)sk);
#endif
		return 0;
	}
	/* Check if some error has been set on the socket already */
	int sk_err = sock_sk_err(sk);
	/* We ignore sk_err_soft; i.e. do not need the full error reason */
	/* Otherwise guess it */
	if (!sk_err)
		sk_err = disconnect_get_sk_err(sk);
	enum fsm_state status = close_status(sk_err);
#ifdef __HAS_MPTCP
	if (mptcp_report_transition(ctx, sk, status, stats))
		return 0;
#endif
	return report_transition(ctx, sk, status, stats);
}
