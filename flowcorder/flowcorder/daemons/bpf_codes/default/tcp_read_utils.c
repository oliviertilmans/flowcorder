/* This file assumes that the proper includes have been done, and
 * is tailored to be appended to instrument_tcp.c */

static u64 tcp_bytes_acked(struct sock *sk)
{
	u64 b = 0;
	bpf_probe_read(&b, sizeof(b), ((const char*)sk) +
			offsetof(struct tcp_sock, bytes_acked));
	return b;
}

static u64 tcp_bytes_rcv(struct sock *sk)
{
	u64 b = 0;
	bpf_probe_read(&b, sizeof(b), ((const char*)sk) +
			offsetof(struct tcp_sock, bytes_received));
	return b;
}

static u32 tcp_total_retrans(struct sock *sk)
{
	u32 b = 0;
	bpf_probe_read(&b, sizeof(b), ((const char*)sk) +
			offsetof(struct tcp_sock, total_retrans));
	return b;
}

static u32 tcp_rtt_us(struct sock *sk)
{
	u32 b = 0;
	bpf_probe_read(&b, sizeof(b), ((const char*)sk) +
			offsetof(struct tcp_sock, srtt_us));
	return b;
}

static u32 tcp_mdev_us(struct sock *sk)
{
	u32 b = 0;
	bpf_probe_read(&b, sizeof(b), ((const char*)sk) +
			offsetof(struct tcp_sock, mdev_us));
	return b;
}

static u16 tcp_mss(struct sock *sk)
{
	u16 b = 0;
	bpf_probe_read(&b, sizeof(b), ((const char*)sk) +
			offsetof(struct tcp_sock, rx_opt) +
			offsetof(struct tcp_options_received, mss_clamp));
	return b;
}

static int tcp_sk_rcvbuf(struct sock *sk)
{
	int b = 0;
	bpf_probe_read(&b, sizeof(b), ((const char*)sk) +
			offsetof(struct sock, sk_rcvbuf));
	return b;
}

static u32 skb_tcp_cb_seq(struct sk_buff *skb)
{
	u32 seq = 0;
	bpf_probe_read(&seq, sizeof(seq), ((const char *)skb) +
		       offsetof(struct sk_buff, cb) +
		       offsetof(struct tcp_skb_cb, seq));
	return seq;
};

static u32 skb_tcp_cb_end_seq(struct sk_buff *skb)
{
	u32 end_seq = 0;
	bpf_probe_read(&end_seq, sizeof(end_seq), ((const char *)skb) +
		       offsetof(struct sk_buff, cb) +
		       offsetof(struct tcp_skb_cb, end_seq));
	return end_seq;
};

static u32 _skb_len(u32 seq, u32 end_seq, struct sk_buff *skb)
{
	u8 flags = 0;
	bpf_probe_read(&flags, sizeof(flags), ((const char *)skb) +
		       offsetof(struct sk_buff, cb) +
		       offsetof(struct tcp_skb_cb, tcp_flags));
	/* end_seq = SEQ + FIN + SYN + datalen */
	return end_seq - seq - (flags & TCPHDR_FIN) ? 1 : 0 -
		(flags & TCPHDR_SYN) ? 1 : 0;
}

static u32 tcp_snd_nxt(struct sock *sk)
{
	u32 snd_nxt = 0;
	bpf_probe_read(&snd_nxt, sizeof(snd_nxt), ((const char *)sk) +
		       offsetof(struct tcp_sock, snd_nxt));
	return snd_nxt;
}

static u32 tcp_rcv_nxt(struct sock *sk)
{
	u32 rcv_nxt = 0;
	bpf_probe_read(&rcv_nxt, sizeof(rcv_nxt), ((const char *)sk) +
		       offsetof(struct tcp_sock, rcv_nxt));
	return rcv_nxt;
}

static u32 tcp_packets_out(struct sock *sk)
{
	u32 packets_out = 0;
	bpf_probe_read(&packets_out, sizeof(packets_out), ((const char *)sk) +
		       offsetof(struct tcp_sock, packets_out));
	return packets_out;
}

static u32 skb_len(struct sk_buff *skb)
{
	u32 seq = skb_tcp_cb_seq(skb);
	u32 end_seq = skb_tcp_cb_end_seq(skb);
	return _skb_len(seq, end_seq, skb);
}

static int sock_sk_err(struct sock *sk)
{
	int sk_err = 0;
	bpf_probe_read(&sk_err, sizeof(sk_err), ((const char *)sk) +
		       offsetof(struct sock, sk_err));
	return sk_err;
}

static struct sock* skb_sk(struct sk_buff *skb)
{
	struct sock *ptr = 0;
	bpf_probe_read(&ptr, sizeof(ptr), ((const char*)skb)+
			offsetof(struct sk_buff, sk));
	return ptr;
}
