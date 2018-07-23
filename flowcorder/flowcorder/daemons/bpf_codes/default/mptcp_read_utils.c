
/* This file assumes that the proper includes have been done, and
 * is tailored to be appended to instrument_tcp.c */

#ifdef __HAS_MPTCP
/** @@COMPATCHECK linux/tcp.h **/
struct mpc_byte_t {
	u32     mpc:1,          /* Other end is multipath capable */
		inside_tk_table:1, /* Is the tcp_sock inside the token-table? */
		send_mp_fclose:1,
		request_mptcp:1, /* Did we send out an MP_CAPABLE?
				  * (this speeds up mptcp_doit() in tcp_recvmsg)
				  */
		pf:1, /* Potentially Failed state: when this flag is set, we
		       * stop using the subflow
		       */
		mp_killed:1, /* Killed with a tcp_done in mptcp? */
		was_meta_sk:1,	/* This was a meta sk (in case of reuse) */
		is_master_sk:1,
		close_it:1,	/* Must close socket in mptcp_data_ready? */
		closing:1,
		mptcp_ver:4,
		mptcp_sched_setsockopt:1,
		mptcp_pm_setsockopt:1,
		record_master_info:1;
} __attribute__((packed));

static struct infinite_mapping_byte_t mptcp_mpcb_infinite_mapping(
		struct mptcp_cb *mpcb)
{
	struct infinite_mapping_byte_t m = {0};
	bpf_probe_read(&m, sizeof(m), ((const char*)mpcb) +
			/* rcv_high_order[2] */
			offsetof(struct mptcp_cb, rcv_high_order) + 4);
	return m;
}

static struct mpc_byte_t mptcp_tcp_mpc(struct sock *sk)
{
	struct mpc_byte_t mpc = {0};
	bpf_probe_read(&mpc, sizeof(mpc), ((const char*)sk) +
			offsetof(struct tcp_sock, meta_sk) +
			sizeof(struct sock*));
	return mpc;
}

static bool is_mptcp(struct sock *sk)
{
	return mptcp_tcp_mpc(sk).mpc != 0;
}
static u64 mptcp_loc_key(struct sock *sk)
{
	u64 loc_key = 0;
	bpf_probe_read(&loc_key, sizeof(loc_key), ((const char*)sk) +
			offsetof(struct tcp_sock, mptcp_loc_key));
	return loc_key;
}

static struct mptcp_tcp_sock* mptcp_tcp_sock(struct sock *sk)
{
	struct mptcp_tcp_sock *ptr = 0;
	bpf_probe_read(&ptr, sizeof(ptr), ((const char*)sk) +
			offsetof(struct tcp_sock, mptcp));
	return ptr;
}

static u8 mptcp_path_index(struct mptcp_tcp_sock *sk)
{
	u8 i = 0;
	bpf_probe_read(&i, sizeof(i), ((const char*)sk) +
			offsetof(struct mptcp_tcp_sock, path_index));
	return i;
}

static u8 mptcp_subflows(struct mptcp_cb *mpcb)
{
	u8 s = 0;
	bpf_probe_read(&s, sizeof(s), ((const char*)mpcb) +
			offsetof(struct mptcp_cb, cnt_subflows));
	return s;
}

static u32 mptcp_reinject_queue_len(struct mptcp_cb *mpcb)
{
	u32 len = 0;
	bpf_probe_read(&len, sizeof(len), ((const char*)mpcb) +
			offsetof(struct mptcp_cb, reinject_queue) +
			offsetof(struct sk_buff_head, qlen));
	return len;
}

static struct mptcp_cb* mptcp_mpcb(struct sock *sk)
{
	struct mptcp_cb *ptr = 0;
	bpf_probe_read(&ptr, sizeof(ptr), ((const char*)sk) +
			offsetof(struct tcp_sock, mpcb));
	return ptr;
}

static struct sock* mptcp_get_meta_sk(struct sock *sk)
{
	struct sock *meta = 0;
	bpf_probe_read(&meta, sizeof(meta), ((const char*)sk) +
			offsetof(struct tcp_sock, meta_sk));
	return meta;
}

static bool mptcp_requested(struct sock *sk)
{
	return mptcp_tcp_mpc(sk).request_mptcp;
}

static bool mptcp_is_meta_sk(struct sock *sk)
{
	return is_mptcp(sk) && mptcp_get_meta_sk(sk) == sk;
}

static struct sock* mptcp_master_sk(struct mptcp_cb *mpcb)
{
	struct sock *sk = 0;
	bpf_probe_read(&sk, sizeof(sk), ((const char*)mpcb) +
			offsetof(struct mptcp_cb, master_sk));
	return sk;
}
#endif
