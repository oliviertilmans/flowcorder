/* This file assumes that the proper includes have been done, and
 * is tailored to be appended to instrument_tcp.c */

#ifdef __HAS_MPTCP
/* MPTCP-specific path statistics */
struct mptcp_stats_t;
/* Statistics on the MPTCP meta-socket */
struct mptcp_meta_stats_t;
/* The event type for mptcp subflows */
struct mptcp_transition_event_t;
/* The event type for the MPTCP meta socket */
struct mpctcp_meta_event_t;
/* Track skbs that could be reinjected */
struct reinject_data_t;
/* @@COMPATCHECK linux/tcp.h // Access the MPTCP flags */
struct mpc_byte_t;
/* @@COMPATCHECK net/mptcp.h // Access the infinite mapping flags */
struct infinite_mapping_byte_t;

/* Return tcp_sock(sk)->mptcp_loc_key */
static u64 mptcp_loc_key(struct sock *sk);
/* Return tcp_sock(sk)->mptcp */
static struct mptcp_tcp_sock* mptcp_tcp_sock(struct sock *sk);
/* Return mptcp_cb->cnt_subflows */
static u8 mptcp_subflows(struct mptcp_cb *mpcb);
/* return mptcp_tcp_sock->path_index */
static u8 mptcp_path_index(struct mptcp_tcp_sock *mtcp_sk);
/* Return tcp_sock(sk)->{mpc, ...} */
static struct mpc_byte_t mptcp_tcp_mpc(struct sock *sk);
/* return tcp_sock(sk)->request_mptcp */
static bool mptcp_requested(struct sock *sk);
/* Return the length of the reinject_queue */
static u32 mptcp_reinject_queue_len(struct mptcp_cb *mpcb);
/* Return the mpcb from the meta socket */
static struct mptcp_cb* mptcp_mpcb(struct sock *sk);
/* Return the mpctcp meta sk */
static struct sock* mptcp_get_meta_sk(struct sock *sk);
/* Return mptcp_cb->{send_infinite_mapping,...} */
static struct infinite_mapping_byte_t
mptcp_mpcb_infinite_mapping( struct mptcp_cb *mpcb);
/* Return tcp_sock(sk)->mpcb->master_sk */
static struct sock* mptcp_master_sk(struct mptcp_cb *mpcb);
/* Report to user-space a meta-socket transition */
static int report_mptcp_meta_transition(struct pt_regs *ctx, struct sock *sk,
			      enum fsm_state new_state,
			      struct mptcp_meta_stats_t *mstats);
/* Fill a transition for a MPTCP subflow */
static void mptcp_stats_for_transition(struct mptcp_transition_event_t *mevt,
		struct sock *sk);
/* Fill a transition for the MPTCP meta socket */
static void mptcp_meta_stats_for_transition(struct mpctcp_meta_event_t *mevt,
		struct sock *sk, enum fsm_state new_state);
/* Create and output a new meta_sk event */
static void mptcp_create_meta_sk_stats(struct pt_regs *ctx,
		struct sock_stats_t *stats, struct sock *meta,
		struct mpctcp_meta_event_t *evt, u64 start_ts);

struct mptcp_stats_t {
	/* u64 reinjected_bytes_in; */
	u64 reinjected_bytes_out; /* Bytes reinjected in the meta socket */
	/* u32 reinjected_in; */
	u32 reinjected_out; /* Segments (skb) reinjected in the meta socket */
} __attribute__((packed));

struct mptcp_transition_event_t {
	struct transition_event_t tcp_stats;
	u64 uuid; /* mptcp_loc_key */
	struct mptcp_stats_t mptcp_stats;
	u8 path_index;
} __attribute__((packed));

struct mptcp_meta_stats_t {
	char task[TASK_COMM_LEN]; /* Process name */
	u64 pid; /* TGID/PID */
	u64 reordering_bytes; /* reordering counter in bytes */
	u64 retransmitted_bytes; /* bytes retransmitted */
	u64 start_ts; /* Transition start TS */
	u64 reinjected_bytes; /* Corresponding number of bytes */
	/* Last state that caused the flow to not be TCP_CA_Open */
	u32 reordering; /* reordering counter */
	u32 reordering_dist; /* mean reordering distance */
	u32 reordering_var; /* variance reordering distance */
	u32 reinjected; /* Number of reinjection across all subflows */
	u16 stalls; /* Head-of line blocking occurences */
	u8 start_state; /* Starting state */
} __attribute__((packed));

struct mpctcp_meta_event_t {
	u64 end_ts; /* End TS of the transition */
	u64 uuid; /* mptcp_loc_key */
	u64 bytes_acked; /* Sent bytes */
	u64 bytes_rcv; /* Received bytes */
	struct mptcp_meta_stats_t stats; /* The meta socket stats */
	u8 end_state; /* Fix alignment across stucts */
	u32 retransmitted_segments; /* rentransmitted segment count */
	int sk_rcvbuf; /* Receive buffer size in bytes */
	u8 subflows; /* Active subflow count */
} __attribute__((packed));

/** @@COMPATCHECK net/mptcp.h **/
struct infinite_mapping_byte_t {
	u16	send_infinite_mapping:1,
		in_time_wait:1,
		list_rcvd:1, /* XXX TO REMOVE */
		addr_signal:1, /* Path-manager wants us to call addr_signal */
		dss_csum:1,
		server_side:1,
		infinite_mapping_rcv:1,
		infinite_mapping_snd:1,
		dfin_combined:1,   /* Was the DFIN combined with subflow-fin? */
		passive_close:1,
		snd_hiseq_index:1, /* Index in snd_high_order of snd_nxt */
		rcv_hiseq_index:1; /* Index in rcv_high_order of rcv_nxt */
} __attribute__((packed));

struct reinject_data_t {
	struct sock *sk_source;
	struct sock *meta;
	u32 skb_len;
	u32 reinject_q_len;
};

/* Map an mtcp connection to its statistics */
BPF_HASH(mptcp_stats_map, struct sock *, struct mptcp_stats_t);
/* Map a meta mtcp connection to its statistics */
BPF_HASH(mptcp_meta_stats_map, struct sock *, struct mptcp_meta_stats_t);
/* Reinjection mapping */
BPF_HASH(mptcp_reinject_map, u64, struct reinject_data_t);


static int mptcp_report_transition(struct pt_regs *ctx, struct sock *sk,
		enum fsm_state new_state, struct sock_stats_t *stats)
{
	struct mptcp_stats_t *mstats = mptcp_stats_map.lookup(&sk);
	if (mstats) {
		struct mptcp_transition_event_t mevt = {0};
		__builtin_memcpy(&mevt.mptcp_stats, mstats, sizeof(*mstats));
		__builtin_memcpy(&mevt.tcp_stats.stats, stats, sizeof(*stats));
		stats_for_transition(&mevt.tcp_stats, sk, new_state);
		mptcp_stats_for_transition(&mevt, sk);

		transition_events.perf_submit(ctx, &mevt, sizeof(mevt));

		if (mevt.tcp_stats.end_state > TCP_EVENT_RTO) {
			struct sock *meta_sk = mptcp_get_meta_sk(sk);
			struct mptcp_meta_stats_t *meta_stats =
				mptcp_meta_stats_map.lookup(&meta_sk);
			if (meta_stats)
				report_mptcp_meta_transition(ctx, meta_sk,
						TCP_EVENT_REM_FLOW, meta_stats);
			mptcp_stats_map.delete(&sk);
		} else {
			stats->starting_state = mevt.tcp_stats.end_state;
			stats->transition_start = mevt.tcp_stats.transition_end;
		}
		return 1;
	}
	return 0;
}

static void mptcp_stats_for_transition(struct mptcp_transition_event_t *mevt,
		struct sock *sk)
{
	mevt->path_index = mptcp_path_index(mptcp_tcp_sock(sk));
	mevt->uuid = mptcp_loc_key(sk);
}

static void mptcp_meta_stats_for_transition(struct mpctcp_meta_event_t *mevt,
		struct sock *sk, enum fsm_state new_state)
{
	u64 now = bpf_ktime_get_ns() / 1000;
	struct mptcp_cb *mpcb = mptcp_mpcb(sk);

	mevt->stats.reordering_dist >>= 3;
	mevt->stats.reordering_var >>= 2;

	mevt->uuid = mptcp_loc_key(sk);
	mevt->subflows = mptcp_subflows(mpcb);
	mevt->end_ts = now;
	mevt->end_state = new_state;
	mevt->sk_rcvbuf = tcp_sk_rcvbuf(sk);
	mevt->bytes_acked = tcp_bytes_acked(sk);
	mevt->bytes_rcv = tcp_bytes_rcv(sk);
	mevt->retransmitted_segments = tcp_total_retrans(sk);
}

static void report_mptcp_meta_transition_with_buf(
		struct mpctcp_meta_event_t *evt, struct pt_regs *ctx,
		struct sock *sk, enum fsm_state new_state,
		struct mptcp_meta_stats_t *mstats)
{
	__builtin_memcpy(&evt->stats, mstats, sizeof(*mstats));
	mptcp_meta_stats_for_transition(evt, sk, new_state);
	transition_events.perf_submit(ctx, evt, sizeof(*evt));
	/* Track the state change stats */
	if (new_state > TCP_EVENT_RTO) {
		/* Terminal state, cleanup connection */
		mptcp_meta_stats_map.delete(&sk);
	} else {
		mstats->start_ts = evt->end_ts;
		mstats->start_state = evt->end_state;
	}
}

static int report_mptcp_meta_transition(struct pt_regs *ctx, struct sock *sk,
			      enum fsm_state new_state,
			      struct mptcp_meta_stats_t *mstats)
{
	struct mpctcp_meta_event_t evt = {0};
	report_mptcp_meta_transition_with_buf(&evt, ctx, sk, new_state, mstats);
	return 0;
}

int kprobe____mptcp_reinject_data(struct pt_regs *ctx,
		struct sk_buff *orig_skb, struct sock *meta_sk,
		struct sock *sk, int clone_it)
{
	struct reinject_data_t d = {0};
	d.sk_source = sk;
	d.meta = meta_sk;
	d.skb_len = skb_len(orig_skb);
	d.reinject_q_len = mptcp_reinject_queue_len(mptcp_mpcb(meta_sk));
	u64 pid = bpf_get_current_pid_tgid();
	mptcp_reinject_map.update(&pid, &d);
	return 0;
}

int kretprobe____mptcp_reinject_data(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	struct reinject_data_t *d =
		mptcp_reinject_map.lookup(&pid);
	if (!d)
		return 0;
	u32 new_qlen = mptcp_reinject_queue_len(mptcp_mpcb(d->meta));
	int qlen_diff = new_qlen - d->reinject_q_len;
	if (qlen_diff <= 0) {
		/* Should probably signal an error if qlen_diff < 0? */
		return 0;
	}
	/* Current MPTCP kernel does not allow map-to-map lookup (or
	 * perf_output) */
	struct sock *key = d->meta;
	/* The reinject queue has grown, track the changes */
	struct mptcp_meta_stats_t *m_stats =
		mptcp_meta_stats_map.lookup(&key);
	if (!m_stats)
		return 0;
	m_stats->reinjected += qlen_diff;
	m_stats->reinjected_bytes += d->skb_len;
	key = d->sk_source;
	struct mptcp_stats_t *f_stats = mptcp_stats_map.lookup(&key);
	if (!f_stats)
		return 0;
	f_stats->reinjected_out += qlen_diff;
	f_stats->reinjected_bytes_out += d->skb_len;
	mptcp_reinject_map.delete(&pid);
	return 0;
}

/* MPTCP has no equivalent to tcp_fastretrans, but the only place where
 * it moves back to TCP_CA_Open is in the fast path, after rxmitting the whole
 * meta_queue. Fortunately, mptcp_retransmit_skb is only used either in the
 * context of the RTO, or right before moving back to TCP_CA_Open.
 * */
BPF_HASH(mptcp_rxmit_map, struct sock*, u8);

int kprobe__mptcp_meta_retransmit_timer(struct pt_regs *ctx,
		struct sock *meta_sk)
{
	u8 zero = 0;
	mptcp_rxmit_map.update(&meta_sk, &zero);
	STORE_PTR((u64)meta_sk);
	struct mptcp_meta_stats_t *mstats =
		mptcp_meta_stats_map.lookup(&meta_sk);
	if (!mstats)
		return 0;
	/* We always increase stall count event if packets_out was empty as
	 * this indicates head-of-line blocking. */
	++(mstats->stalls);
	if (mstats->start_state == TCP_EVENT_ESTABLISHED ||
			mstats->start_state == TCP_EVENT_ADD_FLOW ||
			mstats->start_state == TCP_EVENT_REM_FLOW)
		report_mptcp_meta_transition(ctx, meta_sk,
				TCP_EVENT_RTO, mstats);
	return 0;
}
int kretprobe__mptcp_meta_retransmit_timer(struct pt_regs *ctx)
{
	struct sock *meta_sk = (struct sock*)FETCH_PTR();
	if (!meta_sk)
		return 0;
	mptcp_rxmit_map.delete(&meta_sk);
	return 0;
}

static enum fsm_state mptcp_meta_close_status(struct sock *sk)
{
	int sk_err = sock_sk_err(sk);
	if (!sk_err) {
		sk_err = disconnect_get_sk_err(sk);
		if (!sk_err) {
			struct infinite_mapping_byte_t i =
				mptcp_mpcb_infinite_mapping(mptcp_mpcb(sk));
			sk_err = i.infinite_mapping_snd ? ECONNRESET : 0;
		}
	}
	return close_status(sk_err);
}

int kprobe__mptcp_retransmit_skb(struct pt_regs *ctx, struct sock *meta_sk,
		struct sk_buff *skb)
{
	struct mptcp_meta_stats_t *mstats =
		mptcp_meta_stats_map.lookup(&meta_sk);
	if (!mstats)
		return 0;
	mstats->retransmitted_bytes += skb_len(skb);
	u8 *in_rto = mptcp_rxmit_map.lookup(&meta_sk);
	if (in_rto)
		return 0;
	/* Otherwise we're being called within mptcp_data_ack, and/or a subflow
	 * add/removal has taken place already and has exported a transition */
	if (mstats->start_state == TCP_EVENT_RTO)
		report_mptcp_meta_transition(ctx, meta_sk,
				TCP_EVENT_ESTABLISHED, mstats);
	return 0;
}

static int mptcp_meta_set_state(struct pt_regs *ctx, struct sock *sk, int s)
{
	struct mptcp_meta_stats_t *mstats = mptcp_meta_stats_map.lookup(&sk);
	if (!mstats)
		return 0;
#ifdef _DEBUG
	bpf_trace_printk("Tearing down meta socket: %lu\n", (u64)sk);
#endif
	return report_mptcp_meta_transition(ctx, sk,
			mptcp_meta_close_status(sk), mstats);
}

static int mptcp_add_new_subflow_req(struct pt_regs *ctx, struct sock *sk,
		u64 *start_ts)
{
	struct mptcp_transition_event_t evt = {0};
	if (register_new_connection(ctx, sk, &evt.tcp_stats))
		return 1;
	/* Approximate est. time to RTT */
	evt.tcp_stats.stats.transition_start -= tcp_rtt_us(sk) * 1000;

	stats_for_transition(&evt.tcp_stats, sk, TCP_EVENT_ESTABLISHED);
	mptcp_stats_for_transition(&evt, sk);

	transition_events.perf_submit(ctx, &evt, sizeof(evt));

	if (start_ts)
		*start_ts = evt.tcp_stats.stats.transition_start;
	evt.tcp_stats.stats.transition_start = evt.tcp_stats.transition_end;
	evt.tcp_stats.stats.starting_state = evt.tcp_stats.end_state;

	mptcp_stats_map.update(&sk, &evt.mptcp_stats);
	sock_stats_map.update(&sk, &evt.tcp_stats.stats);

	return 0;
}

int kretprobe__mptcp_check_req_child(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock*)PT_REGS_RC(ctx);
	/* Either the child failed to be allocated, or the subflow opening
	 * failed in which case it returns the meta_sk */
	struct sock *meta = mptcp_get_meta_sk(sk);
	struct mptcp_meta_stats_t *mstats =
		mptcp_meta_stats_map.lookup(&meta);
	if (!sk || meta == sk || !mstats)
		return 0;

	if (mptcp_add_new_subflow_req(ctx, sk, NULL))
		return 0;

	/* We know child comes from an existing meta_sk */
	struct mpctcp_meta_event_t metaevt = {0};
	report_mptcp_meta_transition_with_buf(&metaevt, ctx, meta,
			TCP_EVENT_ADD_FLOW, mstats);

	return 0;
}

/* This is called if !is_meta_sk(sk), i.e. if not mptcp at all, or a new
 * connection. ret value indicates error < 0 (mptcp) < regular tcp */
int kprobe__mptcp_check_req_master(struct pt_regs *ctx, struct sock *sk,
		struct sock *child, struct request_sock *req,
		struct sk_buff *skb, int drop)
{
	STORE_PTR((u64)child);
	return 0;
}

int kretprobe__mptcp_check_req_master(struct pt_regs *ctx)
{
	struct sock *child = (struct sock*)FETCH_PTR();
	if (!child)
		return 0;
	int ret = PT_REGS_RC(ctx);
	if (ret)
		return 0; /* listen overflow or regular tcp eventually caught
			     by inet_csk_accept anyway */
	/* child is a new meta sock, eventually caught by inet_csk_accept,
	 * handle the subflow instead. Fortunately, the master_sk got its rtt
	 * estimation done already. */
	struct sock *sk = mptcp_master_sk(mptcp_mpcb(child));
#ifdef _DEBUG
	bpf_trace_printk("New MPTCP listen connection: %lu/%lu\n",
			(u64)sk, (u64)child);
#endif

	u64 ts;
	if (mptcp_add_new_subflow_req(ctx, sk, &ts))
		return 0;

	struct mpctcp_meta_event_t meta = {0};
	struct sock_stats_t *tcp_stats = sock_stats_map.lookup(&sk);
	if (!tcp_stats)
		return 0;
	/* We know child is a brand new meta_sk */
	mptcp_create_meta_sk_stats(ctx, tcp_stats, child, &meta, ts);

	return 0;
}

static void mptcp_create_meta_sk_stats(struct pt_regs *ctx,
		struct sock_stats_t *stats, struct sock *meta,
		struct mpctcp_meta_event_t *evt, u64 start_ts)
{
#ifdef _DEBUG
	bpf_trace_printk("New MPTCP meta socket: %lu\n", (u64)meta);
#endif
	__builtin_memcpy(&evt->stats.task, &stats->task, TASK_COMM_LEN);
	evt->stats.pid = stats->pid;
	evt->stats.start_ts = start_ts;
	evt->stats.start_state = TCP_EVENT_NEW;
	mptcp_meta_stats_for_transition(evt, meta, TCP_EVENT_ESTABLISHED);

	transition_events.perf_submit(ctx, evt, sizeof(*evt));

	evt->stats.start_ts = evt->end_ts;
	evt->stats.start_state = evt->end_state;
	mptcp_meta_stats_map.update(&meta, &evt->stats);
}

static int mptcp_finish_new_connect(struct pt_regs *ctx, struct sock *sk)
{
	/* Is this a new mptcp connection? */
	struct sock *meta_sk = mptcp_get_meta_sk(sk);
	if (!meta_sk)
		return 0;
#ifdef _DEBUG
	bpf_trace_printk("mptcp_finish_new_connect: New connection %lu for "
			"meta: %lu\n", (u64)sk, (u64)meta_sk);
#endif
	/* Either this is the master_sk, then meta_sk is in the sock_stats_map
	 * or this is a new subflow and it is in the sock_stats_map */
	bool was_meta = false;
	struct sock_stats_t *stats = sock_stats_map.lookup(&sk);
	if (!stats) {
		was_meta = true;
		stats = sock_stats_map.lookup(&meta_sk);
	}
	if (!stats) {
#ifdef _DEBUG
		bpf_trace_printk("mptcp_finish_new_connect: No stats for %lu/"
			"%lu\n", (u64)sk, (u64)meta_sk);
#endif
		return 0;
	}

	union {
		struct mpctcp_meta_event_t meta;
		struct mptcp_transition_event_t subflow;
	} evt;
	__builtin_memset(&evt.meta, 0, sizeof(evt.meta));

	struct mptcp_meta_stats_t *mstats =
		mptcp_meta_stats_map.lookup(&meta_sk);
	if (!mstats) { /* Create the meta socket stats */
		mptcp_create_meta_sk_stats(ctx, stats, meta_sk, &evt.meta,
				stats->transition_start);
	} else {
		report_mptcp_meta_transition_with_buf(&evt.meta, ctx, meta_sk,
				TCP_EVENT_ADD_FLOW, mstats);
	}

	__builtin_memset(&evt.subflow, 0, sizeof(evt.subflow));

	mptcp_stats_map.update(&sk, &evt.subflow.mptcp_stats);

	__builtin_memcpy(&evt.subflow.tcp_stats.stats,
			stats, sizeof(*stats));
	stats_for_transition(&evt.subflow.tcp_stats, sk,
			TCP_EVENT_ESTABLISHED);
	mptcp_stats_for_transition(&evt.subflow, sk);

	transition_events.perf_submit(ctx, &evt.subflow,
			sizeof(evt.subflow));

	evt.subflow.tcp_stats.stats.transition_start =
		evt.subflow.tcp_stats.transition_end;
	evt.subflow.tcp_stats.stats.starting_state =
		evt.subflow.tcp_stats.end_state;

	sock_stats_map.update(&sk, &evt.subflow.tcp_stats.stats);

	if (was_meta) {
		sock_stats_map.delete(&meta_sk);
	}

	return 1;
}

static int mptcp_handle_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct mptcp_meta_stats_t *mstats =
		mptcp_meta_stats_map.lookup(&sk);
	if (mstats) {
		handle_ofo_skb(skb, sk, &mstats->reordering_bytes,
				&mstats->reordering_dist,
				&mstats->reordering_var,
				&mstats->reordering);
		return 1;
		/* report_meta_transition(ctx, sk, TCP_EVENT_OO, mstats); */
	}
	return 0;
}

static void mptcp_update_procinfo(struct sock *sk)
{
	struct mptcp_meta_stats_t *mstats = mptcp_meta_stats_map.lookup(&sk);
	if (!mstats)
		return;
	mstats->pid = bpf_get_current_pid_tgid();
	char str[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&str, sizeof(str));
	__builtin_memcpy(&mstats->task, &str, sizeof(str));
}
#endif  /* __HAS_MPTCP */
