/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

/*
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <net/tcp.h>

#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/static_key.h>

#include <trace/events/tcp.h>

/* Refresh clocks of a TCP socket,
 * ensuring monotically increasing values.
 */
/* 更新tcp socket的时间戳，确保时间戳单调递增。 */
void tcp_mstamp_refresh(struct tcp_sock *tp)
{
	u64 val = tcp_clock_ns();

	if (val > tp->tcp_clock_cache)
		tp->tcp_clock_cache = val;

	val = div_u64(val, NSEC_PER_USEC);
	if (val > tp->tcp_mstamp)
		tp->tcp_mstamp = val;
}

static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp);

/* Account for new data that has been sent to the network. */

/* 调用tcp_event_new_data_sent()-->tcp_advance_send_head()更新sk_send_head，即取发送队列中的下一个SKB。
 * 同时更新snd_nxt，即等待发送的下一个TCP段的序号，然后统计发出但未得到确认的数据报个数。
 * 最后，如果发送该报文前没有需要确认的报文，则复位重传定时器，对本次发送的报文做重传超时计时。
 */
static void tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;

	/* 更新下一个要发送的tcp sequence */
	tp->snd_nxt = TCP_SKB_CB(skb)->end_seq;

	/* 将本skb从sk_wirte_queue中删除 */
	__skb_unlink(skb, &sk->sk_write_queue);

	/* 添加到重传队列中 */
	tcp_rbtree_insert(&sk->tcp_rtx_queue, skb);

	/* 增加待确认的data长度 */
	tp->packets_out += tcp_skb_pcount(skb);

	/* prior_packets=0表示 之前未发送过数据，因此需要启动timer。 */
	if (!prior_packets || icsk->icsk_pending == ICSK_TIME_LOSS_PROBE)
		tcp_rearm_rto(sk); //复位重传定时器

	NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPORIGDATASENT,
		      tcp_skb_pcount(skb));
}

/* SND.NXT, if window was not shrunk or the amount of shrunk was less than one
 * window scaling factor due to loss of precision.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 tcp_acceptable_seq(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (!before(tcp_wnd_end(tp), tp->snd_nxt) ||
	    (tp->rx_opt.wscale_ok &&
	     ((tp->snd_nxt - tcp_wnd_end(tp)) < (1 << tp->rx_opt.rcv_wscale))))
		return tp->snd_nxt;
	else
		return tcp_wnd_end(tp);
}

/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
static __u16 tcp_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;

	if (dst) {
		unsigned int metric = dst_metric_advmss(dst);

		if (metric < mss) {
			mss = metric;
			tp->advmss = mss;
		}
	}

	return (__u16)mss;
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism.
 */
void tcp_cwnd_restart(struct sock *sk, s32 delta)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* 首先赋值为tcp_init_cwnd函数的计算值，其一般情况下等于初始窗口值TCP_INIT_CWND（10），
	 * 但是，如果在路由项中缓存了初始窗口值，等于缓存值。 */
	u32 restart_cwnd = tcp_init_cwnd(tp, __sk_dst_get(sk));
	u32 cwnd = tp->snd_cwnd;

	tcp_ca_event(sk, CA_EVENT_CWND_RESTART);

	/* 慢启动阈值ssthresh等于其当前值与拥塞窗口*3/4两者之间的最大值。 */
	tp->snd_ssthresh = tcp_current_ssthresh(sk);

	/* 重启动窗口值选择其与当前窗口值两者之间的较小值 */
	restart_cwnd = min(restart_cwnd, cwnd);

	/* 如果当前拥塞窗口大于重启动窗口，空闲时长每经过RTO时段，将当前拥塞窗口减半。 */
	while ((delta -= inet_csk(sk)->icsk_rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;

	/* 拥塞窗口等于拥塞窗口与重启动窗口之间的最大值。 */
	tp->snd_cwnd = max(cwnd, restart_cwnd);
	tp->snd_cwnd_stamp = tcp_jiffies32;
	tp->snd_cwnd_used = 0;
}

/* Congestion state accounting after a packet has been sent. */
static void tcp_event_data_sent(struct tcp_sock *tp,
				struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const u32 now = tcp_jiffies32;

	if (tcp_packets_in_flight(tp) == 0)
		tcp_ca_event(sk, CA_EVENT_TX_START);

	tp->lsndtime = now;

	/* If it is a reply for ato after last received
	 * packet, enter pingpong mode.
	 */
	if ((u32)(now - icsk->icsk_ack.lrcvtime) < icsk->icsk_ack.ato)
		icsk->icsk_ack.pingpong = 1;
}

/* Account for an ACK we sent. */
static inline void tcp_event_ack_sent(struct sock *sk, unsigned int pkts,
				      u32 rcv_nxt)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(tp->compressed_ack > TCP_FASTRETRANS_THRESH)) {
		NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPACKCOMPRESSED,
			      tp->compressed_ack - TCP_FASTRETRANS_THRESH);
		tp->compressed_ack = TCP_FASTRETRANS_THRESH;
		if (hrtimer_try_to_cancel(&tp->compressed_ack_timer) == 1)
			__sock_put(sk);
	}

	if (unlikely(rcv_nxt != tp->rcv_nxt))
		return;  /* Special ACK sent by DCTCP to reflect ECN */
	tcp_dec_quickack_mode(sk, pkts);
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void tcp_select_initial_window(const struct sock *sk, int __space, __u32 mss,
			       __u32 *rcv_wnd, __u32 *window_clamp,
			       int wscale_ok, __u8 *rcv_wscale,
			       __u32 init_rcv_wnd)
{
	unsigned int space = (__space < 0 ? 0 : __space);

	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (U16_MAX << TCP_MAX_WSCALE);
	space = min(*window_clamp, space);

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = rounddown(space, mss);

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sock_net(sk)->ipv4.sysctl_tcp_workaround_signed_windows)
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = min_t(u32, space, U16_MAX);

	if (init_rcv_wnd)
		*rcv_wnd = min(*rcv_wnd, init_rcv_wnd * mss);

	*rcv_wscale = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window */
		space = max_t(u32, space, sock_net(sk)->ipv4.sysctl_tcp_rmem[2]);
		space = max_t(u32, space, sysctl_rmem_max);
		space = min_t(u32, space, *window_clamp);
		*rcv_wscale = clamp_t(int, ilog2(space) - 15,
				      0, TCP_MAX_WSCALE);
	}
	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min_t(__u32, U16_MAX << (*rcv_wscale), *window_clamp);
}
EXPORT_SYMBOL(tcp_select_initial_window);

/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
/*
 * 用于选择一个新的窗口大小来作为后续的通告窗口；返回的结果根据
 * RFC1323（详见1.3.2）进行了缩放。
 */
static u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 old_win = tp->rcv_wnd;
	u32 cur_win = tcp_receive_window(tp);
	u32 new_win = __tcp_select_window(sk);

	/* old_win 是接收方窗口的大小。
	 * cur_win 当前的接收窗口大小。
	 * new_win 是新选择出来的窗口大小。
	 */

	/* 当新窗口的大小小于当前窗口的大小时，不能缩减窗口大小。
	 * 这是 IEEE 强烈不建议的一种行为。
	 */
	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		if (new_win == 0)
			NET_INC_STATS(sock_net(sk),
				      LINUX_MIB_TCPWANTZEROWINDOWADV);

		/* 当计算出来的新窗口小于当前窗口时，将新窗口设置为大于 cur_win
		 * 的 1<<tp->rx_opt.rcv_wscale 的整数倍。
		 */
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}

	/* 将当前的接收窗口设置为新的窗口大小。 */
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* 判断当前窗口未越界。 */
	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale &&
	    sock_net(sk)->ipv4.sysctl_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 缩放窗口大小。这里之所以是右移，是因为此时的 new_win 是
	 * 窗口的真正大小。所以返回时需要返回正常的可以放在 16 位整型中的窗口大小。
	 * 所以需要右移。
	 */
	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	/* 因为0窗口，关闭快速路径。 */
	if (new_win == 0) {
		tp->pred_flags = 0;
		if (old_win)
			NET_INC_STATS(sock_net(sk),
				      LINUX_MIB_TCPTOZEROWINDOWADV);
	} else if (old_win == 0) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPFROMZEROWINDOWADV);
	}

	return new_win;
}

/* Packet ECN state for a SYN-ACK */
static void tcp_ecn_send_synack(struct sock *sk, struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_CWR;
	if (!(tp->ecn_flags & TCP_ECN_OK))
		TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_ECE;
	else if (tcp_ca_needs_ecn(sk) ||
		 tcp_bpf_ca_needs_ecn(sk))
		INET_ECN_xmit(sk);
}

/* Packet ECN state for a SYN.  */
static void tcp_ecn_send_syn(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	bool bpf_needs_ecn = tcp_bpf_ca_needs_ecn(sk);
	bool use_ecn = sock_net(sk)->ipv4.sysctl_tcp_ecn == 1 ||
		tcp_ca_needs_ecn(sk) || bpf_needs_ecn;

	if (!use_ecn) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_feature(dst, RTAX_FEATURE_ECN))
			use_ecn = true;
	}

	tp->ecn_flags = 0;

	if (use_ecn) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ECE | TCPHDR_CWR;
		tp->ecn_flags = TCP_ECN_OK;
		if (tcp_ca_needs_ecn(sk) || bpf_needs_ecn)
			INET_ECN_xmit(sk);
	}
}

static void tcp_ecn_clear_syn(struct sock *sk, struct sk_buff *skb)
{
	if (sock_net(sk)->ipv4.sysctl_tcp_ecn_fallback)
		/* tp->ecn_flags are cleared at a later point in time when
		 * SYN ACK is ultimatively being received.
		 */
		TCP_SKB_CB(skb)->tcp_flags &= ~(TCPHDR_ECE | TCPHDR_CWR);
}

static void
tcp_ecn_make_synack(const struct request_sock *req, struct tcphdr *th)
{
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
}

/* Set up ECN state for a packet on a ESTABLISHED socket that is about to
 * be sent.
 */
static void tcp_ecn_send(struct sock *sk, struct sk_buff *skb,
			 struct tcphdr *th, int tcp_header_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->ecn_flags & TCP_ECN_OK) {
		/* Not-retransmitted data segment: set ECT and inject CWR. */
		if (skb->len != tcp_header_len &&
		    !before(TCP_SKB_CB(skb)->seq, tp->snd_nxt)) {
			INET_ECN_xmit(sk);
			if (tp->ecn_flags & TCP_ECN_QUEUE_CWR) {
				tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
				th->cwr = 1;
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
			}
		} else if (!tcp_ca_needs_ecn(sk)) {
			/* ACK or retransmitted segment: clear ECT|CE */
			INET_ECN_dontxmit(sk);
		}
		if (tp->ecn_flags & TCP_ECN_DEMAND_CWR)
			th->ece = 1;
	}
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
static void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->ip_summed = CHECKSUM_PARTIAL;

	TCP_SKB_CB(skb)->tcp_flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;

	tcp_skb_pcount_set(skb, 1);

	TCP_SKB_CB(skb)->seq = seq;
	if (flags & (TCPHDR_SYN | TCPHDR_FIN))
		seq++;
	TCP_SKB_CB(skb)->end_seq = seq;
}

static inline bool tcp_urg_mode(const struct tcp_sock *tp)
{
	return tp->snd_una != tp->snd_up;
}

#define OPTION_SACK_ADVERTISE	(1 << 0)
#define OPTION_TS		(1 << 1)
#define OPTION_MD5		(1 << 2)
#define OPTION_WSCALE		(1 << 3)
#define OPTION_FAST_OPEN_COOKIE	(1 << 8)
#define OPTION_SMC		(1 << 9)

static void smc_options_write(__be32 *ptr, u16 *options)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (unlikely(OPTION_SMC & *options)) {
			*ptr++ = htonl((TCPOPT_NOP  << 24) |
				       (TCPOPT_NOP  << 16) |
				       (TCPOPT_EXP <<  8) |
				       (TCPOLEN_EXP_SMC_BASE));
			*ptr++ = htonl(TCPOPT_SMC_MAGIC);
		}
	}
#endif
}

/* 用于存放发送 TCP 包时， TCP 包所含的选项。*/
struct tcp_out_options {
	u16 options;		/* bit field of OPTION_* */
	u16 mss;		/* 0 to disable */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u8 hash_size;		/* bytes in hash_location */
	__u8 *hash_location;	/* temporary pointer, overloaded */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
	struct tcp_fastopen_cookie *fastopen_cookie;	/* Fast open cookie */
};

/* Write previously computed TCP options to the packet.
 *
 * Beware: Something in the Internet is very sensitive to the ordering of
 * TCP options, we learned this through the hard way, so be careful here.
 * Luckily we can at least blame others for their non-compliance but from
 * inter-operability perspective it seems that we're somewhat stuck with
 * the ordering which we have been using if we want to keep working with
 * those broken things (not that it currently hurts anybody as there isn't
 * particular reason why the ordering would need to be changed).
 *
 * At least SACK_PERM as the first option is known to lead to a disaster
 * (but it may well be that other scenarios fail similarly).
 */
static void tcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			      struct tcp_out_options *opts)
{
	u16 options = opts->options;	/* mungable copy */

	if (unlikely(OPTION_MD5 & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		/* overload cookie hash location */
		opts->hash_location = (__u8 *)ptr;
		ptr += 4;
	}

	if (unlikely(opts->mss)) {
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss);
	}

	if (likely(OPTION_TS & options)) {
		if (unlikely(OPTION_SACK_ADVERTISE & options)) {
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
			options &= ~OPTION_SACK_ADVERTISE;
		} else {
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		}
		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	}

	if (unlikely(OPTION_SACK_ADVERTISE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
	}

	if (unlikely(OPTION_WSCALE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->ws);
	}

	if (unlikely(opts->num_sack_blocks)) {
		struct tcp_sack_block *sp = tp->rx_opt.dsack ?
			tp->duplicate_sack : tp->selective_acks;
		int this_sack;

		*ptr++ = htonl((TCPOPT_NOP  << 24) |
			       (TCPOPT_NOP  << 16) |
			       (TCPOPT_SACK <<  8) |
			       (TCPOLEN_SACK_BASE + (opts->num_sack_blocks *
						     TCPOLEN_SACK_PERBLOCK)));

		for (this_sack = 0; this_sack < opts->num_sack_blocks;
		     ++this_sack) {
			*ptr++ = htonl(sp[this_sack].start_seq);
			*ptr++ = htonl(sp[this_sack].end_seq);
		}

		tp->rx_opt.dsack = 0;
	}

	if (unlikely(OPTION_FAST_OPEN_COOKIE & options)) {
		struct tcp_fastopen_cookie *foc = opts->fastopen_cookie;
		u8 *p = (u8 *)ptr;
		u32 len; /* Fast Open option length */

		if (foc->exp) {
			len = TCPOLEN_EXP_FASTOPEN_BASE + foc->len;
			*ptr = htonl((TCPOPT_EXP << 24) | (len << 16) |
				     TCPOPT_FASTOPEN_MAGIC);
			p += TCPOLEN_EXP_FASTOPEN_BASE;
		} else {
			len = TCPOLEN_FASTOPEN_BASE + foc->len;
			*p++ = TCPOPT_FASTOPEN;
			*p++ = len;
		}

		memcpy(p, foc->val, foc->len);
		if ((len & 3) == 2) {
			p[foc->len] = TCPOPT_NOP;
			p[foc->len + 1] = TCPOPT_NOP;
		}
		ptr += (len + 3) >> 2;
	}

	smc_options_write(ptr, &options);
}

static void smc_set_option(const struct tcp_sock *tp,
			   struct tcp_out_options *opts,
			   unsigned int *remaining)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (tp->syn_smc) {
			if (*remaining >= TCPOLEN_EXP_SMC_BASE_ALIGNED) {
				opts->options |= OPTION_SMC;
				*remaining -= TCPOLEN_EXP_SMC_BASE_ALIGNED;
			}
		}
	}
#endif
}

static void smc_set_option_cond(const struct tcp_sock *tp,
				const struct inet_request_sock *ireq,
				struct tcp_out_options *opts,
				unsigned int *remaining)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (tp->syn_smc && ireq->smc_ok) {
			if (*remaining >= TCPOLEN_EXP_SMC_BASE_ALIGNED) {
				opts->options |= OPTION_SMC;
				*remaining -= TCPOLEN_EXP_SMC_BASE_ALIGNED;
			}
		}
	}
#endif
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
 /*
  * 该函数用户构建带 SYN 选项的 TCP 包。当然，这里只是计算出 TCP 的选项字段
  * 需要多大空间，并不是真正地将选项构建成了 TCP 标准中所规定的格式。
  */
static unsigned int tcp_syn_options(struct sock *sk, struct sk_buff *skb,
				struct tcp_out_options *opts,
				struct tcp_md5sig_key **md5)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;
	struct tcp_fastopen_request *fastopen = tp->fastopen_req;

	*md5 = NULL;

	/* remaining 代表剩余了多少空间。根据 RFC793， TCP 选项的空间是有限的。
 	 * 在后面的代码中，每增加一个选项就会相应地减少 remaining。
 	 */
#ifdef CONFIG_TCP_MD5SIG
	if (static_key_false(&tcp_md5_needed) &&
	    rcu_access_pointer(tp->md5sig_info)) {
		*md5 = tp->af_specific->md5_lookup(sk, sk);
		if (*md5) {
			opts->options |= OPTION_MD5;
			remaining -= TCPOLEN_MD5SIG_ALIGNED;
		}
	}
#endif

	/* We always get an MSS option.  The option bytes which will be seen in
	 * normal data packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so that
	 * calculations in tcp_sendmsg are simpler etc.  So account for this
	 * fact here if necessary.  If we don't do this correctly, as a
	 * receiver we won't recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK rules correctly.
	 * SACKs don't matter, we never delay an ACK when we have any of those
	 * going out.  */
	opts->mss = tcp_advertise_mss(sk);
	remaining -= TCPOLEN_MSS_ALIGNED;

	if (likely(sock_net(sk)->ipv4.sysctl_tcp_timestamps && !*md5)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcp_skb_timestamp(skb) + tp->tsoffset;
		opts->tsecr = tp->rx_opt.ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_window_scaling)) {
		opts->ws = tp->rx_opt.rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_sack)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!(OPTION_TS & opts->options)))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}

	if (fastopen && fastopen->cookie.len >= 0) {
		u32 need = fastopen->cookie.len;

		need += fastopen->cookie.exp ? TCPOLEN_EXP_FASTOPEN_BASE :
					       TCPOLEN_FASTOPEN_BASE;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		/* 到这里会产生一个有趣的现象， remaining 有可能不够用。
 		 * 可以看到，如果选项中的剩余空间不够用了，那么就放弃启用 Fast Open。
 	 	 */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = &fastopen->cookie;
			remaining -= need;
			tp->syn_fastopen = 1;
			tp->syn_fastopen_exp = fastopen->cookie.exp ? 1 : 0;
		}
	}

	smc_set_option(tp, opts, &remaining);

	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Set up TCP options for SYN-ACKs. */
static unsigned int tcp_synack_options(const struct sock *sk,
				       struct request_sock *req,
				       unsigned int mss, struct sk_buff *skb,
				       struct tcp_out_options *opts,
				       const struct tcp_md5sig_key *md5,
				       struct tcp_fastopen_cookie *foc)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;

#ifdef CONFIG_TCP_MD5SIG
	if (md5) {
		opts->options |= OPTION_MD5;
		remaining -= TCPOLEN_MD5SIG_ALIGNED;

		/* We can't fit any SACK blocks in a packet with MD5 + TS
		 * options. There was discussion about disabling SACK
		 * rather than TS in order to fit in better with old,
		 * buggy kernels, but that was deemed to be unnecessary.
		 */
		ireq->tstamp_ok &= !ireq->sack_ok;
	}
#endif

	/* We always send an MSS option. */
	opts->mss = mss;
	remaining -= TCPOLEN_MSS_ALIGNED;

	if (likely(ireq->wscale_ok)) {
		opts->ws = ireq->rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(ireq->tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcp_skb_timestamp(skb) + tcp_rsk(req)->ts_off;
		opts->tsecr = req->ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(ireq->sack_ok)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!ireq->tstamp_ok))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}
	if (foc != NULL && foc->len >= 0) {
		u32 need = foc->len;

		need += foc->exp ? TCPOLEN_EXP_FASTOPEN_BASE :
				   TCPOLEN_FASTOPEN_BASE;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = foc;
			remaining -= need;
		}
	}

	smc_set_option_cond(tcp_sk(sk), ireq, opts, &remaining);

	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
 /*
  * 这个函数用于计算连接已经建立的状态下， TCP 包的头部选项所占用的空间。通
  * 过和 tcp_syn_options函数的对比我们可以直观地看到，大部分 TCP 选项都是在发起
  * 连接的时候放在 TCP 包里的。真正开始传输后， TCP 包所需携带的选项信息就少了很
  * 多。
  */
static unsigned int tcp_established_options(struct sock *sk, struct sk_buff *skb,
					struct tcp_out_options *opts,
					struct tcp_md5sig_key **md5)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int size = 0;
	unsigned int eff_sacks;

	opts->options = 0;

	*md5 = NULL;
#ifdef CONFIG_TCP_MD5SIG
	if (static_key_false(&tcp_md5_needed) &&
	    rcu_access_pointer(tp->md5sig_info)) {
		*md5 = tp->af_specific->md5_lookup(sk, sk);
		if (*md5) {
			opts->options |= OPTION_MD5;
			size += TCPOLEN_MD5SIG_ALIGNED;
		}
	}
#endif

	if (likely(tp->rx_opt.tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = skb ? tcp_skb_timestamp(skb) + tp->tsoffset : 0;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}

	eff_sacks = tp->rx_opt.num_sacks + tp->rx_opt.dsack;
	if (unlikely(eff_sacks)) {
		const unsigned int remaining = MAX_TCP_OPTION_SPACE - size;
		opts->num_sack_blocks =
			min_t(unsigned int, eff_sacks,
			      (remaining - TCPOLEN_SACK_BASE_ALIGNED) /
			      TCPOLEN_SACK_PERBLOCK);
		size += TCPOLEN_SACK_BASE_ALIGNED +
			opts->num_sack_blocks * TCPOLEN_SACK_PERBLOCK;
	}

	return size;
}


/* TCP SMALL QUEUES (TSQ)
 *
 * TSQ goal is to keep small amount of skbs per tcp flow in tx queues (qdisc+dev)
 * to reduce RTT and bufferbloat.
 * We do this using a special skb destructor (tcp_wfree).
 *
 * Its important tcp_wfree() can be replaced by sock_wfree() in the event skb
 * needs to be reallocated in a driver.
 * The invariant being skb->truesize subtracted from sk->sk_wmem_alloc
 *
 * Since transmit from skb destructor is forbidden, we use a tasklet
 * to process all sockets that eventually need to send more skbs.
 * We use one tasklet per cpu, with its own queue of sockets.
 */
/*
 * TCP Small Queues的目的是限制每个tcp连接在Qdisc和device队列中的skb数量，以达到降低RTT和避免bufferbloat的目的。
 */
struct tsq_tasklet {
	struct tasklet_struct	tasklet;
	struct list_head	head; /* queue of tcp sockets */
};

/* 为每个处理器都分配一个tsq_tasklet，且每个tasklet有独立的socket队列。
 * https://blog.csdn.net/u011130578/article/details/44645643
 */
static DEFINE_PER_CPU(struct tsq_tasklet, tsq_tasklet);

static void tcp_tsq_write(struct sock *sk)
{
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_FIN_WAIT1 | TCPF_CLOSING |
	     TCPF_CLOSE_WAIT  | TCPF_LAST_ACK)) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (tp->lost_out > tp->retrans_out &&
		    tp->snd_cwnd > tcp_packets_in_flight(tp)) {
			tcp_mstamp_refresh(tp);
			tcp_xmit_retransmit_queue(sk);
		}

		tcp_write_xmit(sk, tcp_current_mss(sk), tp->nonagle,
			       0, GFP_ATOMIC);
	}
}

/* TSQ的核心处理函数tcp_tsq_handler()，负责重新调用TCP的发送或者重传函数。 */
static void tcp_tsq_handler(struct sock *sk)
{
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk))
		tcp_tsq_write(sk);
	else if (!test_and_set_bit(TCP_TSQ_DEFERRED, &sk->sk_tsq_flags))
		sock_hold(sk);
	bh_unlock_sock(sk);
}
/*
 * One tasklet per cpu tries to send more skbs.
 * We run in tasklet context but need to disable irqs when
 * transferring tsq->head because tcp_wfree() might
 * interrupt us (non NAPI drivers)
 */
/*
 * 以上的tasklet_schedule调用了初始化时注册的tcp_tasklet_func函数。如下，在其处理过程中，
 * 首先从TSQ队列中移除套接口，清除其TSQ_QUEUE入队标志。其次，如果此套接口未设置TCP_TSQ_DEFERRED标志，
 * 表明其已经在tcp_write_xmit发送函数中得到处理，此处不再处理。否则，如果此套接口没有被用户层系统调用锁定，
 * 调用TSQ核心处理函数tcp_tsq_handler处理。
 */
static void tcp_tasklet_func(unsigned long data)
{
	struct tsq_tasklet *tsq = (struct tsq_tasklet *)data;
	LIST_HEAD(list);
	unsigned long flags;
	struct list_head *q, *n;
	struct tcp_sock *tp;
	struct sock *sk;

	local_irq_save(flags);
	list_splice_init(&tsq->head, &list);
	local_irq_restore(flags);

	/* 遍历挂入TSQ队列中的socket，并调用tcp_write_xmit() 发送socket发送队列中的数据。*/
	list_for_each_safe(q, n, &list) {
		tp = list_entry(q, struct tcp_sock, tsq_node);
		list_del(&tp->tsq_node);

		sk = (struct sock *)tp;
		smp_mb__before_atomic();
		clear_bit(TSQ_QUEUED, &sk->sk_tsq_flags);

		tcp_tsq_handler(sk);
		sk_free(sk);
	}
}

#define TCP_DEFERRED_ALL (TCPF_TSQ_DEFERRED |		\
			  TCPF_WRITE_TIMER_DEFERRED |	\
			  TCPF_DELACK_TIMER_DEFERRED |	\
			  TCPF_MTU_REDUCED_DEFERRED)
/**
 * tcp_release_cb - tcp release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
/*
 * 在TSQ的tasklet中，如果用户层正在执行socket相关的系统调用，则会设置TCPF_TSQ_DEFERRED，然后退出。
 * 这样，当用户层系统调用退出时，在套接口释放函数tcp_release_cb()中，就会根据标志TCPF_TSQ_DEFERRED的判断，
 * 执行TSQ函数tcp_tsq_handler()进行发包处理。
 */
void tcp_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & TCP_DEFERRED_ALL))
			return;
		nflags = flags & ~TCP_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	if (flags & TCPF_TSQ_DEFERRED) {
		tcp_tsq_write(sk);
		__sock_put(sk);
	}
	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	sock_release_ownership(sk);

	if (flags & TCPF_WRITE_TIMER_DEFERRED) {
		tcp_write_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & TCPF_DELACK_TIMER_DEFERRED) {
		tcp_delack_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & TCPF_MTU_REDUCED_DEFERRED) {
		inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
		__sock_put(sk);
	}
}
EXPORT_SYMBOL(tcp_release_cb);

void __init tcp_tasklet_init(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct tsq_tasklet *tsq = &per_cpu(tsq_tasklet, i);

		INIT_LIST_HEAD(&tsq->head);
		tasklet_init(&tsq->tasklet,
			     tcp_tasklet_func,
			     (unsigned long)tsq);
	}
}

/*
 * Write buffer destructor automatically called from kfree_skb.
 * We can't xmit new skbs from this context, as we might already
 * hold qdisc lock.
 */
/*
 * 当数据报文skb释放时（如TX完成中断发生），检查其所属套接口的TSQ阻塞状态，如下发送缓存释放函数tcp_wfree。
 * 首先将发送缓存sk_wmem_alloc的值将其skb的truesize-1的值，保留1个计数是由于此函数之后或者tcp_tasklet_func函数
 * 将调用sk_free函数，如果sk_wmem_alloc为1，sk_free将释放套接口结构。其次如果当前进程上下文在ksoftirqd中，
 * 并且Qdisc或者设备队列中还有数据未发送，表明系统当前繁忙，不在进行TSQ拥塞处理，避免导致加重系统的繁忙状况，
 * 也可使此TCP流的确认ACK报文得以处理。
 * 
 * 如果此套接口没有被TSQ阻塞，TSQF_THROTTLED标志未设置，或者其已经位于TSQ处理队列中，直接返回。
 * 如果在此期间套接口的阻塞状态已经缓解（见cmpxchg函数实现），直接返回。否则，将处于阻塞状态的套接口
 * 的sk_tsq_flags中的阻塞状态清除，并且将此套接口添加到当前处理器的TSQ处理队列中，
 * 并且调用处理器的takslet进行处理。
 */
void tcp_wfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long flags, nval, oval;

	/* Keep one reference on sk_wmem_alloc.
	 * Will be released by sk_free() from here or tcp_tasklet_func()
	 */
	WARN_ON(refcount_sub_and_test(skb->truesize - 1, &sk->sk_wmem_alloc));

	/* If this softirq is serviced by ksoftirqd, we are likely under stress.
	 * Wait until our queues (qdisc + devices) are drained.
	 * This gives :
	 * - less callbacks to tcp_write_xmit(), reducing stress (batches)
	 * - chance for incoming ACK (processed by another cpu maybe)
	 *   to migrate this flow (skb->ooo_okay will be eventually set)
	 */
	if (refcount_read(&sk->sk_wmem_alloc) >= SKB_TRUESIZE(1) && this_cpu_ksoftirqd() == current)
		goto out;

	for (oval = READ_ONCE(sk->sk_tsq_flags);; oval = nval) {
		struct tsq_tasklet *tsq;
		bool empty;

		if (!(oval & TSQF_THROTTLED) || (oval & TSQF_QUEUED))
			goto out;

		nval = (oval & ~TSQF_THROTTLED) | TSQF_QUEUED;
		nval = cmpxchg(&sk->sk_tsq_flags, oval, nval);
		if (nval != oval)
			continue;

		/* queue this socket to tasklet queue */
		local_irq_save(flags);
		tsq = this_cpu_ptr(&tsq_tasklet);
		empty = list_empty(&tsq->head);
		list_add(&tp->tsq_node, &tsq->head); //将socket加入到TSQ队列中
		if (empty)
			tasklet_schedule(&tsq->tasklet);
		local_irq_restore(flags);
		return;
	}
out:
	sk_free(sk);
}

/* Note: Called under soft irq.
 * We can call TCP stack right away, unless socket is owned by user.
 */
/* 除以tcp_wfree()之外，在TCP的pacing功能中，pacing超时处理函数tcp_pace_kick()已将处理TSQ除以阻塞状态的套接口，
 * 其逻辑与tcp_wfree中的一致，唯一区别在于pacing处理中，不会先检查套接口是否处于阻塞状态。
 *
 * 由于在TSQ检查时，可能由于当前的pacing速率sk_pacing_rate过高，TSQ限制了数据报文的发送，
 * 将套接口设置为阻塞状态。所以，在tcp_pace_kick函数中处理TSQ队列，必要时调用TSQ的tasklet处理。
 */
enum hrtimer_restart tcp_pace_kick(struct hrtimer *timer)
{
	struct tcp_sock *tp = container_of(timer, struct tcp_sock, pacing_timer);
	struct sock *sk = (struct sock *)tp;

	tcp_tsq_handler(sk);
	sock_put(sk);

	return HRTIMER_NORESTART;
}

static void tcp_update_skb_after_send(struct sock *sk, struct sk_buff *skb,
				      u64 prior_wstamp)
{
	struct tcp_sock *tp = tcp_sk(sk);

	skb->skb_mstamp_ns = tp->tcp_wstamp_ns;
	if (sk->sk_pacing_status != SK_PACING_NONE) {
		unsigned long rate = sk->sk_pacing_rate;

		/* Original sch_fq does not pace first 10 MSS
		 * Note that tp->data_segs_out overflows after 2^32 packets,
		 * this is a minor annoyance.
		 */
		if (rate != ~0UL && rate && tp->data_segs_out >= 10) {
			u64 len_ns = div64_ul((u64)skb->len * NSEC_PER_SEC, rate);
			u64 credit = tp->tcp_wstamp_ns - prior_wstamp;

			/* take into account OS jitter */
			len_ns -= min_t(u64, len_ns / 2, credit);
			tp->tcp_wstamp_ns += len_ns;
		}
	}
	list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);
}

/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
 
 /* https://blog.csdn.net/city_of_skey/article/details/84723087 */

static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,
			      int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned int tcp_options_size, tcp_header_size;
	struct sk_buff *oskb = NULL;
	struct tcp_md5sig_key *md5;
	struct tcphdr *th;
	u64 prior_wstamp;
	int err;

	BUG_ON(!skb || !tcp_skb_pcount(skb));
	tp = tcp_sk(sk);

	/* 查看是否要克隆待发送的数据包, 一般情况下，都要克隆一份，等待收到ack后再删除。 */
	if (clone_it) {
		TCP_SKB_CB(skb)->tx.in_flight = TCP_SKB_CB(skb)->end_seq
			- tp->snd_una;
		oskb = skb;

		tcp_skb_tsorted_save(oskb) {
			/* 如果已经被克隆的skb，则进行复制skb。否则克隆一份。*/
			if (unlikely(skb_cloned(oskb)))
				skb = pskb_copy(oskb, gfp_mask);
			else
				skb = skb_clone(oskb, gfp_mask);
		} tcp_skb_tsorted_restore(oskb);

		if (unlikely(!skb))
			return -ENOBUFS;
	}

	/* 记录当前pacing的时间戳，用于后续的pacing计算检查。 */
	prior_wstamp = tp->tcp_wstamp_ns;
	tp->tcp_wstamp_ns = max(tp->tcp_wstamp_ns, tp->tcp_clock_cache);

	skb->skb_mstamp_ns = tp->tcp_wstamp_ns;

	/* 开始构建TCP的头部：
	 * 查看数据包是否是一个SYN包（TCPCB_FLAG_SYN），如果是，就调用 tcp_syn_options() 构建SYN数据段的选项数据，
	 * 包括时间戳、窗口大小、选择回答(SACK）, 否则调用 tcp_establishe_options() 构建常规TCP选项，
	 * 并返回TCP选项长度。
	 * 注意：这里仅仅是计算出来具体的选项及其大小，并没有形成最终tcp包中选项的格式。
	 */
	inet = inet_sk(sk);
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

	/* 确定TCP协议选项，不同类型的packet */
	if (unlikely(tcb->tcp_flags & TCPHDR_SYN))
		/* 构建SYN包，包括时间戳，MSS, WSCALE，SACK，fast open。*/
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &md5); 
	else
		/* 构建非SYNC TCP segment header选项，包括时间戳，SACK */
		tcp_options_size = tcp_established_options(sk, skb, &opts,
							   &md5);

	/* TCP头部长度包括options长度 + TCP头部，之后，调用相关函数在skb头部为TCP头部留出空间。*/
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	
	/* 拥塞控制：
	 * 确定网络上有多少数据包，大多数情况下是按照保守情况处理，
	 * 网络上有多少数据包做好的详细信息是用收到的SACK的信息来确认，
	 * tp->pachets_out确定发送队列中是否为空，阻塞控制计算方法：
	 * 传送队列上的数据包 + 必须快速重传数据包 - 留在网络上的数据包，
	 * 如果等于0表示不会阻塞，这时发送时间标志。
	 */
	/* if no packet is in qdisc/device queue, then allow XPS to select
	 * another queue. We can be called from tcp_tsq_handler()
	 * which holds one reference to sk.
	 *
	 * TODO: Ideally, in-flight pure ACK packets should not matter here.
	 * One way to get this would be to set skb->truesize = 2 on them.
	 */
	skb->ooo_okay = sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1);

	/* If we had to use memory reserve to allocate this skb,
	 * this might cause drops if packet is looped back :
	 * Other socket might not have SOCK_MEMALLOC.
	 * Packets not looped back do not care about pfmemalloc.
	 */
	skb->pfmemalloc = 0;

	/* 预留TCP header需要的空间，包括tcp option部分。 */
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = skb_is_tcp_pure_ack(skb) ? __sock_wfree : tcp_wfree;

	/* 如果sock已经有计算好sk_txhash，则直接将sk->sk_txhash赋值给skb->l4_hash，并设置skb->l4_hash。
	 * hash值可以在其他地方使用，比如 netdev driver中也可由使用该hash值，进行skb的分类。
	 */
	skb_set_hash_from_sk(skb, sk);
	refcount_add(skb->truesize, &sk->sk_wmem_alloc);

	skb_set_dst_pending_confirm(skb, sk->sk_dst_pending_confirm);

	/* 
	 * 真正构建TCP header并计算校验和：
	 * 构建TCP协议头主要的数据域：源端口、目的端口、数据段初始序列号，tcp_select_window计算窗口大小，
	 * 如果是SYN请求包就不需要计算窗口大小。
	 */
	/* Build TCP header and checksum it. */
	th = (struct tcphdr *)skb->data;
	th->source		= inet->inet_sport;
	th->dest		= inet->inet_dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->tcp_flags);

	th->check		= 0;
	th->urg_ptr		= 0;

	/* The urg_mode check is necessary during a below snd_una win probe */
	if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			th->urg_ptr = htons(0xFFFF);
			th->urg = 1;
		}
	}

	/* 构建好tcp首部后，开始构建tcp选项。即 从tcp_out_options中获取上面设置的options。  */
	tcp_options_write((__be32 *)(th + 1), tp, &opts);

	/* 这里会设置tcp skb的gso type，即 SKB_GSO_TCPV4 */
	skb_shinfo(skb)->gso_type = sk->sk_gso_type;

	if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {
		th->window      = htons(tcp_select_window(sk));
		tcp_ecn_send(sk, skb, th, tcp_header_size);
	} else {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	}

	/* 通过TCP MD5签名来保护BGP会话操作相关 */
#ifdef CONFIG_TCP_MD5SIG
	/* Calculate the MD5 hash, as we have all we need now */
	if (md5) {
		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		tp->af_specific->calc_md5_hash(opts.hash_location,
					       md5, sk, skb);
	}
#endif

	/* 调用 tcp_v4_send_check() 会进行checksum的判断和计算。
	 * 这里的checksum 计算, 只进行了伪头部的计算，剩余的推迟到
	 * 最后sch_generic.c中sch_direct_xmit->validate_xmit_skb()计算。
	 */
	icsk->icsk_af_ops->send_check(sk, skb);

	/* 触发相关的 TCP 事件，这些会被用于拥塞控制算法。 */
	if (likely(tcb->tcp_flags & TCPHDR_ACK))
		tcp_event_ack_sent(sk, tcp_skb_pcount(skb), rcv_nxt);

	if (skb->len != tcp_header_size) {
		tcp_event_data_sent(tp, sk);
		tp->data_segs_out += tcp_skb_pcount(skb);
		tp->bytes_sent += skb->len - tcp_header_size;
	}

	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
			      tcp_skb_pcount(skb));

	tp->segs_out += tcp_skb_pcount(skb);

	/* 这里会设置skb的gso信息，即分段长度和分段数量。 */
	/* OK, its time to fill skb_shinfo(skb)->gso_{segs|size} */
	skb_shinfo(skb)->gso_segs = tcp_skb_pcount(skb);
	skb_shinfo(skb)->gso_size = tcp_skb_mss(skb);

	/* Leave earliest departure time in skb->tstamp (skb->skb_mstamp_ns) */

	/* Cleanup our debris for IP stacks */
	memset(skb->cb, 0, max(sizeof(struct inet_skb_parm),
			       sizeof(struct inet6_skb_parm)));


	/* 实际会调用 ip_queue_xmit() 函数, 把skb送入网络层。
	 * tcp_ipv4.c中的  icsk: internet connect socket。
	 */
	err = icsk->icsk_af_ops->queue_xmit(sk, skb, &inet->cork.fl);

	if (unlikely(err > 0)) {
		/* 如果发送了丢包（如被主动队列管理丢弃），那么进入到拥塞状态机的 CA_CWR 状态。 */
		tcp_enter_cwr(sk);
		err = net_xmit_eval(err);
	}
	if (!err && oskb) {
		/* 成功发送一个skb给qdisc或netdev后，更新发送下一个skb的时间戳。tcp_wstamp_ns */
		tcp_update_skb_after_send(sk, oskb, prior_wstamp);

		/* 用于计算tcp发送速率 */
		tcp_rate_skb_sent(sk, oskb);
	}
	return err;
}


/* TCP数据最终都是通过         tcp_transmit_skb() 函数传送给IP层的。主要工作是构建TCP的首部，并将包交付给IP层。
 * 由于数据段需要等到ACK后才能释放，因此，在发送前会根据参数确定是克隆还是复制一份SKB用于发送。
 * 使用场景包括：
 *	.来自用户空间的数据发送
 *	.重传数据包 - tcp_retransmit_skb()
 *	.探测路由最大传送单元数据包 - tcp_mtu_probe()
 *	.发送复位连接数据包 - tcp_send_active_reset()
 *	.发送连接请求数据包 - tcp_connect()
 *	.发送回答数据包 - tcp_send_ack()
 *	.零窗口探测数据包等 - tcp_xmit_probe_skb()
 */
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	return __tcp_transmit_skb(sk, skb, clone_it, gfp_mask,
				  tcp_sk(sk)->rcv_nxt);
}

/* This routine just queues the buffer for sending.
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	__skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

/* Initialize TSO segments for a packet. */
/* 设置一个tcp skb中的gso信息。
 * 主要是 tcp_gso_size, tcp_gso_segs
 */
static void tcp_set_skb_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	if (skb->len <= mss_now) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		tcp_skb_pcount_set(skb, 1);
		TCP_SKB_CB(skb)->tcp_gso_size = 0;
	} else {
		tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
		TCP_SKB_CB(skb)->tcp_gso_size = mss_now; //用于后面gso分段，即段长度。
	}
}

/* Pcount in the middle of the write queue got changed, we need to do various
 * tweaks to fix counters
 */
static void tcp_adjust_pcount(struct sock *sk, const struct sk_buff *skb, int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->packets_out -= decr;

	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		tp->sacked_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
		tp->retrans_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
		tp->lost_out -= decr;

	/* Reno case is special. Sigh... */
	if (tcp_is_reno(tp) && decr > 0)
		tp->sacked_out -= min_t(u32, tp->sacked_out, decr);

	if (tp->lost_skb_hint &&
	    before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(tp->lost_skb_hint)->seq) &&
	    (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
		tp->lost_cnt_hint -= decr;

	tcp_verify_left_out(tp);
}

static bool tcp_has_tx_tstamp(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->txstamp_ack ||
		(skb_shinfo(skb)->tx_flags & SKBTX_ANY_TSTAMP);
}

static void tcp_fragment_tstamp(struct sk_buff *skb, struct sk_buff *skb2)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);

	if (unlikely(tcp_has_tx_tstamp(skb)) &&
	    !before(shinfo->tskey, TCP_SKB_CB(skb2)->seq)) {
		struct skb_shared_info *shinfo2 = skb_shinfo(skb2);
		u8 tsflags = shinfo->tx_flags & SKBTX_ANY_TSTAMP;

		shinfo->tx_flags &= ~tsflags;
		shinfo2->tx_flags |= tsflags;
		swap(shinfo->tskey, shinfo2->tskey);
		TCP_SKB_CB(skb2)->txstamp_ack = TCP_SKB_CB(skb)->txstamp_ack;
		TCP_SKB_CB(skb)->txstamp_ack = 0;
	}
}

static void tcp_skb_fragment_eor(struct sk_buff *skb, struct sk_buff *skb2)
{
	TCP_SKB_CB(skb2)->eor = TCP_SKB_CB(skb)->eor;
	TCP_SKB_CB(skb)->eor = 0;
}

/* Insert buff after skb on the write or rtx queue of sk.  */
static void tcp_insert_write_queue_after(struct sk_buff *skb,
					 struct sk_buff *buff,
					 struct sock *sk,
					 enum tcp_queue tcp_queue)
{
	if (tcp_queue == TCP_FRAG_IN_WRITE_QUEUE)
		__skb_queue_after(&sk->sk_write_queue, skb, buff);
	else
		tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
int tcp_fragment(struct sock *sk, enum tcp_queue tcp_queue,
		 struct sk_buff *skb, u32 len,
		 unsigned int mss_now, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	int nlen;
	u8 flags;

	if (WARN_ON(len > skb->len))
		return -EINVAL;

	/* 获取减去指定的第一个skb包大小后，剩余的数据大小 */
	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	if (skb_unclone(skb, gfp))
		return -ENOMEM;

	/* 获取第二个skb的buffer，用于存剩余的数据。 */
	/* Get a new skb... force flag on. */
	buff = sk_stream_alloc_skb(sk, nsize, gfp, true);
	if (!buff)
		return -ENOMEM; /* We'll just try again later. */

	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;
	tcp_skb_fragment_eor(skb, buff);

	/* 将要分割的skb，分割成两个skb。 */
	skb_split(skb, buff, len);

	buff->ip_summed = CHECKSUM_PARTIAL;

	buff->tstamp = skb->tstamp;
	tcp_fragment_tstamp(skb, buff);

	old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, mss_now);
	tcp_set_skb_tso_segs(buff, mss_now);

	/* Update delivered info for the new segment */
	TCP_SKB_CB(buff)->tx = TCP_SKB_CB(skb)->tx;

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - tcp_skb_pcount(skb) -
			tcp_skb_pcount(buff);

		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
	}

	/* 将分段后的第2个skb，加入到 sk_write_queue */
	/* Link BUFF into the send queue. */
	__skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk, tcp_queue);
	if (tcp_queue == TCP_FRAG_IN_RTX_QUEUE)
		list_add(&buff->tcp_tsorted_anchor, &skb->tcp_tsorted_anchor);

	return 0;
}

/* This is similar to __pskb_pull_tail(). The difference is that pulled
 * data is not copied, but immediately discarded.
 */
static int __pskb_trim_head(struct sk_buff *skb, int len)
{
	struct skb_shared_info *shinfo;
	int i, k, eat;

	eat = min_t(int, len, skb_headlen(skb));
	if (eat) {
		__skb_pull(skb, eat);
		len -= eat;
		if (!len)
			return 0;
	}
	eat = len;
	k = 0;
	shinfo = skb_shinfo(skb);
	for (i = 0; i < shinfo->nr_frags; i++) {
		int size = skb_frag_size(&shinfo->frags[i]);

		if (size <= eat) {
			skb_frag_unref(skb, i);
			eat -= size;
		} else {
			shinfo->frags[k] = shinfo->frags[i];
			if (eat) {
				shinfo->frags[k].page_offset += eat;
				skb_frag_size_sub(&shinfo->frags[k], eat);
				eat = 0;
			}
			k++;
		}
	}
	shinfo->nr_frags = k;

	skb->data_len -= len;
	skb->len = skb->data_len;
	return len;
}

/* Remove acked data from a packet in the transmit queue. */
int tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	u32 delta_truesize;

	if (skb_unclone(skb, GFP_ATOMIC))
		return -ENOMEM;

	delta_truesize = __pskb_trim_head(skb, len);

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;

	if (delta_truesize) {
		skb->truesize	   -= delta_truesize;
		sk->sk_wmem_queued -= delta_truesize;
		sk_mem_uncharge(sk, delta_truesize);
		sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	}

	/* Any change of skb->len requires recalculation of tso factor. */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(skb, tcp_skb_mss(skb));

	return 0;
}

/* Calculate MSS not accounting any TCP options.  */
static inline int __tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mss_now -= icsk->icsk_af_ops->net_frag_header_len;
	}

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	mss_now -= icsk->icsk_ext_hdr_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	if (mss_now < 48)
		mss_now = 48;
	return mss_now;
}

/* Calculate MSS. Not accounting for SACKs here.  */
int tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	/* Subtract TCP options size, not including SACKs */
	return __tcp_mtu_to_mss(sk, pmtu) -
	       (tcp_sk(sk)->tcp_header_len - sizeof(struct tcphdr));
}

/* Inverse of above */
int tcp_mss_to_mtu(struct sock *sk, int mss)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mtu;

	mtu = mss +
	      tp->tcp_header_len +
	      icsk->icsk_ext_hdr_len +
	      icsk->icsk_af_ops->net_header_len;

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mtu += icsk->icsk_af_ops->net_frag_header_len;
	}
	return mtu;
}
EXPORT_SYMBOL(tcp_mss_to_mtu);

/* MTU probing init per socket */
void tcp_mtup_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct net *net = sock_net(sk);

	icsk->icsk_mtup.enabled = net->ipv4.sysctl_tcp_mtu_probing > 1;
	icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp + sizeof(struct tcphdr) +
			       icsk->icsk_af_ops->net_header_len;
	icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, net->ipv4.sysctl_tcp_base_mss);
	icsk->icsk_mtup.probe_size = 0;
	if (icsk->icsk_mtup.enabled)
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
}
EXPORT_SYMBOL(tcp_mtup_init);

/* This function synchronize snd mss to current pmtu/exthdr set.

   tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
   for TCP options, but includes only bare TCP header.

   tp->rx_opt.mss_clamp is mss negotiated at connection setup.
   It is minimum of user_mss and mss received with SYN.
   It also does not include TCP options.

   inet_csk(sk)->icsk_pmtu_cookie is last pmtu, seen by this function.

   tp->mss_cache is current effective sending mss, including
   all tcp options except for SACKs. It is evaluated,
   taking into account current pmtu, but never exceeds
   tp->rx_opt.mss_clamp.

   NOTE1. rfc1122 clearly states that advertised MSS
   DOES NOT include either tcp or ip options.

   NOTE2. inet_csk(sk)->icsk_pmtu_cookie and tp->mss_cache
   are READ ONLY outside this function.		--ANK (980731)
 */
/* 将当前连接的路径MTU(PMTU)转换为缓存MSS(mss_cache) */
unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	if (icsk->icsk_mtup.search_high > pmtu)
		icsk->icsk_mtup.search_high = pmtu;

	mss_now = tcp_mtu_to_mss(sk, pmtu);
	mss_now = tcp_bound_to_half_wnd(tp, mss_now);

	/* And store cached results */
	icsk->icsk_pmtu_cookie = pmtu;
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
	tp->mss_cache = mss_now;

	return mss_now;
}
EXPORT_SYMBOL(tcp_sync_mss);

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 */
 /* 利用SACKs, IP options， PMTU来获取当前有效的MSS。 */
unsigned int tcp_current_mss(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned int header_len;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5;

	mss_now = tp->mss_cache;

	if (dst) {
		u32 mtu = dst_mtu(dst);
		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_sync_mss(sk, mtu);
	}

	header_len = tcp_established_options(sk, NULL, &opts, &md5) +
		     sizeof(struct tcphdr);
	/* The mss_cache is sized based on tp->tcp_header_len, which assumes
	 * some common options. If this is an odd packet (because we have SACK
	 * blocks etc) then our calculated header_len will be different, and
	 * we have to adjust mss_now correspondingly */
	if (header_len != tp->tcp_header_len) {
		int delta = (int) header_len - tp->tcp_header_len;
		mss_now -= delta;
	}

	return mss_now;
}

/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
/*
 * 此函数是在网络空闲（未充分利用）RTO时长之后调整拥塞窗口。
 * 此调整不针对重传阶段，以及应用程序受到发送缓存限值的情况。首先获得窗口的使用情况，
 * 取值为初始窗口值和tcp_cwnd_validate()函数中记录的使用值snd_cwnd_used之间的较大值。
 * 拥塞窗口值调整为原窗口值与窗口使用值之和的一半。
 */
static void tcp_cwnd_application_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open &&
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		/* Limited by application or receiver window. */
		u32 init_win = tcp_init_cwnd(tp, __sk_dst_get(sk));
		u32 win_used = max(tp->snd_cwnd_used, init_win);
		if (win_used < tp->snd_cwnd) {
			tp->snd_ssthresh = tcp_current_ssthresh(sk);
			tp->snd_cwnd = (tp->snd_cwnd + win_used) >> 1;
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_jiffies32;
}

/*
 * 第一次执行此函数时，max_packets_out和max_packets_seq均未赋值，分别为两者赋值为packets_out和SND.NXT的值。
 * 之后再次执行此函数时，只有进入下一个发送窗口期或者发送报文大于记录值时进行更新。由此可见，
 * 前者max_packets_out记录的为上一个窗口发送的最大报文数量；而后者max_packets_seq记录的为最大的发送序号。
 */
static void tcp_cwnd_validate(struct sock *sk, bool is_cwnd_limited)
{
	const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;
	struct tcp_sock *tp = tcp_sk(sk);

	/* Track the maximum number of outstanding packets in each
	 * window, and remember whether we were cwnd-limited then.
	 */
	if (!before(tp->snd_una, tp->max_packets_seq) ||
	    tp->packets_out > tp->max_packets_out) {
		tp->max_packets_out = tp->packets_out;
		tp->max_packets_seq = tp->snd_nxt;
		tp->is_cwnd_limited = is_cwnd_limited;
	}

	/*
	 * 参数is_cwnd_limited记录了上一个发送窗口期是否受到了拥塞窗口的限制。
	 * 函数tcp_is_cwnd_limited()判断连接的发送是否受限于拥塞窗口，为真，表明当前发送使用了全部可用网络资源，
	 * 反之，表明存在空闲的网络资源。
	 * 在后一种情况下，记录当前网络中报文数量到变量snd_cwnd_used中，
	 * 如果内核配置开启了在空闲时长超过RTO之后，复位拥塞窗口的功能，即tcp_slow_start_after_idle为真，
	 * 并且空闲时长大于等于RTO，并且拥塞控制算法未定义相关处理，这里调用tcp_cwnd_application_limited()函数，
	 * 处理应用限速的情况。
	 */
	if (tcp_is_cwnd_limited(sk)) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_jiffies32;
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out;

		/* 在网络空闲（未充分利用）RTO时长之后调整拥塞窗口。 */
		if (sock_net(sk)->ipv4.sysctl_tcp_slow_start_after_idle &&
		    (s32)(tcp_jiffies32 - tp->snd_cwnd_stamp) >= inet_csk(sk)->icsk_rto &&
		    !ca_ops->cong_control)
			tcp_cwnd_application_limited(sk);

		/*
		 * 以下检查是否为发送端缓存不足引起的空闲，首先，排除拥塞窗口的原因，其次，
		 * 是发送队列为空，而且应用程序遇到缓存限值，记录下发送缓存限值标志TCP_CHRONO_SNDBUF_LIMITED。
		 * 如果是，则启动 TCP_CHRONO_SNDBUF_LIMITED 计时器开始统计时间。
		 /
		/* The following conditions together indicate the starvation
		 * is caused by insufficient sender buffer:
		 * 1) just sent some data (see tcp_write_xmit)
		 * 2) not cwnd limited (this else condition)
		 * 3) no more data to send (tcp_write_queue_empty())
		 * 4) application is hitting buffer limit (SOCK_NOSPACE)
		 */
		if (tcp_write_queue_empty(sk) && sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &sk->sk_socket->flags) &&
		    (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
			tcp_chrono_start(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
}

/* Minshall's variant of the Nagle send check. */
static bool tcp_minshall_check(const struct tcp_sock *tp)
{
	return after(tp->snd_sml, tp->snd_una) &&
		!after(tp->snd_sml, tp->snd_nxt);
}

/* Update snd_sml if this skb is under mss
 * Note that a TSO packet might end with a sub-mss segment
 * The test is really :
 * if ((skb->len % mss) != 0)
 *        tp->snd_sml = TCP_SKB_CB(skb)->end_seq;
 * But we can avoid doing the divide again given we already have
 *  skb_pcount = skb->len / mss_now
 */
static void tcp_minshall_update(struct tcp_sock *tp, unsigned int mss_now,
				const struct sk_buff *skb)
{
	if (skb->len < tcp_skb_pcount(skb) * mss_now)
		tp->snd_sml = TCP_SKB_CB(skb)->end_seq;
}

/* Return false, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized. (provided by caller in %partial bool)
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_CORK is not set, and TCP_NODELAY is set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
static bool tcp_nagle_check(bool partial, const struct tcp_sock *tp,
			    int nonagle)
{
	return partial &&
		((nonagle & TCP_NAGLE_CORK) ||
		 (!nonagle && tp->packets_out && tcp_minshall_check(tp)));
}

/* Return how many segs we'd like on a TSO packet,
 * to send one TSO packet per ms
 */
static u32 tcp_tso_autosize(const struct sock *sk, unsigned int mss_now,
			    int min_tso_segs)
{
	u32 bytes, segs;

	bytes = min_t(unsigned long,
		      sk->sk_pacing_rate >> sk->sk_pacing_shift,
		      sk->sk_gso_max_size - 1 - MAX_TCP_HEADER);

	/* Goal is to send at least one packet per ms,
	 * not one big TSO packet every 100 ms.
	 * This preserves ACK clocking and is consistent
	 * with tcp_tso_should_defer() heuristic.
	 */
	segs = max_t(u32, bytes / mss_now, min_tso_segs);

	return segs;
}

/* Return the number of segments we want in the skb we are transmitting.
 * See if congestion control module wants to decide; otherwise, autosize.
 */
static u32 tcp_tso_segs(struct sock *sk, unsigned int mss_now)
{
	const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;
	u32 min_tso, tso_segs;

	min_tso = ca_ops->min_tso_segs ?
			ca_ops->min_tso_segs(sk) :
			sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs;

	tso_segs = tcp_tso_autosize(sk, mss_now, min_tso);
	return min_t(u32, tso_segs, sk->sk_gso_max_segs);
}

/* 
 * 该函数综合skb中数据长度、发送窗口允许发送数据量、拥塞窗口允许发送数据量，
 * 计算本次允许当前skb发送的数据量，以字节为单位。
 *
 * 有下面这些情况：
 * 1. 最后一个skb、拥塞窗口受限-----返回拥塞窗口允许发送的数据量；
 * 2. 最后一个skb、拥塞窗口不受限-----返回min(发送窗口允许的数据量，实际要发送的数据量skb->len)；
 * 3. 不是最后一个skb、拥塞窗口受限-----返回拥塞窗口允许发送的数据量，
 * 	这种情况返回的允许值可能会大于skb中要发送的数据量。因为可能是这样的关系skb->len < cwnd_len <= window.
 * 4. 不是最后一个skb、拥塞窗口不受限-----返回min(发送窗口允许的数据量，实际要发送的数据量skb->len)。
 */
/* Returns the portion of skb which can be sent right away */
static unsigned int tcp_mss_split_point(const struct sock *sk,
					const struct sk_buff *skb,
					unsigned int mss_now,
					unsigned int max_segs,
					int nonagle)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 partial, needed, window, max_len;

	/* window为发送窗口允许当前skb发送的最大字节数（可能会超过skb->len) */
	window = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

	/* tso允许的最大发送量 */
	max_len = mss_now * max_segs;

	if (likely(max_len <= window && skb != tcp_write_queue_tail(sk)))
		return max_len;

	needed = min(skb->len, window);

	if (max_len <= needed)
		return max_len;

	partial = needed % mss_now;
	/* If last segment is not a full MSS, check if Nagle rules allow us
	 * to include this last segment in this skb.
	 * Otherwise, we'll split the skb at last MSS boundary
	 */
	if (tcp_nagle_check(partial != 0, tp, nonagle))
		return needed - partial;

	return needed;
}


/*
 * 查看当前网络中还在传输的报文（即飞行报文）数量是否超过了拥塞窗口的限制。
 */
/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int tcp_cwnd_test(const struct tcp_sock *tp,
					 const struct sk_buff *skb)
{
	u32 in_flight, cwnd, halfcwnd;

	/* 如果是FIN段，并且只有一个段（FIN可能会携带很多数据），那么总是可以发送的，并不会受到拥塞窗口限制。 */
	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
	    tcp_skb_pcount(skb) == 1)
		return 1;

	/* 估算当前还在网络中传输的tcp段的数目。 */
	in_flight = tcp_packets_in_flight(tp);

	/* 检查是否还有拥塞窗口可用，单位时tcp段。 */
	cwnd = tp->snd_cwnd;
	if (in_flight >= cwnd)
		return 0;

	/* For better scheduling, ensure we have at least
	 * 2 GSO packets in flight.
	 */
	halfcwnd = max(cwnd >> 1, 1U);
	return min(halfcwnd, cwnd - in_flight);
}

/* Initialize TSO state of a skb.
 * This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
 /* 该函数会设置gso_size和分段个数gso_segs，其中gso_size为mss值。
  * 这两个参数用于告诉硬件或者软件gso做segment时使用，需要拆分成的数据包个数和分片长度。
  */
static int tcp_init_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	int tso_segs = tcp_skb_pcount(skb);

	/*
	 * cond1: tso_segs为0，表示skb的gso信息还没有被初始化过。
	 * cond2: MSS发生了改变，需要重新计算GSO信息。
	 */
	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		tcp_set_skb_tso_segs(skb, mss_now);
		tso_segs = tcp_skb_pcount(skb);
	}

	/* 返回需要分割的段数 */
	return tso_segs;
}


/* Return true if the Nagle test allows this packet to be
 * sent now.
 */
/*
 * TCP Nagle避免发送大量的小包（进行阻塞小包，聚合成大包），减少传输次数，但会导致延迟。
 * https://blog.csdn.net/quality_C/article/details/122830119
 * 再次谈谈TCP的Nagle算法与TCP_CORK选项
 * https://baus.net/on-tcp_cork/
 * 
 * Nagle算法的初衷：避免发送大量的小包，防止小包泛滥于网络， 理想情况下，对于一个TCP连接而言，
 *	网络上每次只能一个小包存在。它更多的是端到端意义上的优化。
 * CORK算法的初衷：提高网络利用率， 理想情况下，完全避免发送小包，仅仅发送满包以及不得不发的小包。
 */
static inline bool tcp_nagle_test(const struct tcp_sock *tp, const struct sk_buff *skb,
				  unsigned int cur_mss, int nonagle)
{
	/* Nagle rule does not apply to frames, which sit in the middle of the
	 * write_queue (they have no chances to get new data).
	 *
	 * This is implemented in the callers, where they modify the 'nonagle'
	 * argument based upon the location of SKB in the send queue.
	 */
	if (nonagle & TCP_NAGLE_PUSH)
		return true;

	/* Don't use the nagle rule for urgent data (or for the final FIN). */
	if (tcp_urg_mode(tp) || (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN))
		return true;

	if (!tcp_nagle_check(skb->len < cur_mss, tp, nonagle))
		return true;

	return false;
}

/*
 * 判断当前发送窗口是否至少允许发送一个段，如果允许，返回1，否则返回0。
 * 如果skb的大小超过了一个MSS，那么只要允许发送一个MSS，就返回1；
 * 如果skb的大小小于一个MSS，那么只要允许发送所需的数据量，就会返回1。
 */
/* Does at least the first segment of SKB fit into the send window? */
static bool tcp_snd_wnd_test(const struct tcp_sock *tp,
			     const struct sk_buff *skb,
			     unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;

	/* 如果skb中数据超过了一个mss，则调整至发送一个mss的长度。 */
	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

	/* 检查该段是否在发送窗口内 */
	return !after(end_seq, tcp_wnd_end(tp));
}

/* Trim TSO SKB to LEN bytes, put the remaining data into a new packet
 * which is put after SKB on the list.  It is very much like
 * tcp_fragment() except that it may make several kinds of assumptions
 * in order to speed up the splitting operation.  In particular, we
 * know that all the data is in scatter-gather pages, and that the
 * packet has never been sent out before (and thus is not cloned).
 */
static int tso_fragment(struct sock *sk, enum tcp_queue tcp_queue,
			struct sk_buff *skb, unsigned int len,
			unsigned int mss_now, gfp_t gfp)
{
	struct sk_buff *buff;

	/* 新skb的数据长度为剩余部分。 */
	int nlen = skb->len - len;
	u8 flags;

	/* 如果skb的线性区有数据，就进行tcp_fragment处理。
	 * 一旦开启TSO时，tcp_sendmsg()在组织skb时，实际上时不会往线性区存放数据的，具体见 select_size()
	 */
	/* All of a TSO frame must be composed of paged data.  */
	if (skb->len != skb->data_len)
		return tcp_fragment(sk, tcp_queue, skb, len, mss_now, gfp);

	/* 如果skb只有非线性区，则用tso分片。分配一个新的skb，线性区没有数据。 */
	buff = sk_stream_alloc_skb(sk, 0, gfp, true);
	if (unlikely(!buff))
		return -ENOMEM;

	/* 更改内存记账 */
	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* 设置新分配的skb的序号信息 */
	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* 新分配的skb的 tcp flags */
	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;

	/* This packet was never sent out yet, so no SACK bits. */
	TCP_SKB_CB(buff)->sacked = 0;

	tcp_skb_fragment_eor(skb, buff);

	buff->ip_summed = CHECKSUM_PARTIAL;

	/* 拆分skb的SG区域指针关系 */
	skb_split(skb, buff, len);
	tcp_fragment_tstamp(skb, buff);

	/* 设置老的skb的TSO信息 */
	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, mss_now);
	tcp_set_skb_tso_segs(buff, mss_now);

	/* 将新的skb插入到发送队列中。 */
	/* Link BUFF into the send queue. */
	__skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk, tcp_queue);

	return 0;
}

/* Try to defer sending, if possible, in order to minimize the amount
 * of TSO splitting we do.  View it as a kind of TSO Nagle test.
 *
 * This algorithm is from John Heffner.
 */
 /*
 * 1. 在段中有FIN标志
 * 2. 不处于open拥塞状态
 * 3. TSO段延时超过2个时钟滴答
 * 4. 拥塞窗口和发送窗口的最小值大于64K或三倍的当前有效MSS，
 * 在这些情况下会立即发送，而其他情况下会延时发送，这样主要是为了减少软GSO分段的次数，以提高性能。
 */
static bool tcp_tso_should_defer(struct sock *sk, struct sk_buff *skb,
				 bool *is_cwnd_limited,
				 bool *is_rwnd_limited,
				 u32 max_segs)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 send_win, cong_win, limit, in_flight;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *head;
	int win_divisor;
	s64 delta;

	if (icsk->icsk_ca_state >= TCP_CA_Recovery)
		goto send_now;

	/* Avoid bursty behavior by allowing defer
	 * only if the last write was recent (1 ms).
	 * Note that tp->tcp_wstamp_ns can be in the future if we have
	 * packets waiting in a qdisc or device for EDT delivery.
	 */
	delta = tp->tcp_clock_cache - tp->tcp_wstamp_ns - NSEC_PER_MSEC;
	if (delta > 0)
		goto send_now;

	in_flight = tcp_packets_in_flight(tp);

	BUG_ON(tcp_skb_pcount(skb) <= 1);
	BUG_ON(tp->snd_cwnd <= in_flight);

	send_win = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

	/* From in_flight test above, we know that cwnd > in_flight.  */
	cong_win = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	limit = min(send_win, cong_win);

	/* If a full-sized TSO skb can be sent, do it. */
	if (limit >= max_segs * tp->mss_cache)
		goto send_now;

	/* Middle in queue won't get any more data, full sendable already? */
	if ((skb != tcp_write_queue_tail(sk)) && (limit >= skb->len))
		goto send_now;

	win_divisor = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_tso_win_divisor);
	if (win_divisor) {
		u32 chunk = min(tp->snd_wnd, tp->snd_cwnd * tp->mss_cache);

		/* If at least some fraction of a window is available,
		 * just use it.
		 */
		chunk /= win_divisor;
		if (limit >= chunk)
			goto send_now;
	} else {
		/* Different approach, try not to defer past a single
		 * ACK.  Receiver should ACK every other full sized
		 * frame, so if we have space for more than 3 frames
		 * then send now.
		 */
		if (limit > tcp_max_tso_deferred_mss(tp) * tp->mss_cache)
			goto send_now;
	}

	/* TODO : use tsorted_sent_queue ? */
	head = tcp_rtx_queue_head(sk);
	if (!head)
		goto send_now;
	delta = tp->tcp_clock_cache - head->tstamp;
	/* If next ACK is likely to come too late (half srtt), do not defer */
	if ((s64)(delta - (u64)NSEC_PER_USEC * (tp->srtt_us >> 4)) < 0)
		goto send_now;

	/* 这里表示 如果判断到拥塞窗口小于发送窗口，并且拥塞窗口小于等于报文长度时，意味着
	 * 当前报文不能被发送，于是就设置拥塞窗口限制标志 is_cwnd_limited。（表示说受到拥塞
	 * 窗口的限制）
	 */
	/* Ok, it looks like it is advisable to defer.
	 * Three cases are tracked :
	 * 1) We are cwnd-limited
	 * 2) We are rwnd-limited
	 * 3) We are application limited.
	 */
	if (cong_win < send_win) {
		if (cong_win <= skb->len) {
			*is_cwnd_limited = true; //受到拥塞窗口的限制
			return true;
		}
	} else {
		if (send_win <= skb->len) {
			*is_rwnd_limited = true; //受到当前发送窗口限制
			return true;
		}
	}

	/* If this packet won't get more data, do not wait. */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) ||
	    TCP_SKB_CB(skb)->eor)
		goto send_now;

	return true;

send_now:
	return false;
}

static inline void tcp_mtu_check_reprobe(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	u32 interval;
	s32 delta;

	interval = net->ipv4.sysctl_tcp_probe_interval;
	delta = tcp_jiffies32 - icsk->icsk_mtup.probe_timestamp;
	if (unlikely(delta >= interval * HZ)) {
		int mss = tcp_current_mss(sk);

		/* Update current search range */
		icsk->icsk_mtup.probe_size = 0;
		icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp +
			sizeof(struct tcphdr) +
			icsk->icsk_af_ops->net_header_len;
		icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);

		/* Update probe time stamp */
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
	}
}

static bool tcp_can_coalesce_send_queue_head(struct sock *sk, int len)
{
	struct sk_buff *skb, *next;

	skb = tcp_send_head(sk);
	tcp_for_write_queue_from_safe(skb, next, sk) {
		if (len <= skb->len)
			break;

		if (unlikely(TCP_SKB_CB(skb)->eor))
			return false;

		len -= skb->len;
	}

	return true;
}

/* Create a new MTU probe if we are ready.
 * MTU probe is regularly attempting to increase the path MTU by
 * deliberately sending larger packets.  This discovers routing
 * changes resulting in larger path MTUs.
 *
 * Returns 0 if we should wait to probe (no cwnd available),
 *         1 if a probe was sent,
 *         -1 otherwise
 */
/*
 * 作用：用于及时增大MSS，从而可以发送更大的报文。
 * 与tcp_mtu_probing()--使用MTU Probe来避免PMTU变小而导致发送失败的方法。
 * 共同完成MTU的调整。
 *
 * TCP MTU Probe的原理已经分析完毕，做一个简单的总结：当PMTU变小时，MTU Probe通过丢包发现这种情况，
 * 从而不断的降低当前MSS值，达到成功发送的目的。当PMTU变大时，利用非PUSH报文，尝试发送更大的TCP数据报文。
 * 如果成功，则进一步提高探测上限，从而逐步探测到该PMTU可传送的最大TCP报文。
 *
 * 当skb数据包不需要push的时候，则可以进行MTU探测。TCP的PUSH标志的含义是尽快将数据包发送出去（对于发送端）。
 * 反过来，没有PUSH标志的时候，则表示数据包不是特别“紧急”。这时候就可以做点额外的工作，即进行MTU探测。
 */
static int tcp_mtu_probe(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb, *nskb, *next;
	struct net *net = sock_net(sk);
	int probe_size;
	int size_needed;
	int copy, len;
	int mss_now;
	int interval;

	/* 合法性检查，即判定哪些情况不合适做MTU探测。 */
	/* Not currently probing/verifying,
	 * not in recovery,
	 * have enough cwnd, and
	 * not SACKing (the variable headers throw things off)
	 */
	if (likely(!icsk->icsk_mtup.enabled ||
		   icsk->icsk_mtup.probe_size ||
		   inet_csk(sk)->icsk_ca_state != TCP_CA_Open ||
		   tp->snd_cwnd < 11 ||
		   tp->rx_opt.num_sacks || tp->rx_opt.dsack))
		return -1;

	/* 每次使用上限"searchi_high"和下限"search_low"的中间值作为探测报文的大小。 */
	/* Use binary search for probe_size between tcp_mss_base,
	 * and current mss_clamp. if (search_high - search_low)
	 * smaller than a threshold, backoff from probing.
	 */
	mss_now = tcp_current_mss(sk);
	probe_size = tcp_mtu_to_mss(sk, (icsk->icsk_mtup.search_high +
				    icsk->icsk_mtup.search_low) >> 1);
	size_needed = probe_size + (tp->reordering + 1) * tp->mss_cache;
	interval = icsk->icsk_mtup.search_high - icsk->icsk_mtup.search_low;
	/* When misfortune happens, we are reprobing actively,
	 * and then reprobe timer has expired. We stick with current
	 * probing process by not resetting search range to its orignal.
	 */
	if (probe_size > tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_high) ||
		interval < net->ipv4.sysctl_tcp_probe_threshold) {
		/* Check whether enough time has elaplased for
		 * another round of probing.
		 */
		tcp_mtu_check_reprobe(sk);
		return -1;
	}

	/* 发送缓存中是否有足够的数据（TCP探测报文不可能"伪造"数据） */
	/* Have enough data in the send queue to probe? */
	if (tp->write_seq - tp->snd_nxt < size_needed)
		return -1;

	/* 发送窗口是否有足够的大小 */
	if (tp->snd_wnd < size_needed)
		return -1;
	if (after(tp->snd_nxt + size_needed, tcp_wnd_end(tp)))
		return 0;

	/* Do we need to wait to drain cwnd? With none in flight, don't stall */
	if (tcp_packets_in_flight(tp) + 2 > tp->snd_cwnd) {
		if (!tcp_packets_in_flight(tp))
			return -1;
		else
			return 0;
	}

	if (!tcp_can_coalesce_send_queue_head(sk, probe_size))
		return -1;

	/* 构造数据报文并发送 */
	/* We're allowed to probe.  Build it now. */
	nskb = sk_stream_alloc_skb(sk, probe_size, GFP_ATOMIC, false);
	if (!nskb)
		return -1;
	sk->sk_wmem_queued += nskb->truesize;
	sk_mem_charge(sk, nskb->truesize);

	skb = tcp_send_head(sk);

	TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(skb)->seq;
	TCP_SKB_CB(nskb)->end_seq = TCP_SKB_CB(skb)->seq + probe_size;
	TCP_SKB_CB(nskb)->tcp_flags = TCPHDR_ACK;
	TCP_SKB_CB(nskb)->sacked = 0;
	nskb->csum = 0;
	nskb->ip_summed = CHECKSUM_PARTIAL;

	tcp_insert_write_queue_before(nskb, skb, sk);
	tcp_highest_sack_replace(sk, skb, nskb);

	len = 0;
	tcp_for_write_queue_from_safe(skb, next, sk) {
		copy = min_t(int, skb->len, probe_size - len);
		skb_copy_bits(skb, 0, skb_put(nskb, copy), copy);

		if (skb->len <= copy) {
			/* We've eaten all the data from this skb.
			 * Throw it away. */
			TCP_SKB_CB(nskb)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags;
			/* If this is the last SKB we copy and eor is set
			 * we need to propagate it to the new skb.
			 */
			TCP_SKB_CB(nskb)->eor = TCP_SKB_CB(skb)->eor;
			tcp_unlink_write_queue(skb, sk);
			sk_wmem_free_skb(sk, skb);
		} else {
			TCP_SKB_CB(nskb)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags &
						   ~(TCPHDR_FIN|TCPHDR_PSH);
			if (!skb_shinfo(skb)->nr_frags) {
				skb_pull(skb, copy);
			} else {
				__pskb_trim_head(skb, copy);
				tcp_set_skb_tso_segs(skb, mss_now);
			}
			TCP_SKB_CB(skb)->seq += copy;
		}

		len += copy;

		if (len >= probe_size)
			break;
	}
	tcp_init_tso_segs(nskb, nskb->len);

	/* 这里数据包发送出去后，至少进行了探测。如果探测失败，即该TCP报文由于丢失了怎么办？ */
	/* We're ready to send.  If this fails, the probe will
	 * be resegmented into mss-sized pieces by tcp_write_xmit().
	 */
	if (!tcp_transmit_skb(sk, nskb, 1, GFP_ATOMIC)) {
		/* Decrement cwnd here because we are sending
		 * effectively two packets. */
		tp->snd_cwnd--;
		tcp_event_new_data_sent(sk, nskb);

		icsk->icsk_mtup.probe_size = tcp_mss_to_mtu(sk, nskb->len);
		tp->mtu_probe.probe_seq_start = TCP_SKB_CB(nskb)->seq;
		tp->mtu_probe.probe_seq_end = TCP_SKB_CB(nskb)->end_seq;

		return 1;
	}

	return -1;
}

/* 如果返回true，表明pacing功能正在工作，需要暂停发送数据。 */
static bool tcp_pacing_check(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* 该sock是否使能了pacing功能 */
	if (!tcp_needs_internal_pacing(sk))
		return false;

	/* 已经到了发送下一个packet的时间，即应该立即发送skb了。 */
	if (tp->tcp_wstamp_ns <= tp->tcp_clock_cache)
		return false;

	/* pacing定时器已经在工作了 */
	if (!hrtimer_is_queued(&tp->pacing_timer)) {
		hrtimer_start(&tp->pacing_timer,
			      ns_to_ktime(tp->tcp_wstamp_ns),
			      HRTIMER_MODE_ABS_PINNED_SOFT);
		sock_hold(sk);
	}
	return true;
}

/* TCP Small Queues :
 * Control number of packets in qdisc/devices to two packets / or ~1 ms.
 * (These limits are doubled for retransmits)
 * This allows for :
 *  - better RTT estimation and ACK scheduling
 *  - faster recovery
 *  - high rates
 * Alas, some drivers / subsystems require a fair amount
 * of queued bytes to ensure line rate.
 * One example is wifi aggregation (802.11 AMPDU)
 */

/* https://blog.csdn.net/u011130578/article/details/44645643
 * TCP Small Queues :
 * 控制进入到 qdisc/devices 中的包的数目。
 * 该机制带来了以下的好处 :
 * 1. 更好地进行RTT估算和ACK调度
 * 2. 更快速地恢复
 * 3. 高数据速率
 *
 * TSQ工作原理：
 * 1. 设置net.ipv4.tcp_limit_output_bytes内核选项来指定sysctl_tcp_limit_output_bytes的值；
 * 2. 在TCP发包时，系统调用使用tcp_write_xmit() 来调用tcp_transmit_skb() 发送skb时，
 *	会设置使得skb在释放时会调用tcp_wfree函数，并增加sk->sk_wmem_alloc的值。
 * 3. 当sk->sk_wmem_alloc达到限制时，即底层队列允许当前TCP连接放入的数据的总大小达到限制时（此时底层队列未必会满），
 *	tcp_write_xmit() 就不允许继续发送skb，而是设置标记使得在由tcp_transmit_skb() 
 *	发送的任意skb在释放时会调用tcp_wfree()，将发送skb的任务放入TSQ tasklet中，然后系统调用返回。
 * 4. 此后由TSQ tasklet在软中断上下文中驱动tcp_write_xmit()发送skb，但放入底层队列中的skb的总大小仍然不能超过限制。
 *	一旦底层队列中的skb被陆续释放使得sk->sk_wmem_alloc的值减小到低于限制时，
 *	TSQ tasklet就可以即时地发送skb到队列中。
 *	这样既可以通过限制一个TCP连接向底层队列放入skb的速度来缓解队列拥堵导致的丢包问题，
 *	也能够在队列空间宽松时及时地发送数据，从而减小了TCP延时。
 * 
 * tcp_small_queue_check() 在TCP发送路径的tcp_write_xmit() 函数和tcp_xmit_retransmit_queue() 函数中都有调用。
 */
static bool tcp_small_queue_check(struct sock *sk, const struct sk_buff *skb,
				  unsigned int factor)
{
	unsigned long limit;

	/* 取以下两者之间的较大值：
	 * 1）当前发送的数据报文skb结构所占用空间的两倍值（2*skb->truesize）；
	 * 2）以及当前大约每毫秒的流量值（其通过sk_pacing_rate计算而来，内核将sk_pacing_shift变量定义为10，
	 * 将当前每秒钟的流量（sk_pacing_rate）除以2的10次方，得到大约1毫秒的流量值）。*/
	limit = max_t(unsigned long,
		      2 * skb->truesize,
		      sk->sk_pacing_rate >> sk->sk_pacing_shift);

	/* 其次，如果没有使能socket的pacing功能：
	 * 则，如果此结果值大于 sysctl_tcp_limit_output_bytes（默认为1M）限定的值，
	 * 使用tcp_limit_output_bytes作为限定值。
	 */
	if (sk->sk_pacing_status == SK_PACING_NONE)
		limit = min_t(unsigned long, limit,
			      sock_net(sk)->ipv4.sysctl_tcp_limit_output_bytes);

	/* 最后，如果是重传报文，即factor等于1，将最终的判定值增大一倍。 */
	limit <<= factor;

	/* 需要发送的buffer量大于了pacing限制值，则暂停发送到qdisc或netdev，需要等到TSQ的软中断去发送。 tcp_tsq_handler()
	 * 
	 * 如果sk_wmem_alloc大于limit，说明已经发送了太多的数据在Qdisc或者设备队列中，
	 * 但是如果重传队列为空，此次发送还是允许进行。否则，返回true，禁止发送操作。
	 * 在此之前，设置sk_tsp_flags的标志位TSQ_THROTTLED，表明是由于TSQ检查结果导致的不能发送。
	 * 另外，有可能在此函数设置TSQ_THROTTLED标志之前，发生了TX中断，进行了skb释放操作，
	 * 导致了sk_wmem_alloc的递减，所以，在返回前再次判断sk_wmem_alloc是否超过限值limit。
	 */
	if (refcount_read(&sk->sk_wmem_alloc) > limit) {
		/* Always send skb if rtx queue is empty.
		 * No need to wait for TX completion to call us back,
		 * after softirq/tasklet schedule.
		 * This helps when TX completions are delayed too much.
		 */
		if (tcp_rtx_queue_empty(sk))
			return false;

		/* 设置该sock为TSQ，即tcp_wfree() 才会将socket放入到TSQ队列中，等待tasklet发送。*/
		set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);

		/* It is possible TX completion already happened
		 * before we set TSQ_THROTTLED, so we must
		 * test again the condition.
		 */
		smp_mb__after_atomic();
		if (refcount_read(&sk->sk_wmem_alloc) > limit)
			return true;
	}
	return false;
}

/*
 * 该函数完成最后的计时统计：
 * 用当前时间减去计时器开始时间 chrono_start，将所得时长保存到对应的以类型值为索引的 chrono_stat数组中。
 * 然后，记录当前时间值到 chrono_start，开始新的类型计时。
 */
static void tcp_chrono_set(struct tcp_sock *tp, const enum tcp_chrono new)
{
	const u32 now = tcp_jiffies32;
	enum tcp_chrono old = tp->chrono_type;

	if (old > TCP_CHRONO_UNSPEC)
		tp->chrono_stat[old - 1] += now - tp->chrono_start;
	tp->chrono_start = now;
	tp->chrono_type = new;
}

/*
 * 计时开始函数：
 * 三种计时器类型值越大，优先级越高，即 TCP_CHRONO_SNDBUF_LIMITED 类型计时器优先级最高。
 * 所以，当开启 TCP_CHRONO_SNDBUF_LIMITED 计时器时，需要停止其他类型的计时器。
 */
void tcp_chrono_start(struct sock *sk, const enum tcp_chrono type)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* If there are multiple conditions worthy of tracking in a
	 * chronograph then the highest priority enum takes precedence
	 * over the other conditions. So that if something "more interesting"
	 * starts happening, stop the previous chrono and start a new one.
	 */
	if (type > tp->chrono_type)
		tcp_chrono_set(tp, type);
}

/*
 * 计时器停止函数：
 * 需要注意在停止类型 TCP_CHRONO_RWND_LIMITED 或者 TCP_CHRONO_SNDBUF_LIMITED 的计时器时，
 * 同时会打开 TCP_CHRONO_BUSY 计时器类型。
 */
void tcp_chrono_stop(struct sock *sk, const enum tcp_chrono type)
{
	struct tcp_sock *tp = tcp_sk(sk);


	/* There are multiple conditions worthy of tracking in a
	 * chronograph, so that the highest priority enum takes
	 * precedence over the other conditions (see tcp_chrono_start).
	 * If a condition stops, we only stop chrono tracking if
	 * it's the "most interesting" or current chrono we are
	 * tracking and starts busy chrono if we have pending data.
	 */
	if (tcp_rtx_and_write_queues_empty(sk))
		tcp_chrono_set(tp, TCP_CHRONO_UNSPEC);
	else if (type == tp->chrono_type)
		tcp_chrono_set(tp, TCP_CHRONO_BUSY);
}

/* This routine writes packets to the network.  It advances the
 * send_head.  This happens as incoming acks open up the remote
 * window for us.
 *
 * LARGESEND note: !tcp_urg_mode is overkill, only frames between
 * snd_up-64k-mss .. snd_up cannot be large. However, taking into
 * account rare use of URG, this is not a big flaw.
 *
 * Send at most one packet when push_one > 0. Temporarily ignore
 * cwnd limit to force at most one packet out when push_one == 2.

 * Returns true, if no segments are in flight and we have queued segments,
 * but cannot send anything now because of SWS or another problem.
 */
/*
 * 将socket的发送队列上的skb发送出去，0表示发送成功，过程如下：
 * 1. 检查拥塞窗口大小
 * 2. 检查当前报文是否完全处于发送窗口内
 * 3. 检查报文是否使用nagle算法发送
 * 4. 通过以上检查后的skb发送出去
 * 5. 循环检查发送队列上所有未发送的skb
 * 
 * 最后调用：tcp_transmit_skb() 进行发送。
 *
 * 注意：
 * 	可能TSQ或者pacing的限制导致暂定发送，然后，TSO tasklet或者pacing timer到期后，继续发送数据。
 */
/*
 * http://sunjiangang.blog.chinaunix.net/uid-9543173-id-3543419.html 
 */
static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;
	bool is_cwnd_limited = false, is_rwnd_limited = false;
	u32 max_segs;

	/* 该变量用于统计发送的包的数量，初始化为 0。*/
	sent_pkts = 0;

	/* 即在每次发送skb时，就需要更新tcp socket的 tcp_clock_cache 时间戳。*/
	tcp_mstamp_refresh(tp);

	/* 不需要立即发送，linux 这里会做mtu探测工作。*/
	if (!push_one) {

		/* 进行MTU探测，用于及时增大MSS, 从而可以发送更大的报文。 */
		/* Do MTU probing. */
		result = tcp_mtu_probe(sk);
		if (!result) {
			return false;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}

	/* 获取一个skb的最大的tso分段数量 */
	max_segs = tcp_tso_segs(sk, mss_now);

	/* 不断循环发送队列数据 - 从socket的 sk_write_queue 中。 */
	while ((skb = tcp_send_head(sk))) {
		unsigned int limit;

		/* 如果需要热迁移时： */
		if (unlikely(tp->repair) && tp->repair_queue == TCP_SEND_QUEUE) {
			/* "skb_mstamp_ns" is used as a start point for the retransmit timer */
			skb->skb_mstamp_ns = tp->tcp_wstamp_ns = tp->tcp_clock_cache;
			list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);

			/* 
			 * 计算本skb将会被分割成几个TSO段传输( skb->len / mss)
			 * 重新设置 tcp_gso_segs 和 tcp_gso_size。
			 */
			tcp_init_tso_segs(skb, mss_now);
			goto repair; /* Skip network transmission */
		}

		/* 不需要热迁移时：
		 */

		/* tcp的 pacing 正在工作，需要暂停发送packet到qdisc或者netdev中，
		 * 需要等到pacing定时器超时后，在定时器的handler tcp_pace_kick()中进行发送。
		 * 注意：需要看该socket是否有使能tcp pacing功能。
		 *
		 * 限速点1：由于pacing速率的限制。
		 */
		if (tcp_pacing_check(sk))
			break;

		/* 初始化tso分段相关：
		/* 设置TSO相关信息，包括GSO类型，GSO分段的大小等。这些信息是准备给GSO分段使用的。
		 * 如果网络设备不支持TSO，但又用了TSO功能，则报文在提交给网络设备前，需要进行软件分段，
		 * 即由软件实现TSO功能。即GSO。
		 */
		tso_segs = tcp_init_tso_segs(skb, mss_now);
		BUG_ON(!tso_segs);

		/* 获取当前可用的拥塞窗口大小：
		 * 如果为0，表示拥塞窗口已满，目前不能发送。
		 * 用拥塞窗口和正在网络上传输的包数目相比，如果拥塞窗口还大，
		 * 则返回拥塞窗口减掉正在网上传输的包数后剩下的大小。
		 * 目的：
		 *	判断正在传输的包数目是否超过了拥塞窗口，如果超过了，则不发送。
		 *
		 * 限速点2：由于cwnd的限制。
		 */
		cwnd_quota = tcp_cwnd_test(tp, skb);
		if (!cwnd_quota) {
			/* 强制发送一个包进行丢包探测 */
			if (push_one == 2)
				/* Force out a loss probe pkt. */
				cwnd_quota = 1;
			else
				/* 如果窗口大小为0，则无法发送任何东西。*/
				break; 
		}

		/* 检查tcp的数据段是否在发送窗口之内，如果是，则可以发送，否则，不能发送。
		 * 条件：至少要有一个发送窗口才能正常发送。
		 *
		 * 限速点3：滑动窗口检查，即是否在发送窗口内。
		 */
		if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now))) {
			is_rwnd_limited = true;
			break;
		}

		/*
		 * 限速点4：检查是否有nagle算法限制，或者 需要TSO的defer处理。
		 */
		/* 表示数据长度小于MSS，则是一个小包，不需要tso分段，需要继续检查是否启用nagle算法。 */
		if (tso_segs == 1) {
			/* 根据nagle算法，检查是否允许发送数据段 */
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;

		/* 表示需要tso分段, 则检查是否需要延迟发送。
		 * 检查是否可以延时发送，有很多条件判断。详细见函数。
		 * 目的是为了减少软GSO分段的次数，以提高实时性。
		 * 会对 is_cwnd_limited进行设置。
		 */
		} else { 
			if (!push_one &&
			    tcp_tso_should_defer(sk, skb, &is_cwnd_limited,
						 &is_rwnd_limited, max_segs))
				break;
		}

		/* 下面的逻辑是：
		 * 	不用推迟发送，即马上发送的处理。
		 */

		/* 在需要分段，并且非紧急模式的条件下，重新确定分段长度限制 - 通过mss_now计算limit的值。
		 * 以发送窗口和拥塞窗口的最小值作为分段段长。
		 * 注意：
		 * 	前面 tcp_init_tso_segs() 中会设置skb的gso信息，并且，后面会调用tso_fragment()进行“tcp分段”。
		 * 	而分段的条件是 skb->len > limit。
		 * 	这里的关键就是limit的值，我们看到在tso_segs > 1时，也就是开启gso的时候，
		 * 	limit的值是由tcp_mss_split_point() 得到的，也就是min(skb->len, window)，
		 * 	即发送窗口允许的最大值。在没有开启gso时limit就是当前的mss。
		 */
		/* limit为本次分段的段长，初始化为当前MSS。 */
		limit = mss_now;
		if (tso_segs > 1 && !tcp_urg_mode(tp))
			/* 这里返回发送窗口和拥塞窗口允许发送的最大字节数 */
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    min_t(unsigned int,
							  cwnd_quota,
							  max_segs),
						    nonagle);

		/*
		 * 在tcp_write_xmit()中，如果skb中数据量过大，超过了发送窗口和拥塞窗口的限定，只允许发送skb的一部分，
		 * 那么就需要将skb拆分成两段，前半段长度为len，本次可以发送，后半段保存在新分配的skb中，
		 * 在发送队列sk_write_queue中将后半段插入到前半段的后面，这样可以保证数据的顺序发送
		 *
		 * 前面处理中： 根据不同条件检查，可能需要对SKB中的报文进行分段处理，分段的报文包括两种：
		 * 1. 普通的用MSS分段的报文
		 * 2. TSO分段的报文。
		 * 
		 * 能否发送报文主要取决于两个条件：
		 * 1. 1是报文需完全在发送窗口中，2是拥塞窗口未满。
		 *	第一种情况：应该不会再分段了，因为在tcp_sendmsg()中创建报文的SKB时已经根据MSS处理了。
		 * 	第二种情况：一般情况下都会大于MSS，因为通过TSO分段的段有可能大于拥塞窗口的剩余空间，
		 *		如果是这样，就需要以发送窗口和拥塞窗口的最小值作为段长对报文再次分段。
		 */
		if (skb->len > limit &&
		    unlikely(tso_fragment(sk, TCP_FRAG_IN_WRITE_QUEUE,
					  skb, limit, mss_now, gfp)))
			break;

		/*
		 * Linux3.6 引入的新机制。在之前的Linux实现中，如果TCP的窗口很大，那么，
		 * 可能导致驱动队列中待发送的包的的数目超过队列缓存的大小，因而导致丢包。
		 * 为了解决该问题，Linux引入了TCP小队列机制。
		 *
		 * TCP Small Queues的目的是限制每个TCP连接在Qdisc和device队列中的skb数量，
		 * 以达到降低RTT（Round-Trip Time）和避免bufferbloat。
		 *
		 * https://blog.csdn.net/sinat_20184565/article/details/89341370
		 *
		 * 限速点5：TSQ的限制
		 */
		if (tcp_small_queue_check(sk, skb, 0))
			break;

		/* 真正地将数据包发送到ip层：
		 * 	构造TCP header等，最终调用ip_queue_xmit() 将数据发送到网络层。
		 * 	注意：
		 * 	这里clone_it传入的是1，因为 TCP发送方在接收方确认收到数据之前，始终在发送队列中
		 * 	保留一份SKB的备份。要实现这种备份，用克隆SKB的方法是最有效的。先创建一个纯数据
		 * 	区的TCP包，然后标识该SKB已被克隆，最后 TCP发送引擎用克隆的SKB来建立TCP和IPv4首部。
		 */
		if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))
			break;

repair:
		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		/* 发送成功了，则进行发送之后的数据更新，包括统计计数和复位重传定时器等。*/
		tcp_event_new_data_sent(sk, skb);

		
		/* 更新struct tcp_sock中的snd_sml字段。snd_sml表示最近发送的小包(小于MSS的段)的最后一个字节序号，
		 * 在发送成功后，如果报文小于MSS，即更新该字段，主要用来判断是否启动nagle算法。
		 */
		tcp_minshall_update(tp, mss_now, skb);

		/* 更新发送数据段数量 */
		sent_pkts += tcp_skb_pcount(skb);

		/* 只发送sk_write_queue中的一个skb，则跳出 */
		if (push_one)
			break;
	}

	/*
	 * 由于对端的接收窗口限制了本端的发送，则启动 TCP_CHRONO_RWND_LIMITED 计时器，否则，停止该计时器。
	 */
	if (is_rwnd_limited)
		tcp_chrono_start(sk, TCP_CHRONO_RWND_LIMITED);
	else
		tcp_chrono_stop(sk, TCP_CHRONO_RWND_LIMITED);


	/* 本次有数据发送，则对tcp拥塞窗口相关数据更新。 */
	if (likely(sent_pkts)) {
		/* 如果本连接处于CWR或者Recovery拥塞状态，需要增加prr的值。 */
		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += sent_pkts;

		/* 每次发送一个尾部丢失探测。 */
		/* Send one loss probe per tail loss episode. */
		if (push_one != 2)
			tcp_schedule_loss_probe(sk, false);

		/* 1. tcp_tso_should_defer() 的结果：
		 *	a. 判断到拥塞窗口小于发送窗口，并且，报文长度大于拥塞窗口；
		 *	b. 判断到拥塞窗口大于发送窗口，但是，报文长度大于发送窗口。
		 *	于是就设置拥塞窗口限制标志 is_cwnd_limited。（表示说受到拥塞窗口的限制）
		 *
		 * 2. 还在网络中packets数量大于等于拥塞窗口了，表示说 受到拥塞窗口限制了。
		 */
		is_cwnd_limited |= (tcp_packets_in_flight(tp) >= tp->snd_cwnd);

		/* 拥塞窗口校验 */
		tcp_cwnd_validate(sk, is_cwnd_limited);

		return false;
	}

	/* 如果本次没有数据发送，则根据已发送但未确认的报文数packets_out和sk_write_queue返回。
	 * 如果packets_out不为零且sk_write_queue为不为空，都视为有数据发出，因此，返回成功。
	 */
	return !tp->packets_out && !tcp_write_queue_empty(sk);
}

bool tcp_schedule_loss_probe(struct sock *sk, bool advancing_rto)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 timeout, rto_delta_us;
	int early_retrans;

	/* Don't do any loss probe on a Fast Open connection before 3WHS
	 * finishes.
	 */
	if (tp->fastopen_rsk)
		return false;

	early_retrans = sock_net(sk)->ipv4.sysctl_tcp_early_retrans;
	/* Schedule a loss probe in 2*RTT for SACK capable connections
	 * not in loss recovery, that are either limited by cwnd or application.
	 */
	if ((early_retrans != 3 && early_retrans != 4) ||
	    !tp->packets_out || !tcp_is_sack(tp) ||
	    (icsk->icsk_ca_state != TCP_CA_Open &&
	     icsk->icsk_ca_state != TCP_CA_CWR))
		return false;

	/* Probe timeout is 2*rtt. Add minimum RTO to account
	 * for delayed ack when there's one outstanding packet. If no RTT
	 * sample is available then probe after TCP_TIMEOUT_INIT.
	 */
	if (tp->srtt_us) {
		timeout = usecs_to_jiffies(tp->srtt_us >> 2);
		if (tp->packets_out == 1)
			timeout += TCP_RTO_MIN;
		else
			timeout += TCP_TIMEOUT_MIN;
	} else {
		timeout = TCP_TIMEOUT_INIT;
	}

	/* If the RTO formula yields an earlier time, then use that time. */
	rto_delta_us = advancing_rto ?
			jiffies_to_usecs(inet_csk(sk)->icsk_rto) :
			tcp_rto_delta_us(sk);  /* How far in future is RTO? */
	if (rto_delta_us > 0)
		timeout = min_t(u32, timeout, usecs_to_jiffies(rto_delta_us));

	tcp_reset_xmit_timer(sk, ICSK_TIME_LOSS_PROBE, timeout,
			     TCP_RTO_MAX, NULL);
	return true;
}

/* Thanks to skb fast clones, we can detect if a prior transmit of
 * a packet is still in a qdisc or driver queue.
 * In this case, there is very little point doing a retransmit !
 */
static bool skb_still_in_host_queue(const struct sock *sk,
				    const struct sk_buff *skb)
{
	if (unlikely(skb_fclone_busy(sk, skb))) {
		NET_INC_STATS(sock_net(sk),
			      LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES);
		return true;
	}
	return false;
}

/* When probe timeout (PTO) fires, try send a new segment if possible, else
 * retransmit the last segment.
 */
void tcp_send_loss_probe(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int pcount;
	int mss = tcp_current_mss(sk);

	skb = tcp_send_head(sk);
	if (skb && tcp_snd_wnd_test(tp, skb, mss)) {
		pcount = tp->packets_out;
		tcp_write_xmit(sk, mss, TCP_NAGLE_OFF, 2, GFP_ATOMIC);
		if (tp->packets_out > pcount)
			goto probe_sent;
		goto rearm_timer;
	}
	skb = skb_rb_last(&sk->tcp_rtx_queue);
	if (unlikely(!skb)) {
		WARN_ONCE(tp->packets_out,
			  "invalid inflight: %u state %u cwnd %u mss %d\n",
			  tp->packets_out, sk->sk_state, tp->snd_cwnd, mss);
		inet_csk(sk)->icsk_pending = 0;
		return;
	}

	/* At most one outstanding TLP retransmission. */
	if (tp->tlp_high_seq)
		goto rearm_timer;

	if (skb_still_in_host_queue(sk, skb))
		goto rearm_timer;

	pcount = tcp_skb_pcount(skb);
	if (WARN_ON(!pcount))
		goto rearm_timer;

	if ((pcount > 1) && (skb->len > (pcount - 1) * mss)) {
		if (unlikely(tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb,
					  (pcount - 1) * mss, mss,
					  GFP_ATOMIC)))
			goto rearm_timer;
		skb = skb_rb_next(skb);
	}

	if (WARN_ON(!skb || !tcp_skb_pcount(skb)))
		goto rearm_timer;

	if (__tcp_retransmit_skb(sk, skb, 1))
		goto rearm_timer;

	/* Record snd_nxt for loss detection. */
	tp->tlp_high_seq = tp->snd_nxt;

probe_sent:
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPLOSSPROBES);
	/* Reset s.t. tcp_rearm_rto will restart timer from now */
	inet_csk(sk)->icsk_pending = 0;
rearm_timer:
	tcp_rearm_rto(sk);
}

/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
 /* 判断socket状态，然后，对tcp_write_xmit进行简单封装。 */
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	 /* 如果此时连接已经关闭了，那么直接返回。 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

	/* 将剩余的部分发送出去。 */
	if (tcp_write_xmit(sk, cur_mss, nonagle, 0,
			   sk_gfp_mask(sk, GFP_ATOMIC)))
		tcp_check_probe_timer(sk); /* 如果发送失败，检查是否需要启动零窗口探测定时器。*/
}

/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
 /* 只发送socket发送队列中的一个包。 */
void tcp_push_one(struct sock *sk, unsigned int mss_now)
{
	struct sk_buff *skb = tcp_send_head(sk);

	BUG_ON(!skb || skb->len < mss_now);

	/* 继续往下传skb */
	tcp_write_xmit(sk, mss_now, TCP_NAGLE_PUSH, 1, sk->sk_allocation);
}

/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 *
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 *
 * BSD seems to make the following compromise:
 *
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
/*
 * __tcp_select_window(sk)来计算新的窗口大小。该函数会尝试增加窗口的大小，但是有两个限制条件：
 * 1. 窗口不能收缩 (RFC793)
 * 2. 每个 socket 所能使用的内存是有限制的
 */
u32 __tcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = icsk->icsk_ack.rcv_mss;
	int free_space = tcp_space(sk);
	int allowed_space = tcp_full_space(sk);
	int full_space = min_t(int, tp->window_clamp, allowed_space);
	int window;

	/* 如果 mss 超过了总共的空间大小，那么把 mss 限制在允许的空间范围内。 */
	if (unlikely(mss > full_space)) {
		mss = full_space;
		if (mss <= 0)
			return 0;
	}
	if (free_space < (full_space >> 1)) {
		/* 当空闲空间小于允许空间的一半时。 */
		icsk->icsk_ack.quick = 0;

		if (tcp_under_memory_pressure(sk))
			tp->rcv_ssthresh = min(tp->rcv_ssthresh,
					       4U * tp->advmss);

		/* free_space 有可能成为新的窗口的大小，因此，需要考虑
		 * 窗口扩展的影响。
		 */
		/* free_space might become our new window, make sure we don't
		 * increase it due to wscale.
		 */
		free_space = round_down(free_space, 1 << tp->rx_opt.rcv_wscale);

		/* 如果空闲空间小于 mss 的大小，或者低于最大允许空间的的 1/16，那么，
		 * 返回 0 窗口。否则， tcp_clamp_window() 会增长接收缓存到 tcp_rmem[2]。
		 * 新进入的数据会由于内醋限制而被丢弃。对于较大的窗口，单纯地探测 mss 的
		 * 大小以宣告 0 窗口有些太晚了（可能会超过限制）。
		 */

		/* if free space is less than mss estimate, or is below 1/16th
		 * of the maximum allowed, try to move to zero-window, else
		 * tcp_clamp_window() will grow rcv buf up to tcp_rmem[2], and
		 * new incoming data is dropped due to memory limits.
		 * With large window, mss test triggers way too late in order
		 * to announce zero window in time before rmem limit kicks in.
		 */
		if (free_space < (allowed_space >> 4) || free_space < mss)
			return 0;
	}

	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

	/* 这里处理一个例外情况，就是如果开启了窗口缩放，那么就没法对齐 mss 了。
	 * 所以就保持窗口是对齐 2 的幂的。
	 */
	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		window = ALIGN(window, (1 << tp->rx_opt.rcv_wscale));
	} else {
		window = tp->rcv_wnd;

		/* 如果内存条件允许，那么就把窗口设置为 mss 的整倍数。
		 * 或者如果 free_space > 当前窗口大小加上全部允许的空间的一半，
		 * 那么，就将窗口大小设置为 free_space
		 */
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		if (window <= free_space - mss || window > free_space)
			window = rounddown(free_space, mss);
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
	}

	return window;
}

void tcp_skb_collapse_tstamp(struct sk_buff *skb,
			     const struct sk_buff *next_skb)
{
	if (unlikely(tcp_has_tx_tstamp(next_skb))) {
		const struct skb_shared_info *next_shinfo =
			skb_shinfo(next_skb);
		struct skb_shared_info *shinfo = skb_shinfo(skb);

		shinfo->tx_flags |= next_shinfo->tx_flags & SKBTX_ANY_TSTAMP;
		shinfo->tskey = next_shinfo->tskey;
		TCP_SKB_CB(skb)->txstamp_ack |=
			TCP_SKB_CB(next_skb)->txstamp_ack;
	}
}

/* Collapses two adjacent SKB's during retransmission. */
static bool tcp_collapse_retrans(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = skb_rb_next(skb);
	int next_skb_size;

	next_skb_size = next_skb->len;

	BUG_ON(tcp_skb_pcount(skb) != 1 || tcp_skb_pcount(next_skb) != 1);

	if (next_skb_size) {
		if (next_skb_size <= skb_availroom(skb))
			skb_copy_bits(next_skb, 0, skb_put(skb, next_skb_size),
				      next_skb_size);
		else if (!skb_shift(skb, next_skb, next_skb_size))
			return false;
	}
	tcp_highest_sack_replace(sk, next_skb, skb);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

	/* Merge over control information. This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->tcp_flags |= TCP_SKB_CB(next_skb)->tcp_flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked & TCPCB_EVER_RETRANS;
	TCP_SKB_CB(skb)->eor = TCP_SKB_CB(next_skb)->eor;

	/* changed transmit queue under us so clear hints */
	tcp_clear_retrans_hints_partial(tp);
	if (next_skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = skb;

	tcp_adjust_pcount(sk, next_skb, tcp_skb_pcount(next_skb));

	tcp_skb_collapse_tstamp(skb, next_skb);

	tcp_rtx_queue_unlink_and_free(next_skb, sk);
	return true;
}

/* Check if coalescing SKBs is legal. */
static bool tcp_can_collapse(const struct sock *sk, const struct sk_buff *skb)
{
	if (tcp_skb_pcount(skb) > 1)
		return false;
	if (skb_cloned(skb))
		return false;
	/* Some heuristics for collapsing over SACK'd could be invented */
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		return false;

	return true;
}

/* Collapse packets in the retransmit queue to make to create
 * less packets on the wire. This is only done on retransmission.
 */
/*
 * 在TCP重传的时候，并没有限制TCP只能重传与初传完全相同的报文段大小，TCP允许执行重组包(repacketization)，
 * 发送一个更大的TCP报文段，进而增加性能。TCP在重传时候允许重组包同时提供了一种判别虚假重传的方法。
 * 在linux中参数/proc/sys/net/ipv4/tcp_retrans_collapse为非0值的时候打开重传重组包功能，为0的时候关闭重传重组包功能。
 */
static void tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *to,
				     int space)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = to, *tmp;
	bool first = true;

	if (!sock_net(sk)->ipv4.sysctl_tcp_retrans_collapse)
		return;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		return;

	skb_rbtree_walk_from_safe(skb, tmp) {
		if (!tcp_can_collapse(sk, skb))
			break;

		if (!tcp_skb_can_collapse_to(to))
			break;

		space -= skb->len;

		if (first) {
			first = false;
			continue;
		}

		if (space < 0)
			break;

		if (after(TCP_SKB_CB(skb)->end_seq, tcp_wnd_end(tp)))
			break;

		if (!tcp_collapse_retrans(sk, to))
			break;
	}
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
int __tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int cur_mss;
	int diff, len, err;


	/* Inconclusive MTU probe */
	if (icsk->icsk_mtup.probe_size)
		icsk->icsk_mtup.probe_size = 0;

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 */
	if (refcount_read(&sk->sk_wmem_alloc) >
	    min_t(u32, sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2),
		  sk->sk_sndbuf))
		return -EAGAIN;

	if (skb_still_in_host_queue(sk, skb))
		return -EBUSY;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (unlikely(before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))) {
			WARN_ON_ONCE(1);
			return -EINVAL;
		}
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp)) &&
	    TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;


	/* tcp 分段操作 fragment  */
	len = cur_mss * segs;
	if (skb->len > len) {
		if (tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb, len,
				 cur_mss, GFP_ATOMIC))
			return -ENOMEM; /* We'll try again later. */
	} else {
		if (skb_unclone(skb, GFP_ATOMIC))
			return -ENOMEM;

		diff = tcp_skb_pcount(skb);
		tcp_set_skb_tso_segs(skb, cur_mss);
		diff -= tcp_skb_pcount(skb);
		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
		if (skb->len < cur_mss)
			tcp_retrans_try_collapse(sk, skb, cur_mss);
	}

	/* RFC3168, section 6.1.1.1. ECN fallback */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN_ECN) == TCPHDR_SYN_ECN)
		tcp_ecn_clear_syn(sk, skb);

	/* Update global and local TCP statistics. */
	segs = tcp_skb_pcount(skb);
	TCP_ADD_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS, segs);
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
	tp->total_retrans += segs;
	tp->bytes_retrans += skb->len;

	/* make sure skb->data is aligned on arches that require it
	 * and check if ack-trimming & collapsing extended the headroom
	 * beyond what csum_start can cover.
	 */
	if (unlikely((NET_IP_ALIGN && ((unsigned long)skb->data & 3)) ||
		     skb_headroom(skb) >= 0xFFFF)) {
		struct sk_buff *nskb;

		tcp_skb_tsorted_save(skb) {
			nskb = __pskb_copy(skb, MAX_TCP_HEADER, GFP_ATOMIC);
			err = nskb ? tcp_transmit_skb(sk, nskb, 0, GFP_ATOMIC) :
				     -ENOBUFS;
		} tcp_skb_tsorted_restore(skb);

		if (!err) {
			tcp_update_skb_after_send(sk, skb, tp->tcp_wstamp_ns);
			tcp_rate_skb_sent(sk, skb);
		}
	} else {
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
	}

	if (BPF_SOCK_OPS_TEST_FLAG(tp, BPF_SOCK_OPS_RETRANS_CB_FLAG))
		tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_RETRANS_CB,
				  TCP_SKB_CB(skb)->seq, segs, err);

	if (likely(!err)) {
		TCP_SKB_CB(skb)->sacked |= TCPCB_EVER_RETRANS;
		trace_tcp_retransmit_skb(sk, skb);
	} else if (err != -EBUSY) {
		NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPRETRANSFAIL, segs);
	}
	return err;
}

/* 重传数据包 */
int tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int err = __tcp_retransmit_skb(sk, skb, segs);

	if (err == 0) {
#if FASTRETRANS_DEBUG > 0
		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
			net_dbg_ratelimited("retrans_out leaked\n");
		}
#endif
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		tp->retrans_out += tcp_skb_pcount(skb);

		/* Save stamp of the first retransmit. */
		if (!tp->retrans_stamp)
			tp->retrans_stamp = tcp_skb_timestamp(skb);

	}

	if (tp->undo_retrans < 0)
		tp->undo_retrans = 0;
	tp->undo_retrans += tcp_skb_pcount(skb);
	return err;
}

/* This gets called after a retransmit timeout, and the initially
 * retransmitted data is acknowledged.  It tries to continue
 * resending the rest of the retransmit queue, until either
 * we've sent it all or the congestion window limit is reached.
 */
void tcp_xmit_retransmit_queue(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb, *rtx_head, *hole = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 max_segs;
	int mib_idx;

	if (!tp->packets_out)
		return;

	rtx_head = tcp_rtx_queue_head(sk);
	skb = tp->retransmit_skb_hint ?: rtx_head;
	max_segs = tcp_tso_segs(sk, tcp_current_mss(sk));
	skb_rbtree_walk_from(skb) {
		__u8 sacked;
		int segs;

		if (tcp_pacing_check(sk))
			break;

		/* we could do better than to assign each time */
		if (!hole)
			tp->retransmit_skb_hint = skb;

		segs = tp->snd_cwnd - tcp_packets_in_flight(tp);
		if (segs <= 0)
			return;
		sacked = TCP_SKB_CB(skb)->sacked;
		/* In case tcp_shift_skb_data() have aggregated large skbs,
		 * we need to make sure not sending too bigs TSO packets
		 */
		segs = min_t(int, segs, max_segs);

		if (tp->retrans_out >= tp->lost_out) {
			break;
		} else if (!(sacked & TCPCB_LOST)) {
			if (!hole && !(sacked & (TCPCB_SACKED_RETRANS|TCPCB_SACKED_ACKED)))
				hole = skb;
			continue;

		} else {
			if (icsk->icsk_ca_state != TCP_CA_Loss)
				mib_idx = LINUX_MIB_TCPFASTRETRANS;
			else
				mib_idx = LINUX_MIB_TCPSLOWSTARTRETRANS;
		}

		if (sacked & (TCPCB_SACKED_ACKED|TCPCB_SACKED_RETRANS))
			continue;

		if (tcp_small_queue_check(sk, skb, 1))
			return;

		if (tcp_retransmit_skb(sk, skb, segs))
			return;

		NET_ADD_STATS(sock_net(sk), mib_idx, tcp_skb_pcount(skb));

		/* 如果本连接处于CWR或者Recovery拥塞状态，则需要增加prr_out的值。 */
		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += tcp_skb_pcount(skb);

		if (skb == rtx_head &&
		    icsk->icsk_pending != ICSK_TIME_REO_TIMEOUT)
			tcp_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					     inet_csk(sk)->icsk_rto,
					     TCP_RTO_MAX,
					     skb);
	}
}

/* We allow to exceed memory limits for FIN packets to expedite
 * connection tear down and (memory) recovery.
 * Otherwise tcp_send_fin() could be tempted to either delay FIN
 * or even be forced to close flow without any FIN.
 * In general, we want to allow one skb per socket to avoid hangs
 * with edge trigger epoll()
 */
void sk_forced_mem_schedule(struct sock *sk, int size)
{
	int amt;

	if (size <= sk->sk_forward_alloc)
		return;
	amt = sk_mem_pages(size);
	sk->sk_forward_alloc += amt * SK_MEM_QUANTUM;
	sk_memory_allocated_add(sk, amt);

	if (mem_cgroup_sockets_enabled && sk->sk_memcg)
		mem_cgroup_charge_skmem(sk->sk_memcg, amt);
}

/* Send a FIN. The caller locks the socket for us.
 * We should try to send a FIN packet really hard, but eventually give up.
 */
void tcp_send_fin(struct sock *sk)
{
	/* 取得 sock 发送队列的最后一个元素，如果为空，返回 null*/
	struct sk_buff *skb, *tskb = tcp_write_queue_tail(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* Optimization, tack on the FIN if we have one skb in write queue and
	 * this skb was not yet sent, or we are under memory pressure.
	 * Note: in the latter case, FIN packet will be sent after a timeout,
	 * as TCP stack thinks it has already been transmitted.
	 */
	 /* 这里做了一些优化, 如果发送队列的末尾还有段没有发出去，则利用该段发送 FIN。 */
	if (!tskb && tcp_under_memory_pressure(sk))
		tskb = skb_rb_last(&sk->tcp_rtx_queue);

	/* 如果当前正在发送的队列不为空，或者当前 TCP 处于内存压力下 (值得进一步分析)，则进行该优化 */
	if (tskb) {
coalesce:
		TCP_SKB_CB(tskb)->tcp_flags |= TCPHDR_FIN;
		TCP_SKB_CB(tskb)->end_seq++; //递增序列号
		tp->write_seq++;
		if (tcp_write_queue_empty(sk)) { //队头为空
			/* This means tskb was already sent.
			 * Pretend we included the FIN on previous transmit.
			 * We need to set tp->snd_nxt to the value it would have
			 * if FIN had been sent. This is because retransmit path
			 * does not change tp->snd_nxt.
			 */
			tp->snd_nxt++;
			return;
		}
	} else {
		/* 为封包分配空间 */
		skb = alloc_skb_fclone(MAX_TCP_HEADER, sk->sk_allocation);
		if (unlikely(!skb)) {
			/* 如果分配不到空间，且队尾还有未发送的包，利用该包发出 FIN。 */
			if (tskb)
				goto coalesce;
			return;
		}
		INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
		skb_reserve(skb, MAX_TCP_HEADER);
		sk_forced_mem_schedule(sk, skb->truesize);

		/* 构造一个 FIN 包，并加入发送队列。 */
		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		tcp_init_nondata_skb(skb, tp->write_seq,
				     TCPHDR_ACK | TCPHDR_FIN);
		tcp_queue_skb(sk, skb);
	}

	/*  
	 * 在函数的最后，将所有的剩余数据一口气发出去，完成发送 FIN 包的过程。至此，主动
	 * 关闭过程的第一次握手完成。
	 */
	__tcp_push_pending_frames(sk, tcp_current_mss(sk), TCP_NAGLE_OFF);
}

/* We get here when a process closes a file descriptor (either due to
 * an explicit close() or as a byproduct of exit()'ing) and there
 * was unread data in the receive queue.  This behavior is recommended
 * by RFC 2525, section 2.17.  -DaveM
 */
void tcp_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;

	TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTRSTS);

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_TCP_HEADER, priority);
	if (!skb) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_init_nondata_skb(skb, tcp_acceptable_seq(sk),
			     TCPHDR_ACK | TCPHDR_RST);
	tcp_mstamp_refresh(tcp_sk(sk));
	/* Send it off. */
	if (tcp_transmit_skb(sk, skb, 0, priority))
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);

	/* skb of trace_tcp_send_reset() keeps the skb that caused RST,
	 * skb here is different to the troublesome skb, so use NULL
	 */
	trace_tcp_send_reset(sk, NULL);
}

/* Send a crossed SYN-ACK during socket establishment.
 * WARNING: This routine must only be called when we have already sent
 * a SYN packet that crossed the incoming SYN that caused this routine
 * to get called. If this assumption fails then the initial rcv_wnd
 * and rcv_wscale values will not be correct.
 */
int tcp_send_synack(struct sock *sk)
{
	struct sk_buff *skb;

	skb = tcp_rtx_queue_head(sk);
	if (!skb || !(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
		pr_err("%s: wrong queue state\n", __func__);
		return -EFAULT;
	}
	if (!(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_ACK)) {
		if (skb_cloned(skb)) {
			struct sk_buff *nskb;

			tcp_skb_tsorted_save(skb) {
				nskb = skb_copy(skb, GFP_ATOMIC);
			} tcp_skb_tsorted_restore(skb);
			if (!nskb)
				return -ENOMEM;
			INIT_LIST_HEAD(&nskb->tcp_tsorted_anchor);
			tcp_rtx_queue_unlink_and_free(skb, sk);
			__skb_header_release(nskb);
			tcp_rbtree_insert(&sk->tcp_rtx_queue, nskb);
			sk->sk_wmem_queued += nskb->truesize;
			sk_mem_charge(sk, nskb->truesize);
			skb = nskb;
		}

		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ACK;
		tcp_ecn_send_synack(sk, skb);
	}
	return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
}

/**
 * tcp_make_synack - Prepare a SYN-ACK.
 * sk: listener socket
 * dst: dst entry attached to the SYNACK
 * req: request_sock pointer
 *
 * Allocate one skb and build a SYNACK packet.
 * @dst is consumed : Caller should not use it again.
 */
/*
 * 该函数用来构造一个 SYN+ACK 段，
 * 并初始化 TCP 首部及 SKB 中的各字段项，
 * 填入相应的选项，如 MSS， SACK，窗口扩大因子，时间戳等。
 */
struct sk_buff *tcp_make_synack(const struct sock *sk, struct dst_entry *dst,
				struct request_sock *req,
				struct tcp_fastopen_cookie *foc,
				enum tcp_synack_type synack_type)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_key *md5 = NULL;
	struct tcp_out_options opts;
	struct sk_buff *skb;
	int tcp_header_size;
	struct tcphdr *th;
	int mss;

	/* 首先为将要发送的数据申请发送缓存，如果没有申请到，那就会返回 NULL。 */
	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (unlikely(!skb)) {
		dst_release(dst);
		return NULL;
	}

	/* 为 MAC 层， IP 层， TCP 层首部预留必要的空间。 */
	/* Reserve space for headers. */
	skb_reserve(skb, MAX_TCP_HEADER);

	/* 根据attach_req来判断该执行如何执行相关操作。然后设置发送缓存的目的路由。 */
	switch (synack_type) {
	case TCP_SYNACK_NORMAL:
		skb_set_owner_w(skb, req_to_sk(req));
		break;
	case TCP_SYNACK_COOKIE:
		/* Under synflood, we do not attach skb to a socket,
		 * to avoid false sharing.
		 */
		break;
	case TCP_SYNACK_FASTOPEN:
		/* sk is a const pointer, because we want to express multiple
		 * cpu might call us concurrently.
		 * sk->sk_wmem_alloc in an atomic, we can promote to rw.
		 */
		skb_set_owner_w(skb, (struct sock *)sk);
		break;
	}
	skb_dst_set(skb, dst);

	/* 根据每一个路由器上的 mss 以及自身的 mss 来得到最大的 mss。*/
	mss = tcp_mss_clamp(tp, dst_metric_advmss(dst));

	/* 清除选项，并且设置相关时间戳。 */
	memset(&opts, 0, sizeof(opts));
#ifdef CONFIG_SYN_COOKIES
	if (unlikely(req->cookie_ts))
		skb->skb_mstamp_ns = cookie_init_timestamp(req);
	else
#endif
		skb->skb_mstamp_ns = tcp_clock_ns();

	/* 查看是否有 MD5 选项，有的话构造出相应的 md5 */
#ifdef CONFIG_TCP_MD5SIG
	rcu_read_lock();
	md5 = tcp_rsk(req)->af_specific->req_md5_lookup(sk, req_to_sk(req));
#endif
	skb_set_hash(skb, tcp_rsk(req)->txhash, PKT_HASH_TYPE_L4);
	tcp_header_size = tcp_synack_options(sk, req, mss, skb, &opts, md5,
					     foc) + sizeof(*th);

	/* 得到 tcp 的头部大小，然后进行大小设置，并且重置传输层的头部。 */
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	/* 清空 tcp 头部，并设置 tcp 头部的各个字段 */
	th = (struct tcphdr *)skb->data;
	memset(th, 0, sizeof(struct tcphdr));
	th->syn = 1;
	th->ack = 1;
	tcp_ecn_make_synack(req, th);
	th->source = htons(ireq->ir_num);
	th->dest = ireq->ir_rmt_port;
	skb->mark = ireq->ir_mark;

	/* 首先初始化不含数据的 tcp 报文，然后设置相关的序列号，确认序列号，窗口大小，
	 * 选项字段，以及 TCP 数据偏移，之所以除以 4，是 doff 的单位是 32 位字，即以四个字
	 * 节长的字为计算单位。
	 */
	skb->ip_summed = CHECKSUM_PARTIAL;
	th->seq = htonl(tcp_rsk(req)->snt_isn);
	/* XXX data is queued and acked as is. No buffer/window check */
	th->ack_seq = htonl(tcp_rsk(req)->rcv_nxt);

	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	th->window = htons(min(req->rsk_rcv_wnd, 65535U));
	tcp_options_write((__be32 *)(th + 1), NULL, &opts);
	th->doff = (tcp_header_size >> 2);
	__TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTSEGS);

	/* 最后判断是否需要 md5 哈希值，如果需要的话，就进行添加。最后返回生成包含
	 * SYN+ACK 段的 skb。
	 */
#ifdef CONFIG_TCP_MD5SIG
	/* Okay, we have all we need - do the md5 hash if needed */
	if (md5)
		tcp_rsk(req)->af_specific->calc_md5_hash(opts.hash_location,
					       md5, req_to_sk(req), skb);
	rcu_read_unlock();
#endif

	/* Do not fool tcpdump (if any), clean our debris */
	skb->tstamp = 0;
	return skb;
}
EXPORT_SYMBOL(tcp_make_synack);

static void tcp_ca_dst_init(struct sock *sk, const struct dst_entry *dst)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_congestion_ops *ca;
	u32 ca_key = dst_metric(dst, RTAX_CC_ALGO);

	if (ca_key == TCP_CA_UNSPEC)
		return;

	rcu_read_lock();
	ca = tcp_ca_find_key(ca_key);
	if (likely(ca && try_module_get(ca->owner))) {
		module_put(icsk->icsk_ca_ops->owner);
		icsk->icsk_ca_dst_locked = tcp_ca_dst_locked(dst);
		icsk->icsk_ca_ops = ca;
	}
	rcu_read_unlock();
}

/* Do all connect socket setups that can be done AF independent. */
static void tcp_connect_init(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale;
	u32 rcv_wnd;

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr);
	if (sock_net(sk)->ipv4.sysctl_tcp_timestamps)
		tp->tcp_header_len += TCPOLEN_TSTAMP_ALIGNED;

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk))
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	/* If user gave his TCP_MAXSEG, record it to clamp */
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;
	tcp_mtup_init(sk);
	tcp_sync_mss(sk, dst_mtu(dst));

	tcp_ca_dst_init(sk, dst);

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = tcp_mss_clamp(tp, dst_metric_advmss(dst));

	tcp_initialize_rcv_mss(sk);

	/* limit the window selection if the user enforce a smaller rx buffer */
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (tp->window_clamp > tcp_full_space(sk) || tp->window_clamp == 0))
		tp->window_clamp = tcp_full_space(sk);

	rcv_wnd = tcp_rwnd_init_bpf(sk);
	if (rcv_wnd == 0)
		rcv_wnd = dst_metric(dst, RTAX_INITRWND);

	tcp_select_initial_window(sk, tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  sock_net(sk)->ipv4.sysctl_tcp_window_scaling,
				  &rcv_wscale,
				  rcv_wnd);

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	tcp_init_wl(tp, 0);
	tcp_write_queue_purge(sk);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	tp->snd_nxt = tp->write_seq;

	if (likely(!tp->repair))
		tp->rcv_nxt = 0;
	else
		tp->rcv_tstamp = tcp_jiffies32;
	tp->rcv_wup = tp->rcv_nxt;
	tp->copied_seq = tp->rcv_nxt;

	inet_csk(sk)->icsk_rto = tcp_timeout_init(sk);
	inet_csk(sk)->icsk_retransmits = 0;
	tcp_clear_retrans(tp);
}

static void tcp_connect_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	tcb->end_seq += skb->len;
	__skb_header_release(skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
	tp->write_seq = tcb->end_seq;
	tp->packets_out += tcp_skb_pcount(skb);
}

/* Build and send a SYN with data and (cached) Fast Open cookie. However,
 * queue a data-only packet after the regular SYN, such that regular SYNs
 * are retransmitted on timeouts. Also if the remote SYN-ACK acknowledges
 * only the SYN sequence, the data are retransmitted in the first ACK.
 * If cookie is not cached or other error occurs, falls back to send a
 * regular SYN with Fast Open cookie request option.
 */
static int tcp_send_syn_data(struct sock *sk, struct sk_buff *syn)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_fastopen_request *fo = tp->fastopen_req;
	int space, err = 0;
	struct sk_buff *syn_data;

	tp->rx_opt.mss_clamp = tp->advmss;  /* If MSS is not cached */
	if (!tcp_fastopen_cookie_check(sk, &tp->rx_opt.mss_clamp, &fo->cookie))
		goto fallback;

	/* MSS for SYN-data is based on cached MSS and bounded by PMTU and
	 * user-MSS. Reserve maximum option space for middleboxes that add
	 * private TCP options. The cost is reduced data space in SYN :(
	 */
	tp->rx_opt.mss_clamp = tcp_mss_clamp(tp, tp->rx_opt.mss_clamp);

	space = __tcp_mtu_to_mss(sk, inet_csk(sk)->icsk_pmtu_cookie) -
		MAX_TCP_OPTION_SPACE;

	space = min_t(size_t, space, fo->size);

	/* limit to order-0 allocations */
	space = min_t(size_t, space, SKB_MAX_HEAD(MAX_TCP_HEADER));

	syn_data = sk_stream_alloc_skb(sk, space, sk->sk_allocation, false);
	if (!syn_data)
		goto fallback;
	syn_data->ip_summed = CHECKSUM_PARTIAL;
	memcpy(syn_data->cb, syn->cb, sizeof(syn->cb));
	if (space) {
		int copied = copy_from_iter(skb_put(syn_data, space), space,
					    &fo->data->msg_iter);
		if (unlikely(!copied)) {
			tcp_skb_tsorted_anchor_cleanup(syn_data);
			kfree_skb(syn_data);
			goto fallback;
		}
		if (copied != space) {
			skb_trim(syn_data, copied);
			space = copied;
		}
	}
	/* No more data pending in inet_wait_for_connect() */
	if (space == fo->size)
		fo->data = NULL;
	fo->copied = space;

	tcp_connect_queue_skb(sk, syn_data);

	/* fastopen情况下，需要启动 TCP_CHRONO_BUSY 计时器。*/
	if (syn_data->len)
		tcp_chrono_start(sk, TCP_CHRONO_BUSY);

	err = tcp_transmit_skb(sk, syn_data, 1, sk->sk_allocation);

	syn->skb_mstamp_ns = syn_data->skb_mstamp_ns;

	/* Now full SYN+DATA was cloned and sent (or not),
	 * remove the SYN from the original skb (syn_data)
	 * we keep in write queue in case of a retransmit, as we
	 * also have the SYN packet (with no data) in the same queue.
	 */
	TCP_SKB_CB(syn_data)->seq++;
	TCP_SKB_CB(syn_data)->tcp_flags = TCPHDR_ACK | TCPHDR_PSH;
	if (!err) {
		tp->syn_data = (fo->copied > 0);
		tcp_rbtree_insert(&sk->tcp_rtx_queue, syn_data);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPORIGDATASENT);
		goto done;
	}

	/* data was not sent, put it in write_queue */
	__skb_queue_tail(&sk->sk_write_queue, syn_data);
	tp->packets_out -= tcp_skb_pcount(syn_data);

fallback:
	/* Send a regular SYN with Fast Open cookie request option */
	if (fo->cookie.len > 0)
		fo->cookie.len = 0;
	err = tcp_transmit_skb(sk, syn, 1, sk->sk_allocation);
	if (err)
		tp->syn_fastopen = 0;
done:
	fo->cookie.len = -1;  /* Exclude Fast Open option for SYN retries */
	return err;
}

/* Build a SYN and send it off. */
/* 真正构造 SYN 包并发送 */
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

	tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_CONNECT_CB, 0, NULL);

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	tcp_connect_init(sk);

	/* 如果 repair 位被置 1，那么结束 TCP 连接 */
	if (unlikely(tp->repair)) {
		tcp_finish_connect(sk, NULL);
		return 0;
	}

	/* 分配一个 sk_buff */
	buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
	if (unlikely(!buff))
		return -ENOBUFS;

	/* 初始化 skb，并自增 write_seq 的值 */
	tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);

	/* 设置时间戳 */
	tcp_mstamp_refresh(tp);
	tp->retrans_stamp = tcp_time_stamp(tp);

	/* 将当前的 sk_buff 添加到发送队列中 */
	tcp_connect_queue_skb(sk, buff);

	/* 支持显式拥塞控制 */
	tcp_ecn_send_syn(sk, buff);
	tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);


	/*
	 * 发送 SYN 包，这里同时还考虑了 Fast Open 的情况，意思就是
	 * 可以在连接建立的时候同时发数据。
	 */
	/* Send off SYN; include data in Fast Open. */
	err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
	      tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
	if (err == -ECONNREFUSED)
		return err;

	/* We change tp->snd_nxt after the tcp_transmit_skb() call
	 * in order to make this packet get counted in tcpOutSegs.
	 */
	/* send next 下一个待发送字节的序列号 */
	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;
	buff = tcp_send_head(sk);
	if (unlikely(buff)) {
		tp->snd_nxt	= TCP_SKB_CB(buff)->seq;
		tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
	}
	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);


	/* 设定超时重传定时器 */
	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}
EXPORT_SYMBOL(tcp_connect);

/* Send out a delayed ack, the caller does the policy checking
 * to see if we should even be here.  See tcp_input.c:tcp_ack_snd_check()
 * for details.
 */
void tcp_send_delayed_ack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int ato = icsk->icsk_ack.ato;
	unsigned long timeout;

	if (ato > TCP_DELACK_MIN) {
		const struct tcp_sock *tp = tcp_sk(sk);
		int max_ato = HZ / 2;

		if (icsk->icsk_ack.pingpong ||
		    (icsk->icsk_ack.pending & ICSK_ACK_PUSHED))
			max_ato = TCP_DELACK_MAX;

		/* Slow path, intersegment interval is "high". */

		/* If some rtt estimate is known, use it to bound delayed ack.
		 * Do not use inet_csk(sk)->icsk_rto here, use results of rtt measurements
		 * directly.
		 */
		if (tp->srtt_us) {
			int rtt = max_t(int, usecs_to_jiffies(tp->srtt_us >> 3),
					TCP_DELACK_MIN);

			if (rtt < max_ato)
				max_ato = rtt;
		}

		ato = min(ato, max_ato);
	}

	/* Stay within the limit we were given */
	timeout = jiffies + ato;

	/* Use new timeout only if there wasn't a older one earlier. */
	if (icsk->icsk_ack.pending & ICSK_ACK_TIMER) {
		/* If delack timer was blocked or is about to expire,
		 * send ACK now.
		 */
		if (icsk->icsk_ack.blocked ||
		    time_before_eq(icsk->icsk_ack.timeout, jiffies + (ato >> 2))) {
			tcp_send_ack(sk);
			return;
		}

		if (!time_before(timeout, icsk->icsk_ack.timeout))
			timeout = icsk->icsk_ack.timeout;
	}
	icsk->icsk_ack.pending |= ICSK_ACK_SCHED | ICSK_ACK_TIMER;
	icsk->icsk_ack.timeout = timeout;
	sk_reset_timer(sk, &icsk->icsk_delack_timer, timeout);
}

/* This routine sends an ack and also updates the window. */
void __tcp_send_ack(struct sock *sk, u32 rcv_nxt)
{
	struct sk_buff *buff;

	/* 如果当前的套接字已经被关闭了，那么直接返回。 */
	/* If we have been reset, we may not send again. */
	if (sk->sk_state == TCP_CLOSE)
		return;

	/* We are not putting this on the write queue, so
	 * tcp_transmit_skb() will set the ownership to this
	 * sock.
	 */
	/* 为数据包分配空间 */
	buff = alloc_skb(MAX_TCP_HEADER,
			 sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));
	if (unlikely(!buff)) {
		inet_csk_schedule_ack(sk);
		inet_csk(sk)->icsk_ack.ato = TCP_ATO_MIN;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
					  TCP_DELACK_MAX, TCP_RTO_MAX);
		return;
	}

	/* 初始化 ACK 包 */
	/* Reserve space for headers and prepare control bits. */
	skb_reserve(buff, MAX_TCP_HEADER);
	tcp_init_nondata_skb(buff, tcp_acceptable_seq(sk), TCPHDR_ACK);

	/* We do not want pure acks influencing TCP Small Queues or fq/pacing
	 * too much.
	 * SKB_TRUESIZE(max(1 .. 66, MAX_TCP_HEADER)) is unfortunately ~784
	 */
	skb_set_tcp_pure_ack(buff);

	/* Send it off, this clears delayed acks for us. */
	__tcp_transmit_skb(sk, buff, 0, (__force gfp_t)0, rcv_nxt);
}
EXPORT_SYMBOL_GPL(__tcp_send_ack);

/* 第三次握手：发送ACK包
 * 该函数用于发送 ACK，并更新窗口的大小
 */
void tcp_send_ack(struct sock *sk)
{
	__tcp_send_ack(sk, tcp_sk(sk)->rcv_nxt);
}

/* This routine sends a packet with an out of date sequence
 * number. It assumes the other end will try to ack it.
 *
 * Question: what should we make while urgent mode?
 * 4.4BSD forces sending single byte of data. We cannot send
 * out of window data, because we have SND.NXT==SND.MAX...
 *
 * Current solution: to send TWO zero-length segments in urgent mode:
 * one is with SEG.SEQ=SND.UNA to deliver urgent pointer, another is
 * out-of-date with SND.UNA-1 to probe window.
 */
static int tcp_xmit_probe_skb(struct sock *sk, int urgent, int mib)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_TCP_HEADER,
			sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));
	if (!skb)
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	/* Use a previous sequence.  This should cause the other
	 * end to send an ack.  Don't queue or clone SKB, just
	 * send it.
	 */
	tcp_init_nondata_skb(skb, tp->snd_una - !urgent, TCPHDR_ACK);
	NET_INC_STATS(sock_net(sk), mib);
	return tcp_transmit_skb(sk, skb, 0, (__force gfp_t)0);
}

/* Called from setsockopt( ... TCP_REPAIR ) */
void tcp_send_window_probe(struct sock *sk)
{
	if (sk->sk_state == TCP_ESTABLISHED) {
		tcp_sk(sk)->snd_wl1 = tcp_sk(sk)->rcv_nxt - 1;
		tcp_mstamp_refresh(tcp_sk(sk));
		tcp_xmit_probe_skb(sk, 0, LINUX_MIB_TCPWINPROBE);
	}
}

/* Initiate keepalive or window probe from timer. */
int tcp_write_wakeup(struct sock *sk, int mib)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE)
		return -1;

	skb = tcp_send_head(sk);
	if (skb && before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))) {
		int err;
		unsigned int mss = tcp_current_mss(sk);
		unsigned int seg_size = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

		if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

		/* We are probing the opening of a window
		 * but the window size is != 0
		 * must have been a result SWS avoidance ( sender )
		 */
		if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||
		    skb->len > mss) {
			seg_size = min(seg_size, mss);
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
			if (tcp_fragment(sk, TCP_FRAG_IN_WRITE_QUEUE,
					 skb, seg_size, mss, GFP_ATOMIC))
				return -1;
		} else if (!tcp_skb_pcount(skb))
			tcp_set_skb_tso_segs(skb, mss);

		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
		if (!err)
			tcp_event_new_data_sent(sk, skb);
		return err;
	} else {
		if (between(tp->snd_up, tp->snd_una + 1, tp->snd_una + 0xFFFF))
			tcp_xmit_probe_skb(sk, 1, mib);
		return tcp_xmit_probe_skb(sk, 0, mib);
	}
}

/* A window probe timeout has occurred.  If window is not closed send
 * a partial packet else a zero probe.
 */
void tcp_send_probe0(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	unsigned long probe_max;
	int err;

	err = tcp_write_wakeup(sk, LINUX_MIB_TCPWINPROBE);

	if (tp->packets_out || tcp_write_queue_empty(sk)) {
		/* Cancel probe timer, if it is not required. */
		icsk->icsk_probes_out = 0;
		icsk->icsk_backoff = 0;
		return;
	}

	if (err <= 0) {
		if (icsk->icsk_backoff < net->ipv4.sysctl_tcp_retries2)
			icsk->icsk_backoff++;
		icsk->icsk_probes_out++;
		probe_max = TCP_RTO_MAX;
	} else {
		/* If packet was not sent due to local congestion,
		 * do not backoff and do not remember icsk_probes_out.
		 * Let local senders to fight for local resources.
		 *
		 * Use accumulated backoff yet.
		 */
		if (!icsk->icsk_probes_out)
			icsk->icsk_probes_out = 1;
		probe_max = TCP_RESOURCE_PROBE_INTERVAL;
	}
	tcp_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
			     tcp_probe0_when(sk, probe_max),
			     TCP_RTO_MAX,
			     NULL);
}

int tcp_rtx_synack(const struct sock *sk, struct request_sock *req)
{
	const struct tcp_request_sock_ops *af_ops = tcp_rsk(req)->af_specific;
	struct flowi fl;
	int res;

	tcp_rsk(req)->txhash = net_tx_rndhash();
	res = af_ops->send_synack(sk, NULL, &fl, req, NULL, TCP_SYNACK_NORMAL);
	if (!res) {
		__TCP_INC_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
		if (unlikely(tcp_passive_fastopen(sk)))
			tcp_sk(sk)->total_retrans++;
		trace_tcp_retransmit_synack(sk, req);
	}
	return res;
}
EXPORT_SYMBOL(tcp_rtx_synack);
