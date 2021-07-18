/*
 * Binary Increase Congestion control for TCP
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of BICTCP in
 * Lison-Xu, Kahaled Harfoush, and Injong Rhee.
 *  "Binary Increase Congestion Control for Fast, Long Distance
 *  Networks" in InfoComm 2004
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/bitcp.pdf
 *
 * Unless BIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define BICTCP_B		4	 /*
					  * In binary search,
					  * go to point (max+min)/N
					  */

static int fast_convergence = 1;
static int max_increment = 16;
static int low_window = 14;
static int beta = 819;		/* = 819/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh;
static int smooth_part = 20;

module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(max_increment, int, 0644);
MODULE_PARM_DESC(max_increment, "Limit on increment allowed during binary search");
module_param(low_window, int, 0644);
MODULE_PARM_DESC(low_window, "lower bound on congestion window (for TCP friendliness)");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(smooth_part, int, 0644);
MODULE_PARM_DESC(smooth_part, "log(B/(B*Smin))/log(B/(B-1))+B, # of RTT from Wmax-B to Wmax");

/* BIC TCP Parameters */
struct bictcp {
	/* 每次cwnd增长 1/cnt的比例 */
	u32	cnt;		/* increase cwnd by 1 after ACKs */

	/* snd_cwnd之前的最大值 */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */

	/* 最近的snd_cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */

	/* 更新last_cwnd的时间 */
	u32	last_time;	/* time when updated last_cwnd */

	/* 一轮的开始 */
	u32	epoch_start;	/* beginning of an epoch */

#define ACK_RATIO_SHIFT	4
	u32	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->epoch_start = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;
}

static void bictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);

	/* 如果设置了初始值，就设置为初始值 */
	if (initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) /* record the beginning of an epoch */
		ca->epoch_start = tcp_jiffies32;

	/* start off normal */
	if (cwnd <= low_window) {
		ca->cnt = cwnd;
		return;
	}

	/* binary increase */
	if (cwnd < ca->last_max_cwnd) {
		__u32	dist = (ca->last_max_cwnd - cwnd)
			/ BICTCP_B;

		if (dist > max_increment)
			/* linear increase */
			ca->cnt = cwnd / max_increment;
		else if (dist <= 1U)
			/* binary search increase */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B;
		else
			/* binary search increase */
			ca->cnt = cwnd / dist;
	} else {
		/* slow start AMD linear increase */
		if (cwnd < ca->last_max_cwnd + BICTCP_B)
			/* slow start */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B;
		else if (cwnd < ca->last_max_cwnd + max_increment*(BICTCP_B-1))
			/* slow start */
			ca->cnt = (cwnd * (BICTCP_B-1))
				/ (cwnd - ca->last_max_cwnd);
		else
			/* linear increase */
			ca->cnt = cwnd / max_increment;
	}

	/* if in slow start or link utilization is very low */
	if (ca->last_max_cwnd == 0) {
		if (ca->cnt > 20) /* increase cwnd 5% per RTT */
			ca->cnt = 20;
	}

	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;
}

static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp))
		tcp_slow_start(tp, acked);
	else {
		bictcp_update(ca, tp->snd_cwnd);
		tcp_cong_avoid_ai(tp, ca->cnt, 1);
	}
}

/*
 *	behave like Reno until low_window is reached,
 *	then increase congestion window slowly
 */
 /* 门限值的计算
  * 这里涉及到了 Fast Convergence 机制。该机制的存在是为了加快 CUBIC 算法的收敛速
  * 度。在网络中，一个新的流的加入，会使得旧的流让出一定的带宽，以便给新的流让出一
  * 定的增长空间。为了增加旧的流释放的带宽量， CUBIC 的作者引入了 Fast Convergence
  * 机制。每次发生丢包后，会对比此次丢包时拥塞窗口的大小和之前的拥塞窗口大小。如
  * 果小于了之前拥塞窗口的最大值，那么就说明可能是有新的流加入了。此时，就多留出
  * 一些带宽给新的流使用，以使得网络尽快收敛到稳定状态。
  */
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	if (tp->snd_cwnd <= low_window)
		return max(tp->snd_cwnd >> 1U, 2U);
	else
		return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss)
		bictcp_reset(inet_csk_ca(sk));
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
static void bictcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_state == TCP_CA_Open) {
		struct bictcp *ca = inet_csk_ca(sk);

		ca->delayed_ack += sample->pkts_acked -
			(ca->delayed_ack >> ACK_RATIO_SHIFT);
	}
}

static struct tcp_congestion_ops bictcp __read_mostly = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "bic",
};

static int __init bictcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&bictcp);
}

static void __exit bictcp_unregister(void)
{
	tcp_unregister_congestion_control(&bictcp);
}

module_init(bictcp_register);
module_exit(bictcp_unregister);

MODULE_AUTHOR("Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BIC TCP");
