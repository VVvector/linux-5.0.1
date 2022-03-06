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

/* 增加到last_max_cwnd需要的rtt数，默认4 */
#define BICTCP_B		4	 /*
					  * In binary search,
					  * go to point (max+min)/N
					  */

static int fast_convergence = 1;

/* 一个rtt时间内最大增加的cwnd数量，默认16 */
static int max_increment = 16;
static int low_window = 14;
static int beta = 819;		/* = 819/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh;

/* 一个rtt时间内最大增加的cwnd数量，默认16 */
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

/* bictcp_reset在两种情况下被调用:
 * 1. 初始化时（bictcp_init ）
 * 2. 进入拥塞处理时（bictcp_state 状态为TCP_CA_Loss）
 *
 * TCP_CA_Loss是当被超时定时器超时的时候，调用tcp_enter_loss,在其中被设置
 * 而内核的丢包检测有:超时丢包检测,快速丢包检测以及rack之类的丢包检测。
 * 当丢包时会保存ssthresh，通过ssthresh来记录当前cwnd信息，下一次可以慢启动快速达到该阈值。
 */
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
/*
 * ACK驱动：每收到一个ACK的时候，便将窗口设置到Wmax和Wmin的中点，一直持续到接近Wmax。
 * 可见BIC的行为是ACK驱动的，而ACK在什么时候到来是与RTT相关的。
 *
 * bic算法在超过ssthresh后有max_increment限制，只能线性增加。
 * 对于两个rtt不同的tcp连接， 因为max_increment的控制，导致两个连接达到相同速率的不公平性
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
	/* 正常情况下，如果cwnd没有更新，且ack的间隔小于31ms，则bic不会使用该ack做ca->cnt的计算更新。 */
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) /* record the beginning of an epoch */
		ca->epoch_start = tcp_jiffies32;

	/* 由于该增长方式在小带宽下显然不怎么奏效，BIC规定了如果当前窗口值小于low_window(该值在实现里面为14)，
	 * 那么就采用标准TCP的拥塞方式进行处理。
	 */
	/* start off normal */
	if (cwnd <= low_window) {
		ca->cnt = cwnd;
		return;
	}

	/* binary increase */
	if (cwnd < ca->last_max_cwnd) {
		__u32	dist = (ca->last_max_cwnd - cwnd)
			/ BICTCP_B;

		/* 离最大窗口很远的时候，快速增长，一个rtt增max_increment个窗口 */
		if (dist > max_increment)
			/* linear increase */
			ca->cnt = cwnd / max_increment;

		/* 当接近最大窗口时（差值小于4），一个rtt增(BICTCP_B/smooth_part)个MSS。增长就非常缓慢，
		 * 大约经过smooth_part个rtt才增大到最大窗口。
		 * 5个rtt后cwnd + 1。
		 */
		else if (dist <= 1U)
			/* binary search increase */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B;

		/* 一个rtt增(last_max_cwnd - cwnd) 个窗口，也就是一个rtt达到最大窗口．
		 * 经过 BICTCP_B = 4 个rtt时间后，达到last_max_cwnd。
		 */
		else
			/* binary search increase */
			ca->cnt = cwnd / dist;
	} else {
		/* 说明只超过last_max_cwnd一点，继续谨慎增加。
		 *一个rtt增(BICTCP_B/smooth_part )个MSS, 即5个rtt后，cwnd+1。
		 */
		/* slow start AMD linear increase */
		if (cwnd < ca->last_max_cwnd + BICTCP_B)
			/* slow start */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B;

		/* 一个rtt增大(cwnd-last_max_cwnd)/(BICTCP_B-1)个窗口．速度会越来越快，
		 * 因为cwnd不断增大．根据if条件范围可以算出1个rtt增加的窗口范围在[BICTCP_B/(BICTCP_B-1), max_increment] */
		else if (cwnd < ca->last_max_cwnd + max_increment*(BICTCP_B-1))
			/* slow start */
			ca->cnt = (cwnd * (BICTCP_B-1))
				/ (cwnd - ca->last_max_cwnd);

		/* 说明上一个last_max_cwnd已经没有参考意义，开始线性增加，一个rtt增加max_increment
		 * 一个rtt增max_increment个窗口
		 */
		else
			/* linear increase */
			ca->cnt = cwnd / max_increment;
	}

	/* 当last_max_cwnd == 0。即在慢启动开始或出现拥塞的时候，控制cnt不超过20,
	 * 即一个rtt至少增cwnd/20个窗口。
	 * 注意：前期在没有发生过丢包时，last_max_cwnd一直为0，即ca->cnt为10。
	 */
	/* if in slow start or link utilization is very low */
	if (ca->last_max_cwnd == 0) {
		if (ca->cnt > 20) /* increase cwnd 5% per RTT */
			ca->cnt = 20;
	}

	/*
	 * 对延迟确认的处理。延迟确认的时候，一个ack不止是确认一个报文，作者的意思是，
	 * 根据延迟ack的比例(1 << ACK_RATIO_SHIFT / delayed_ack)，
	 * 增大窗口的时候, cnt需要扩大 (delayed_ack / 2^ACK_RATIO_SHIFT) = 2 倍，即速度下降50%。
	 * 默认延迟比例为50%（ACK_RATIO_SHIFT为常数4, delayed_ack默认值为2 << ACK_RATIO_SHIFT）
	 */
	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;
}

static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	/* 如果由于cwnd而限制的数据的发送，应该继续进行cwnd的调整；否则，不应该调整cwnd。
	 *（例如，如果是由于application发送受限）
	 * (检查点3：看是否有进入到拥塞算法的慢启动或者拥塞避免阶段算法进行窗口调整。)
	 */
	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp))
		tcp_slow_start(tp, acked);
	else {
		/* 根据算法更新ca->cnt变量，即控制后面的窗口更新速度。 */
		bictcp_update(ca, tp->snd_cwnd);

		/* 实际调整cwnd */
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
/*
 * 每收到一个ack，就会调用tcp_ack(这个函数有点复杂后面慢慢看)。tcp_ack会调用.pkts_acked和.cong_avoid，
 * pkts_acked对应bictcp_acked, cong_avoid对应bictcp_cong_avoid。tcp_ack中如果检测到丢包，则进入拥塞阶段，
 * 调用.ssthresh，对应bic的bictcp_recalc_ssthresh函数，tcp_ack完成重传后，
 * 退回到拥塞阶段，调用.undo_cwnd函数，即tcp_reno_undo_cwnd。
 * 
 * bictcp_recalc_ssthresh()用于拥塞后计算慢启动阈值ssthresh。
 */
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */

	/* 设置last_max_cwnd */
	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE); //即大约0.9倍cwnd
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	/* 设置snd_cwnd */
	if (tp->snd_cwnd <= low_window)
		return max(tp->snd_cwnd >> 1U, 2U);
	else
		return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U); //即大约0.8倍cwnd。
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss)
		bictcp_reset(inet_csk_ca(sk));
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
/*
 * 计算ca->delayed_ack，表示每收到一个ack，平均确认的packet数量，这里通过ACK_RATIO_SHIFT做了加权计算
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
