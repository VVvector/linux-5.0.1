/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U<<3)
#define HYSTART_DELAY_MAX	(16U<<3)
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta __read_mostly = 2;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta, "spacing between ack's indicating train (msecs)");

/* BIC TCP Parameters */
struct bictcp {
	/* 每次 cwnd 增长 1/cnt 的比例 */
	u32	cnt;		/* increase cwnd by 1 after ACKs */

	/* snd_cwnd 之前的最大值 */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */

	/* 最近的 snd_cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */

	/* 更新 last_cwnd 的时间 */
	u32	last_time;	/* time when updated last_cwnd */

	/* bic 函数的初始点 */
	u32	bic_origin_point;/* origin point of bic function */

	/* 从当前一轮开始到初始点的时间 */
	u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */

	/* 最小延迟 (msec << 3) */
	u32	delay_min;	/* min delay (msec << 3) */

	/* 一轮的开始 */
	u32	epoch_start;	/* beginning of an epoch */

	/* ack 的数量 */
	u32	ack_cnt;	/* number of acks */

	/* estimated tcp cwnd */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
	u16	unused;

	/* 用于决定 curr_rtt 的样本数 */
	u8	sample_cnt;	/* number of samples to decide curr_rtt */

	/* 是否找到了退出点? */
	u8	found;		/* the exit point is found? */

	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->found = 0;
}

static inline u32 bictcp_clock(void)
{
#if HZ < 1000
	return ktime_to_ms(ktime_get_real());
#else
	return jiffies_to_msecs(jiffies);
#endif
}

/*
 * 在长期的实践中，人们发现慢启动存在这样一个问题：如果慢启动时窗口变得很大
 *（在大带宽网络中），那么如果慢启动的过程中发生了丢包，有可能一次丢掉大量的包（因
 * 为每次窗口都会加倍）。 HyStart(Hybrid Slow Start) 是一种优化过的慢启动算法，可以
 * 避免传统慢启动过程中的突发性丢包，从而提升系统的吞吐量并降低系统负载。
 * 在 HyStart 算法中，慢启动过程仍然是每次将拥塞窗口加倍。但是，它会使用 ACK
 * 空间和往返延迟作为启发信息，来寻找一个安全的退出点 (Safe Exit Points)。退出点即
 * 结束慢启动并进入拥塞避免的点。如果在慢启动的过程中发生丢包，那么 HyStart 算法
 * 的表现和传统的慢启动协议是一致的。
 * 初始化 HyStart 算法时，会记录当前的时间，上一次的 rtt 值，并重新统计当前的
 * rtt 值。
 */
static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = bictcp_clock();
	ca->end_seq = tp->snd_nxt;
	ca->curr_rtt = 0;
	ca->sample_cnt = 0;
}

static void bictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);

	/* 查看是否启用了hystart机制 */
	if (hystart)
		bictcp_hystart_reset(sk);

	/* 如果设置了初始值，就设置为初始值 */
	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

/* 
 * 如果目前没有任何数据包在传输了，那么需要重新设定epoch_start。这个是为了
 * 解决当应用程序在一段时间内不发送任何数据时， now-epoch_start 会变得很大，由此，
 * 根据 Cubic 函数计算出来的目标拥塞窗口值也会变得很大。但显然，这是一个错误。因此，
 * 需要在应用程序重新开始发送数据时，重置epoch_start 的值。在这里CA_EVENT_TX_START事
 * 件表明目前所有的包都已经被确认了（即没有任何正在传输的包），而应用程序又开始
 * 发送新的数据包了。所有的包都被确认说明应用程序有一段时间没有发包。因而，在程
 * 序又重新开始发包时，需要重新设定 epoch_start的值，以便在计算拥塞窗口的大小时，
 * 仍能合理地遵循 cubic 函数的曲线。
 */
static void bictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct bictcp *ca = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	/* 统计 ACKed packets 的数目 */
	ca->ack_cnt += acked;	/* count the number of ACKed packets */

	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	/* CUBIC 函数每个时间单位内最多更新一次 ca->cnt 的值。
	 * 每一次发生 cwnd 减小事件， ca->epoch_start 会被设置为 0.
	 * 这会强制重新计算 ca->cnt。
	 */
	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && tcp_jiffies32 == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) {
		/* 记录起始时间 */
		ca->epoch_start = tcp_jiffies32;	/* record beginning */

		/* 开始计数 */
		ca->ack_cnt = acked;			/* start counting */

		/* 同步cubic的cwnd值 */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(tcp_jiffies32 - ca->epoch_start);
	t += msecs_to_jiffies(ca->delay_min >> 3);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	/* 根据 cubic 函数计算出来的目标拥塞窗口值和当前拥塞窗口值，计算 cnt 的大小。 */
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		/* 只增长一小点 */
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

	/* TCP 友好性 */
tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;

		/* 推算在传统的 AIMD 算法下， TCP 拥塞窗口的大小 */
		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		/* 如果 TCP 的算法快于 CUBIC，那么就增长到 TCP 算法的水平 */
		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	 /* 控制增长速率不高于每个 rtt 增长为原来的 1.5 倍 */
	ca->cnt = max(ca->cnt, 2U);
}

/* 处于拥塞避免状态时，计算拥塞窗口 */
static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;


	/* 当 tp->snd_cwnd < tp->snd_ssthresh 时，
	 * 让拥塞窗口大小正好等于 ssthresh 的大小。并据此计算 acked 的大小。
	 * 这里不妨举个例子。如果 ssthresh 的值为 6，初始 cwnd 为 1。那么按照 TCP 的标准，
	 * 拥塞窗口大小的变化应当为 1,2,4,6 而不是 1,2,4,8。当处于慢启动的状态时， acked 的数
	 * 目完全由慢启动决定。
	 * 
	 * 如果满足 cwnd < ssthresh，那么， bictcp_cong_avoid就表现为慢启动。
	 * 否则，就表现为拥塞避免。拥塞避免状态下，调用bictcp_update来更新拥塞窗口的值。
	 */
	if (tcp_in_slow_start(tp)) {
		if (hystart && after(ack, ca->end_seq))
			bictcp_hystart_reset(sk);
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}

	/* 到这里，说明需要进入拥塞避免处理了。 */
	bictcp_update(ca, tp->snd_cwnd, acked);

	/* 在更新完窗口大小以后， CUBIC 模块没有直接改变窗口值，
	 * 而是通过调用 tcp_cong_avoid_ai() 来改变窗口大小的。
	 */
	tcp_cong_avoid_ai(tp, ca->cnt, acked);
}

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

	return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

/* 当拥塞状态机的状态发生改变时，会调用set_state函数，对应到 CUBIC 模块中，
 * 就是bictcp_state函数。
 * 
 * CUBIC 只特殊处理了一种状态： TCP_CA_Loss。可以看到，当进入了 LOSS 以后，就会
 * 调用bictcp_reset函数，重置拥塞控制参数。这样，拥塞控制算法就会重新从慢启动开
 * 始执行。
 */
static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		bictcp_reset(inet_csk_ca(sk));
		bictcp_hystart_reset(sk);
	}
}

/*
 * 每次收到 ACK 以后，如果 tcp 仍处于慢启动状态，且拥塞窗口大小已经大于了一
 * 定的值，那么就会通过调用hystart_update()进入到 hystart 算法。
 */
static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	/* 如果已经找到了退出点，那么直接返回 */
	if (ca->found & hystart_detect)
		return;

	/*
	 * 第一个判别条件，如果收到两次相隔不远的 ACK 之间的时间大于了 rtt 时间的一
	 * 半，那么，就说明窗口的大小差不多到了网络容量的上限了。这里之所以会右移 4，是因为
	 * delay_min是最小延迟左移 3 后的结果。 rtt 的一半相当于单程的时延。连续收到的两次
	 * ACK 可以用于估计带宽大小。这里需要特别解释一下：由于在慢启动阶段，会一次性发
	 * 送大量的包，所以，可以假设在网络中，数据是连续发送的。而收到的两个连续的包之间
	 * 的时间间隔就是窗口大小除以网络带宽的商。作为发送端，我们只能获得两次 ACK 之间
	 * 的时间差，因此用这个时间来大致估计带宽。拥塞窗口的合理大小为 C = B ×Dmin +S，
	 * 这里 C 是窗口大小， B 是带宽， Dmin 是最小的单程时延， S 是缓存大小。由于带宽是
	 * 基本恒定的，因此，只要两次 ACK 之间的时间接近与 Dmin 就可以认为该窗口的大小
	 * 是基本合理的，已经充分的利用了网络。
	 */
	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now = bictcp_clock();

		/* first detection parameter - ack-train detection */
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta) {
			ca->last_ack = now;
			if ((s32)(now - ca->round_start) > ca->delay_min >> 4) {
				ca->found |= HYSTART_ACK_TRAIN;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}

	/*
	 * 第二个启发条件是如果当前往返时延的增长已经超过了一定的限度，那么，说明网
	 * 络的带宽已经要被占满了。因此，也需要退出慢启动状态。
	 */
	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			if (ca->curr_rtt == 0 || ca->curr_rtt > delay)
				ca->curr_rtt = delay;

			ca->sample_cnt++;
		} else {
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
				ca->found |= HYSTART_DELAY;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}

	/* 退出慢启动状态的方法很简单，都是直接将当前的snd_ssthresh的大小设定为和当前拥
	 * 塞窗口一样的大小。这样， TCP 自然就会转入拥塞避免状态。
 	 */
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
 /* 收到 ACK 后， Cubic 模块会重新计算链路的延迟情况。 */
static void bictcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 delay;

	/* Some calls are for duplicates without timetamps */
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
		return;

	delay = (sample->rtt_us << 3) / USEC_PER_MSEC;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	/* 当第一次调用或者链路延迟增大时，重设 delay_min 的值。 */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	/* 当 cwnd 大于阈值(16)后，会触发 hystart 更新机制 */
	if (hystart && tcp_in_slow_start(tp) &&
	    tp->snd_cwnd >= hystart_low_window)
		hystart_update(sk, delay);
}

static struct tcp_congestion_ops cubictcp __read_mostly = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= bictcp_cwnd_event,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "cubic",
};

/* 系统默认的拥塞控制算法:
	拥塞算法是 针对发送方而言，但 收到接收方的窗口限制。
	解决在大带宽延迟积网络中TCP拥塞窗口增长缓慢的问题，其具有TCP友好性与RTT公平性，
	实时保持窗口的增长率不受RTT的影响

 * CUBIC 算法的思路是这样的：当发生了一次丢包后，它将此时的窗口大小定义为
 * Wmax，之后，进行乘法减小。这里与标准 TCP 不同，乘法减小时不是直接减小一半，
 * 而是乘一个常系数 β。快重传和快恢复的部分和标准 TCP 一致。当它进入到拥塞避免
 * 阶段以后，它根据 cubic 函数凹的部分进行窗口的增长，直至到达 Wmax 为止。之后，
 * 它会根据 cubic 函数凸的部分继续增长。
 */
static int __init cubictcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */
	/* 预先计算缩放因子（此时假定 SRTT 为 100ms） */
	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3
		/ (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(cube_factor, bic_scale * 10);

	/* 注册到系统中 */
	return tcp_register_congestion_control(&cubictcp);
}

static void __exit cubictcp_unregister(void)
{
	tcp_unregister_congestion_control(&cubictcp);
}

module_init(cubictcp_register);
module_exit(cubictcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CUBIC TCP");
MODULE_VERSION("2.3");
