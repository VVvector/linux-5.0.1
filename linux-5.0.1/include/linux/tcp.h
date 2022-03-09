/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H


#include <linux/skbuff.h>
#include <linux/win_minmax.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>
#include <uapi/linux/tcp.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int __tcp_hdrlen(const struct tcphdr *th)
{
	return th->doff * 4;
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return __tcp_hdrlen(tcp_hdr(skb));
}

static inline struct tcphdr *inner_tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_inner_transport_header(skb);
}

static inline unsigned int inner_tcp_hdrlen(const struct sk_buff *skb)
{
	return inner_tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* TCP Fast Open */
#define TCP_FASTOPEN_COOKIE_MIN	4	/* Min Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_MAX	16	/* Max Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_SIZE 8	/* the size employed by this impl. */

/* TCP Fast Open Cookie as stored in memory */
struct tcp_fastopen_cookie {
	union {
		u8	val[TCP_FASTOPEN_COOKIE_MAX];
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr addr;
#endif
	};
	s8	len;
	bool	exp;	/* In RFC6994 experimental option format */
};

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

/*These are used to set the sack_ok field in struct tcp_options_received */
#define TCP_SACK_SEEN     (1 << 0)   /*1 = peer is SACK capable, */
#define TCP_DSACK_SEEN    (1 << 2)   /*1 = DSACK was received from peer*/

/* 其主要表述 TCP 头部的选项字段。*/
struct tcp_options_received {
/*	PAWS/RTTM data	*/
	/* 记录从接收到的段中取出时间戳设置到 ts_recent 的时间
	 * 用于检测 ts_recent 的有效性：如果自从该事件之后已经
	 * 经过了超过 24 天的时间，则认为 ts_recent 已无效。
	 */
	int	ts_recent_stamp;/* Time we stored ts_recent (for aging) */

	/*
	 * 下一个待发送的 TCP 段中的时间戳回显值。当一个含有最后
	 * 发送 ACK 中确认序号的段到达时，该段中的时间戳被保存在
	 * ts_recent 中。而下一个待发送的 TCP 段的时间戳值是由
	 * SKB 中 TCP 控制块的成员 when 填入的， when 字段值是由协议
	 * 栈取系统时间变量 jiffies 的低 32 位。
	 */
	u32	ts_recent;	/* Time stamp to echo next		*/

	/* 保存最近一次接收到对端的 TCP 段的时间戳选项中的时间戳值。*/
	u32	rcv_tsval;	/* Time stamp value             	*/

	/* 保存最近一次接收到对端的 TCP 段的时间戳选项中的时间戳回显应答。*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/

	/* 标识最近一次接收到的 TCP 段是否存在 TCP 时间戳选项， 1 为有，0 为无。*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/

		/* 标识 TCP 连接是否启动时间戳选项 */
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/

		/* 标志接收方是否支持窗口扩大因子，只出现在 SYN 段中。 */
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/

		/* 标记是否对方提供 SACK 服务 */
		sack_ok : 3,	/* SACK seen on SYN packet		*/
		smc_ok : 1,	/* SMC seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;	/* mss requested by user in ioctl	*/
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

static inline void tcp_clear_options(struct tcp_options_received *rx_opt)
{
	rx_opt->tstamp_ok = rx_opt->sack_ok = 0;
	rx_opt->wscale_ok = rx_opt->snd_wscale = 0;
#if IS_ENABLED(CONFIG_SMC)
	rx_opt->smc_ok = 0;
#endif
}

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increase this, although since:
 *   size = TCPOLEN_SACK_BASE_ALIGNED (4) + n * TCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TCP header */
#define TCP_NUM_SACKS 4

struct tcp_request_sock_ops;

struct tcp_request_sock {
	struct inet_request_sock 	req;
	const struct tcp_request_sock_ops *af_specific;
	u64				snt_synack; /* first SYNACK sent time */
	bool				tfo_listener;
	u32				txhash;
	u32				rcv_isn;
	u32				snt_isn;
	u32				ts_off;
	u32				last_oow_ack_time; /* last SYNACK */
	u32				rcv_nxt; /* the ack # by SYNACK. For
						  * FastOpen it's the seq#
						  * after data-in-SYN.
						  */
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}


/* 该数据结构是 TCP 协议的控制块，它在inet_connection_sock结构的基础上扩展
 * 了滑动窗口协议、 拥塞控制算法等一些 TCP 的专有属性。
 */
struct tcp_sock {
	/* INET协议族面向连接的套接字结构 include/net/inet_connection_sock,
		其中包含的 struct inet_connection_sock_af_ops *icsk_af_ops数据结构，
		是套接字操作函数指针ops，各协议实例在初始化时将函数指针初始化为自己的函数实例。
	*/
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;

	/* 数据段TCP协议头的长度 */
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	
	u16	gso_segs;	/* Max number of segs per GSO packet	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	/* 用来作为快速路径的判断条件。
	 * 相当于tcp header的第3个32bits字段，只是将Reserved字段和非ACK位的flag标志字段设置为了0。
	 * __tcp_fast_path_on() 在本函数中被设置。
	 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
	u64	bytes_received;	/* RFC4898 tcpEStatsAppHCThruOctetsReceived
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
	u32	segs_in;	/* RFC4898 tcpEStatsPerfSegsIn
				 * total number of segments in.
				 */
	u32	data_segs_in;	/* RFC4898 tcpEStatsPerfDataSegsIn
				 * total number of data segments in.
				 */
	/* 等待接收的下一个TCP段的序号，每接收到一个段后设置该值 */
 	u32	rcv_nxt;	/* What we want to receive next 	*/

	/* 代表还没有读取的数据 */
	u32	copied_seq;	/* Head of yet unread data		*/

	/* 意思就是在上一个窗口更新时所接收到的确认号，也就是上一个窗口更新之后，将要发送的第一个字节的序列号。
	 */
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/

	/* 下一个准备发送的TCP段的序号，即序号等于snd_nxt的数据还没有发送 */
 	u32	snd_nxt;	/* Next sequence we send		*/
	u32	segs_out;	/* RFC4898 tcpEStatsPerfSegsOut
				 * The total number of segments sent.
				 */
	u32	data_segs_out;	/* RFC4898 tcpEStatsPerfDataSegsOut
				 * total number of data segments sent.
				 */
	u64	bytes_sent;	/* RFC4898 tcpEStatsPerfHCDataOctetsOut
				 * total number of data bytes sent.
				 */
	u64	bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
	u32	dsack_dups;	/* RFC4898 tcpEStatsStackDSACKDups
				 * total number of DSACK blocks received
				 */

	/* 滑动窗口左边界， snd_una + snd_wnd滑动窗口右边界。 */
	/* 1. 在已发送的数据中，但是还没有被确认的最小序号。注意序号等于snd_una的数据已经发送，
	 * 最想收到的确认号要大于snd_una。
	 * 2. 但是，如果发送的所有数据都已经确认，那么snd_una将等于下一个要发送的数据，即snd_una代表
	 * 的数据还没有发送。在tcp_ack()中更新。
	 * 
	 * 更新：
	 * 1. 客户端：发生在SYN段的发送过程中。tcp_connect_init()，初始化为write_seq
	 * 2. 服务器：发生在第三次握手的ACK段时。tcp_child_process()->tcp_rcv_state_process()
	 * 在数据传输过程中，应该在收到ACK后更新snd_una和snd_wnd。如果输入段中携带了ACK，
	 * 最终都会有tcp_ack()处理确认相关的内容
	 */
 	u32	snd_una;	/* First byte we want an ack for	*/

	/**
	 * 最近发送的小包(小于MSS段)的最后一个字节序号，在成功发送段后，如果报文小于MSS，即更新该字段。 
	 * 主要用来更新是否启用Nagle算法。
	 */
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */

	/* 最后一次收到ACK段的时间，用于TCP保活。 */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */

	/* 最近一次发送数据包的时间，主要用于拥塞窗口的设置 */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
	u32	last_oow_ack_time;  /* timestamp of last out-of-window ACK */
	u32	compressed_ack_rcv_nxt;

	u32	tsoffset;	/* timestamp offset */

	struct list_head tsq_node; /* anchor in tsq_tasklet.head list */
	struct list_head tsorted_sent_queue; /* time-sorted sent but un-SACKed skbs */

	/* 记录发送窗口更新时，造成窗口更新的那个数据报的第一个序号。
	 * 用来判断是否需要更新窗口。如果后续收到的ACK段大于此值，则需要更新。 */
	u32	snd_wl1;	/* Sequence for window update		*/

	/* 发送方窗口大小，即接收方提供的接收窗口大小
	 * 对snd_wnd的初始化发生在收到SYN+ACK段时
	 * 发送窗口是实现流量控制的关键，它影响的只有新数据的发送过程，
	 * 与重传无关，因为重传的数据一定是在对端接收能力之内。
	 */
	u32	snd_wnd;	/* The window we expect to receive	*/

	/* 接收方通告过的最大接收窗口值，即可以代表对端接收缓冲区的最大值 */
	u32	max_window;	/* Maximal window ever seen from peer	*/
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

	/* 滑动窗口的最大值，在TCP建立连接时，进行初始化。太大会导致滑动窗口不能在TCP首部中表示。 */
	u32	window_clamp;	/* Maximal window to advertise		*/

	/* 当前接收窗口大小的阀值，用于控制滑动窗口的缓慢增长 */
	u32	rcv_ssthresh;	/* Current window clamp			*/

	/* Information of the most recently (s)acked skb */
	struct tcp_rack {
		u64 mstamp; /* (Re)sent time of the skb */
		u32 rtt_us;  /* Associated RTT */
		u32 end_seq; /* Ending TCP sequence of the skb */
		u32 last_delivered; /* tp->delivered at last reo_wnd adj */
		u8 reo_wnd_steps;   /* Allowed reordering window */
#define TCP_RACK_RECOVERY_THRESH 16
		u8 reo_wnd_persist:5, /* No. of recovery since last adj */
		   dsack_seen:1, /* Whether DSACK seen after last adj */
		   advanced:1;	 /* mstamp advanced since last lost marking */
	} rack;
	u16	advmss;		/* Advertised MSS			*/
	u8	compressed_ack;
	u32	chrono_start;	/* Start time in jiffies of a TCP chrono */
	u32	chrono_stat[3];	/* Time in jiffies for chrono_stat stats */
	u8	chrono_type:2,	/* current chronograph type */
		rate_app_limited:1,  /* rate_{delivered,interval_us} limited? */
		fastopen_connect:1, /* FASTOPEN_CONNECT sockopt */
		fastopen_no_cookie:1, /* Allow send/recv SYN+data without a cookie */
		is_sack_reneg:1,    /* in recovery from loss with SACK reneg? */
		unused:2;

	u8	nonagle     : 4,/* Disable Nagle algorithm?             */
		thin_lto    : 1,/* Use linear timeouts for thin streams */
		recvmsg_inq : 1,/* Indicate # of bytes in queue upon recvmsg */

		/* 支持热迁移
		 * 当需要迁移的时候，为迁移的socket进入repaire模式。
		 * setsockopt的TCP_PREPAIR。
		 */
		repair      : 1,

		/* FRTO - forward RTO-Recovery，也称为F-RTO，是一种发送端的无效RTO超时重传检测方法。
		 * 虚假重传spurious retransmission。
		 * https://www.cnblogs.com/lshs/p/6038603.html
		 */
		frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */

	u8	repair_queue;
	u8	syn_data:1,	/* SYN includes data */
		syn_fastopen:1,	/* SYN includes Fast Open option */
		syn_fastopen_exp:1,/* SYN includes Fast Open exp. option */
		syn_fastopen_ch:1, /* Active TFO re-enabling probe */
		syn_data_acked:1,/* data in SYN is acked by SYN-ACK */
		save_syn:1,	/* Save headers of SYN packet */
		is_cwnd_limited:1,/* forward progress limited by snd_cwnd? */
		syn_smc:1;	/* SYN includes SMC */
	u32	tlp_high_seq;	/* snd_nxt at the time of TLP retransmit. */

	u64	tcp_wstamp_ns;	/* departure time for next sent data packet */
	u64	tcp_clock_cache; /* cache last tcp_clock_ns() (see tcp_mstamp_refresh()) */

/* RTT measurement */
	u64	tcp_mstamp;	/* most recent packet received/sent */
	/* 经过平滑后的RTT值，它代表当前的RTT值，每收到一个ack更新一次。
	 * 为了避免浮点运算，它是实际RTT值的8倍。
	 */
	u32	srtt_us;	/* smoothed round trip time << 3 in usecs */

	/* 为RTT的平均偏差，用来衡量RTT的抖动，每收到一个ack更新一次。 */
	u32	mdev_us;	/* medium deviation			*/

	/* 上一个RTT内的最大mdev_us， 代表上个RTT内时延的波动情况，有效期为一个RTT。 */
	u32	mdev_max_us;	/* maximal mdev for the last rtt period	*/

	/* 为mdev_max的平滑值，可生可降，代表连接的抖动情况，在连接断开前都有效。*/
	u32	rttvar_us;	/* smoothed mdev_max			*/

	/* 用于判断当前采样是否处于RTT时间窗内。
	 * 因为linux在一个RTT时间窗内部更新状态变量的方式和RTT时间窗结束更新状态变量的方式不同。
	 * 1. 当snd.una <= rtt_seq，说明之前发送的数据包还没有收到ack，即当前还处于RTT时间窗内部。
	 * 2. 当snd.una > rtt_seq, 说明之前发送的数据包已经收到了对应的ack确认，那么一个RTT时间窗结束，
	 *    并把rtt_seq设置为snd.nxt继续下一个RTT时间窗的处理。
	 */
	u32	rtt_seq;	/* sequence number to update rttvar	*/
	struct  minmax rtt_min;

	/* 发送方已经发送出去，但是，还未得到ack的TCP段的数目（不包含重传）, packets_out = SND.NXT - SND.UNA。
	 * 该值时动态的，当有新的段发出或者有新的确认收到都会增加或减少该值。
	 */
	u32	packets_out;	/* Packets which are "in flight"	*/

	/* 因为重传才发送出去，但是，还没有被确认的段的数量。*/
	u32	retrans_out;	/* Retransmitted packets out		*/

	u32	max_packets_out;  /* max packets_out in last window */
	u32	max_packets_seq;  /* right edge of max_packets_out flight */

	u16	urg_data;	/* Saved octet of OOB data and control flags */

	/* 显式拥塞通知状态位，如TCP_ECN_OK */
	u8	ecn_flags;	/* ECN status bits.			*/

	/* TCP_KEEPCNT - SO_KEEPALIVE 设置在断开连接之前通过套接字发送多少个保存连接活动的探测数据段。 */
	u8	keepalive_probes; /* num of allowed keep alive probes	*/
	u32	reordering;	/* Packet reordering metric.		*/
	u32	reord_seen;	/* number of data packet reordering events */
	u32	snd_up;		/* Urgent pointer		*/

/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
 	/* 收到对方的tcp option设置。 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	/* 拥塞控制时，慢启动的阈值 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*/

	/* 发送的拥塞窗口大小 */
 	u32	snd_cwnd;	/* Sending congestion window		*/
	
	/* 
	 * 自从上次调整拥塞窗口到目前为止接收到的总 ACK 段数。
	 * 如果该字段为零，则说明已经调整了拥塞窗口，且到目前
	 * 为止还没有接收到 ACK 段。调整拥塞窗口之后，每接收到
	 * 一个 ACK， ACK 段就会使 snd_cwnd_cnt 加 1。 
	 */
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/

	/* 允许的最大拥塞窗口值，初始值为65535 */
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */

	/* 从发送队列发出而未得到确认的段数，用于在检验拥塞窗口时调节拥塞窗口 */
	u32	snd_cwnd_used;

	/* 记录最近一次检验拥塞窗口的时间
	 * 在拥塞期间，接收到 ACK 后会进行
	 * 拥塞窗口的检验。而在非拥塞期间，为了防止由于应用
	 * 程序限制而造成拥塞窗口失效，因此在成功发送段后，
	 * 如果有必要也会检验拥塞窗口。 
	 */
	u32	snd_cwnd_stamp;

	/* 在进入 Recovery 状态时的拥塞窗口。表示prr算法中的RecoverFS的值 */
	u32	prior_cwnd;	/* cwnd right before starting loss recovery */

	/* 在Recovery状态下，已经被接收方从网络中拿走的数据量。
	 * 用于计算数据离开网络的速度。
	 */
	u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
	/* 在Recovery状态下，一共发送的数量量。
	 * 用于计算数据进入网络的速度。
	 */
	u32	prr_out;	/* Total number of pkts sent during Recovery. */

	u32	delivered;	/* Total data packets delivered incl. rexmits */
	u32	delivered_ce;	/* Like the above but only ECE marked packets */
	u32	lost;		/* Total data packets lost incl. rexmits */
	
	u32	app_limited;	/* limited until "delivered" reaches this val */
	u64	first_tx_mstamp;  /* start of window send phase */
	u64	delivered_mstamp; /* time we reached "delivered" */
	u32	rate_delivered;    /* saved rate sample: packets delivered */
	u32	rate_interval_us;  /* saved rate sample: time elapsed */

	/* 当前接收窗口大小 */
 	u32	rcv_wnd;	/* Current receiver window		*/

	/* 已经加入接收队列中的最后一个字节的序号 
	 * write/send等写系统调用一旦返回成功，说明数据已被TCP协议接收，这时
	 * 就要为每个数据分配一个序号，write_seq就是下一个要分配的序号。其初始值
	 * 由secure_tcp_sequence_number()基于算法生成。注意 等于write_seq的序号还没有被分配。
	 */
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */

	u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */

	/* 一般表示已经真正发送出去的最后一个字节序号，有时也表示期望发出去的最后一个字节的序号 */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */

	/* 记录发送后再传输过程中丢失的段的数量，因为tcp没有一种机制可以准确地知道发出去的段是否真的丢了，所以
	 * 这只是一个预估值。
	 *
	 * 一般是根据选择恢复方法来确定丢失的段数量。
	 * 例如：
	 * 0. Normal(non-FACK, non-RACK) :
	 *	1. 未启用SACK, dup ACK表示ACK seq相同的段。
	 *	2. 启用SACK, 携带SACK的ACK段也被认为是重复ACK。
	 *	设 dupthresh = 3，SACKed_count = 6，从 unAcked 包开始的 SACKed_count - dupthresh 个数据包，
	 *	即 3 个数据包会被标记为 LOST。
	 * 1. FACK - forward ack:
	 *	它假设网络不会使数据包乱序，因此收到最大的被 SACK 的数据包之前，FACK 均认为是丢失的。
	 * 	FACK 模式下，重传时机为 被 SACKed 的包数 + 空洞数 > dupthresh。
	 * 2. RACK - recent ack:
	 * 	如果数据包 p1 在 p2 之前发送，没有收到 p1 的确认，当收到 p2 的 Sack 时，推断 p1 丢包。
	 */
	u32	lost_out;	/* Lost packets			*/

	/*
	 * 启用SACK时；表示已经被SACK选项确认的段的数量。
	 * 不启用SACK时：表示接收到的重复ACK的次数，因为重复ACK不会自动发送，一定是对端收到了数据包。
	 *	该值在接收到确认新数据段时被清除
	 */
	u32	sacked_out;	/* SACK'd packets			*/

	struct hrtimer	pacing_timer;
	struct hrtimer	compressed_ack_timer;

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;
	struct sk_buff *retransmit_skb_hint;

	/* 乱序数据包队列 */
	/* OOO segments go in this rbtree. Socket lock must be held. */
	struct rb_root	out_of_order_queue;
	struct sk_buff	*ooo_last_skb; /* cache rb_last(out_of_order_queue) */

	/* SACKs data, these 2 need to be together (see tcp_options_write) */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4];

	struct sk_buff *highest_sack;   /* skb just after the highest
					 * skb with SACKed bit set
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

	int     lost_cnt_hint;

	/* 在启用RTO算法的情况下，路径MTU探测成功，进入拥塞控制状态时保存的ssthresh值。
	 * 主要用于撤销拥塞窗口 undo_xxx() 时，恢复慢启动阀值
	 */
	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/

	/* 记录发生拥塞时的snd_nxt，标识重传队列的尾部。
	 * 也是(recovery point + 1)，即在进行RTO超时重传时，当前已发送的数据中的最高序列号。
	 */
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	/**
	 * 主动连接时，记录第一个SYN段的发送时间，用来检测ACK序号是否回绕。 
	 * 在数据传输阶段，当发送超时重传时，记录上次重传阶段第一个重传段的发送时间，用于判断是否可以进行拥塞撤销。
	 */
	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	/* 在使用 F-RTO 算法进行发送超时处理，或进入 Recovery 进行重传，
	 * 或进入 Loss 开始慢启动时，记录当时的 SND.UNA, 标记重传起始点。
	 * 它是检测是否可以进行拥塞控制撤销的条件之一，一般在完成
	 * 拥塞撤销操作或进入拥塞控制 Loss 状态后会清零。 
	 */
	u32	undo_marker;	/* snd_una upon a new recovery episode. */

	/* 在恢复拥塞控制之前可进行撤销的重传段数。在进入 F-TRO 算法或
	 * 拥塞状态 Loss 时清零，在重传时计数，是检测是否可以进行拥塞
	 * 撤销的条件之一。 */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u64	bytes_retrans;	/* RFC4898 tcpEStatsPerfOctetsRetrans
				 * Total data bytes retransmitted
				 */
	u32	total_retrans;	/* Total retransmits for entire connection */

	/* 紧急数据的序号，由所在段的序号和紧急指针相加而得到 */
	u32	urg_seq;	/* Seq of received urgent pointer */

	/* 在TCP开始传送连接是否保存活动的探测数据段之前，连接处于空闲状态的时间值(秒)，默认为2小时。需设置SO_KEEPLIVE才有效 */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */

	/* 设定在两次传送探测连接保存活动数据段之间要等待多少秒。初始值为75秒 */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

	/* 指定处于FIN_WAIT2状态的孤立套接字还应报纸存活多少时间。如果其值为0，则关闭选项。
	linux使用常规方式处理FIN_WAIT_2和TIME_WAIT状态。如果值小于0，则套接字立即从FIN_WAIT_2
	状态进入CLOSE状态，不经过TIME_WAIT。*/
	int			linger2;


/* Sock_ops bpf program related variables */
#ifdef CONFIG_BPF
	u8	bpf_sock_ops_cb_flags;  /* Control calling BPF programs
					 * values defined in uapi/linux/tcp.h
					 */
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) (TP->bpf_sock_ops_cb_flags & ARG)
#else
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) 0
#endif

/* 存储接收方的RTT估算值，用于限制调整TCP接收缓冲区空间的间隔时间不能小于RTT */
/* Receiver side RTT estimation */
	u32 rcv_rtt_last_tsecr;
	struct {
		u32	rtt_us;
		u32	seq;
		u64	time;
	} rcv_rtt_est;

/* 用来调整TCP接收缓冲空间和接收窗口大小，也用于实现通过调节接收窗口来进行流量控制的功能。
每次将数据复制到用户空间，都计算新的TCP接收缓冲空间大小。 */
/* Receiver queue space */
	struct {
		u32	space;
		u32	seq;
		u64	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;
	u32	mtu_info; /* We received an ICMP_FRAG_NEEDED / ICMPV6_PKT_TOOBIG
			   * while socket was owned by user.
			   */

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	__rcu *md5sig_info;
#endif

/* TCP fastopen related information */
	/* 与 TCP Fast Open 相关的信息 */
	struct tcp_fastopen_request *fastopen_req;
	/* fastopen_rsk points to request_sock that resulted in this big
	 * socket. Used to retransmit SYNACKs etc.
	 */
	struct request_sock *fastopen_rsk;
	u32	*saved_syn;
};

enum tsq_enum {
	TSQ_THROTTLED,
	TSQ_QUEUED,
	TCP_TSQ_DEFERRED,	   /* tcp_tasklet_func() found socket was owned */
	TCP_WRITE_TIMER_DEFERRED,  /* tcp_write_timer() found socket was owned */
	TCP_DELACK_TIMER_DEFERRED, /* tcp_delack_timer() found socket was owned */
	TCP_MTU_REDUCED_DEFERRED,  /* tcp_v{4|6}_err() could not call
				    * tcp_v{4|6}_mtu_reduced()
				    */
};

enum tsq_flags {
	TSQF_THROTTLED			= (1UL << TSQ_THROTTLED),
	TSQF_QUEUED			= (1UL << TSQ_QUEUED),
	TCPF_TSQ_DEFERRED		= (1UL << TCP_TSQ_DEFERRED),
	TCPF_WRITE_TIMER_DEFERRED	= (1UL << TCP_WRITE_TIMER_DEFERRED),
	TCPF_DELACK_TIMER_DEFERRED	= (1UL << TCP_DELACK_TIMER_DEFERRED),
	TCPF_MTU_REDUCED_DEFERRED	= (1UL << TCP_MTU_REDUCED_DEFERRED),
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
#define tw_rcv_nxt tw_sk.__tw_common.skc_tw_rcv_nxt
#define tw_snd_nxt tw_sk.__tw_common.skc_tw_snd_nxt
	u32			  tw_rcv_wnd;
	u32			  tw_ts_offset;
	u32			  tw_ts_recent;

	/* The time we sent the last out-of-window ACK: */
	u32			  tw_last_oow_ack_time;

	int			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key	  *tw_md5_key;
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

static inline bool tcp_passive_fastopen(const struct sock *sk)
{
	return (sk->sk_state == TCP_SYN_RECV &&
		tcp_sk(sk)->fastopen_rsk != NULL);
}

static inline void fastopen_queue_tune(struct sock *sk, int backlog)
{
	struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;
	int somaxconn = READ_ONCE(sock_net(sk)->core.sysctl_somaxconn);

	queue->fastopenq.max_qlen = min_t(unsigned int, backlog, somaxconn);
}

static inline void tcp_move_syn(struct tcp_sock *tp,
				struct request_sock *req)
{
	tp->saved_syn = req->saved_syn;
	req->saved_syn = NULL;
}

static inline void tcp_saved_syn_free(struct tcp_sock *tp)
{
	kfree(tp->saved_syn);
	tp->saved_syn = NULL;
}

struct sk_buff *tcp_get_timestamping_opt_stats(const struct sock *sk);

static inline u16 tcp_mss_clamp(const struct tcp_sock *tp, u16 mss)
{
	/* We use READ_ONCE() here because socket might not be locked.
	 * This happens for listeners.
	 */
	u16 user_mss = READ_ONCE(tp->rx_opt.user_mss);

	return (user_mss && user_mss < mss) ? user_mss : mss;
}
#endif	/* _LINUX_TCP_H */
