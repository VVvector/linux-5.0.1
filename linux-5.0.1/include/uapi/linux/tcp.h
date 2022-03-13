/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
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
#ifndef _UAPI_LINUX_TCP_H
#define _UAPI_LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_cpu_to_be32(0x00800000),
	TCP_FLAG_ECE = __constant_cpu_to_be32(0x00400000),
	TCP_FLAG_URG = __constant_cpu_to_be32(0x00200000),
	TCP_FLAG_ACK = __constant_cpu_to_be32(0x00100000),
	TCP_FLAG_PSH = __constant_cpu_to_be32(0x00080000),
	TCP_FLAG_RST = __constant_cpu_to_be32(0x00040000),
	TCP_FLAG_SYN = __constant_cpu_to_be32(0x00020000),
	TCP_FLAG_FIN = __constant_cpu_to_be32(0x00010000),
	TCP_RESERVED_BITS = __constant_cpu_to_be32(0x0F000000),
	TCP_DATA_OFFSET = __constant_cpu_to_be32(0xF0000000)
}; 

/*
 * TCP general constants
 */
#define TCP_MSS_DEFAULT		 536U	/* IPv4 (RFC1122, RFC2581) */
#define TCP_MSS_DESIRED		1220U	/* IPv6 (tunneled), EDNS0 (RFC3226) */

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */
#define TCP_THIN_LINEAR_TIMEOUTS 16      /* Use linear timeouts for thin streams*/
#define TCP_THIN_DUPACK         17      /* Fast retrans. after 1 dupack */
#define TCP_USER_TIMEOUT	18	/* How long for loss retry before timeout */

/*
 * setsockopt设置TCP_PREPAIR选项
 * 比如docker等容器在不同的机器之间无缝迁移(可能由于调度，维护，交割等原因)，是常见的需求场景
 * 但是又希望不能中断服务，因此各种虚拟机和容器的热迁移就得到很多关注。
 * 进入repair模式的要求:
 *   1. 需要CAP_NET_ADMIN， 用户命名空间需要有网络管理能力
 *   2. socket处于CLOSE状态或ESTABLISHED状态
 */
#define TCP_REPAIR		19	/* TCP sock is under repair right now */
#define TCP_REPAIR_QUEUE	20
#define TCP_QUEUE_SEQ		21
#define TCP_REPAIR_OPTIONS	22
#define TCP_FASTOPEN		23	/* Enable FastOpen on listeners */
#define TCP_TIMESTAMP		24
#define TCP_NOTSENT_LOWAT	25	/* limit number of unsent bytes in write queue */
#define TCP_CC_INFO		26	/* Get Congestion Control (optional) info */
#define TCP_SAVE_SYN		27	/* Record SYN headers for new connections */
#define TCP_SAVED_SYN		28	/* Get SYN headers recorded for connection */
#define TCP_REPAIR_WINDOW	29	/* Get/set window parameters */
#define TCP_FASTOPEN_CONNECT	30	/* Attempt FastOpen with connect */
#define TCP_ULP			31	/* Attach a ULP to a TCP connection */
#define TCP_MD5SIG_EXT		32	/* TCP MD5 Signature with extensions */
#define TCP_FASTOPEN_KEY	33	/* Set the key for Fast Open (cookie) */
#define TCP_FASTOPEN_NO_COOKIE	34	/* Enable TFO without a TFO cookie */
#define TCP_ZEROCOPY_RECEIVE	35
#define TCP_INQ			36	/* Notify bytes available to read as a cmsg on read */

#define TCP_CM_INQ		TCP_INQ

#define TCP_REPAIR_ON		1
#define TCP_REPAIR_OFF		0
#define TCP_REPAIR_OFF_NO_WP	-1	/* Turn off without window probes */

struct tcp_repair_opt {
	__u32	opt_code;
	__u32	opt_val;
};

struct tcp_repair_window {
	__u32	snd_wl1;
	__u32	snd_wnd;
	__u32	max_window;

	__u32	rcv_wnd;
	__u32	rcv_wup;
};

enum {
	TCP_NO_QUEUE,
	TCP_RECV_QUEUE,
	TCP_SEND_QUEUE,
	TCP_QUEUES_NR,
};

/* for TCP_INFO socket option */
#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8 /* ECN was negociated at TCP session init */
#define TCPI_OPT_ECN_SEEN	16 /* we received at least one packet with ECT */
#define TCPI_OPT_SYN_DATA	32 /* SYN-ACK acked data in SYN sent or rcvd */

/*
 * 在tcp建立连接后，tcp本身有一个状态机的跳转来处理各种丢包，包乱序等异常情况。
 */
enum tcp_ca_state {
	/*
	 * 当网络中没有发送丢包，也就不需要重传，sender按照慢启动或者拥塞避免算法处理到来的ACK。
	 */
	/* Normal state, no dubious events, fast path */
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)

	/*
	 * 当sender检测到dupack或者sack，将会转移到Disorder状态，当处于这个状态时，cwnd将维持不变。
	 * 每收到一个dupack或sack，发送方将发送一个新包。
	 */
	/* In all the respects it is "Open", but requires a bit more attention.
	 * It is entered when we see some SACKs or dupacks. It is split of "Open"
	 * mainly to move some processing from fast path to slow one.
	 */
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)

	/*
	 * 当sender收到ACK包含显式拥塞通知ECN，这个ECN由路由器写在IP头中，告诉TCP sender网络拥塞，
	 * sender不会立马降低cwnd，而是根据 快速恢复算法(例如，PRR) 进行降窗，直到减少到新的ssthresh
	 *（不同的TCP CC算法对应的ssthresh不同，例如，newreno：0.5, cubic:717/1024）。当cwnd正在
	 * 减少，网络中又没有重传包时，这个状态就叫CWR，CWR可以被Recovery 或者 Loss中断。
	 */
	/* CWND was reduced due to some Congestion Notification event. It can be ECN,
	 * ICMP source quench, local device congestion.
	 */
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)

	/*
	 * 当sender因为 快速重传机制(接收到一定数量的dup ack时) 触发丢包时，sender会重传第一个未被ACK的包，
	 * 并进入Recovery状态。
	 * 在Recovery状态期间，cwnd的处理和CWR大致一样，要么重传标记为lost的包，要么根据包守恒原则
	 * 发送新包，直到网络中所有的包都被ACK，才会退出Recovery进入open状态，Recovery状态可以被loss
	 * 状态打断。重传超时时有可能中断Recovery状态。
	 */
	/* CWND was reduced, we are fast-retransmitting. */
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)

	/*
	 * 当RTO后，tcp sender进入loss状态，所有在网络中的包被标记为lost，cwnd重置为1，通过slow start
	 * 重新增加cwnd。Loss与Recovery状态的不同点在于cwnd会重置为1，但是，Recovery不会。Recvoery状态下
	 * 拥塞控制通过 快速恢复算法 逐步降低cwnd至sshthresh。Loss状态不能被其他任何状态中断，只有当网络
	 * 中所有的包都被成功ACK后，才能重新进入Open状态。例如，快速重传不能在Loss状态期间被触发，这和
	 * NewReno规范一致的。
	 * 当一个RTO超时，或者接收到的ACK的确认已经被先前的SACK确认过，则意味着我们记录的SACK信息不能
	 * 反映接收方实际的状态，此时都会进入Loss状态，参见超时重传定时器例程和tcp_check_sack_reneging()。
	 */
	/* CWND was reduced due to RTO timeout or SACK reneging */
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info {
	/* tcp状态 */
	__u8	tcpi_state;
	/* tcp拥塞状态 */
	__u8	tcpi_ca_state;
	/* 超时重传次数 */
	__u8	tcpi_retransmits;
	/* 持续定时器或者保活定时器发送且未确认的段数 */
	__u8	tcpi_probes;
	/* 退避指数 */
	__u8	tcpi_backoff;
	/* 时间戳，SACK, 窗口扩大，ECN选项 */
	__u8	tcpi_options;
	/* 发送，接收的窗口扩大因子 */
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	/* app受限，即app发送不够快，未占满网络带宽。 */
	__u8	tcpi_delivery_rate_app_limited:1;

	/* 超时时间，us */
	__u32	tcpi_rto;
	/* 延迟确认ack的估值, us */
	__u32	tcpi_ato;
	/* 本端MSS */
	__u32	tcpi_snd_mss;
	/* 对端MSS */
	__u32	tcpi_rcv_mss;

	/* 未确认的数据段数，或者current listen backlog */
	__u32	tcpi_unacked;
	/* SACKed的段数，或者listen backlog set in listen() */
	__u32	tcpi_sacked;
	/* 丢失且未恢复的数据段数 */
	__u32	tcpi_lost;
	/* 重传且未确认的数据段数 */
	__u32	tcpi_retrans;
	/* FACKed的数据段数 */
	__u32	tcpi_fackets;

	/* Times. /ms */
	/* 最近一次发送数据包在多久之前 */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	/* 最近一次接收数据包在多久之前 */
	__u32	tcpi_last_data_recv;
	/* 最近一次接收ack包在多久之前 */
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	/* 没有丢包时，可以重新排序的数据段数。 */
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;

	__u64	tcpi_pacing_rate;
	__u64	tcpi_max_pacing_rate;
	__u64	tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	__u64	tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	__u32	tcpi_segs_out;	     /* RFC4898 tcpEStatsPerfSegsOut */
	__u32	tcpi_segs_in;	     /* RFC4898 tcpEStatsPerfSegsIn */

	__u32	tcpi_notsent_bytes;
	__u32	tcpi_min_rtt;
	__u32	tcpi_data_segs_in;	/* RFC4898 tcpEStatsDataSegsIn */
	__u32	tcpi_data_segs_out;	/* RFC4898 tcpEStatsDataSegsOut */

	/* tcp的发送速率 */
	__u64   tcpi_delivery_rate;

	/* 几种chrono timer的时间 __TCP_CHRONO_MAX */
	__u64	tcpi_busy_time;      /* Time (usec) busy sending data */
	__u64	tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
	__u64	tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

	__u32	tcpi_delivered;
	__u32	tcpi_delivered_ce;

	__u64	tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	__u64	tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
	__u32	tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
	__u32	tcpi_reord_seen;     /* reordering events seen */
};

/* netlink attributes types for SCM_TIMESTAMPING_OPT_STATS */
enum {
	TCP_NLA_PAD,
	TCP_NLA_BUSY,		/* Time (usec) busy sending data */
	TCP_NLA_RWND_LIMITED,	/* Time (usec) limited by receive window */
	TCP_NLA_SNDBUF_LIMITED,	/* Time (usec) limited by send buffer */
	TCP_NLA_DATA_SEGS_OUT,	/* Data pkts sent including retransmission */
	TCP_NLA_TOTAL_RETRANS,	/* Data pkts retransmitted */
	TCP_NLA_PACING_RATE,    /* Pacing rate in bytes per second */
	TCP_NLA_DELIVERY_RATE,  /* Delivery rate in bytes per second */
	TCP_NLA_SND_CWND,       /* Sending congestion window */
	TCP_NLA_REORDERING,     /* Reordering metric */
	TCP_NLA_MIN_RTT,        /* minimum RTT */
	TCP_NLA_RECUR_RETRANS,  /* Recurring retransmits for the current pkt */
	TCP_NLA_DELIVERY_RATE_APP_LMT, /* delivery rate application limited ? */
	TCP_NLA_SNDQ_SIZE,	/* Data (bytes) pending in send queue */
	TCP_NLA_CA_STATE,	/* ca_state of socket */
	TCP_NLA_SND_SSTHRESH,	/* Slow start size threshold */
	TCP_NLA_DELIVERED,	/* Data pkts delivered incl. out-of-order */
	TCP_NLA_DELIVERED_CE,	/* Like above but only ones w/ CE marks */
	TCP_NLA_BYTES_SENT,	/* Data bytes sent including retransmission */
	TCP_NLA_BYTES_RETRANS,	/* Data bytes retransmitted */
	TCP_NLA_DSACK_DUPS,	/* DSACK blocks received */
	TCP_NLA_REORD_SEEN,	/* reordering events seen */
	TCP_NLA_SRTT,		/* smoothed RTT in usecs */
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

/* tcp_md5sig extension flags for TCP_MD5SIG_EXT */
#define TCP_MD5SIG_FLAG_PREFIX		1	/* address prefix length */

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u8	tcpm_flags;				/* extension flags */
	__u8	tcpm_prefixlen;				/* address prefix */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

/* INET_DIAG_MD5SIG */
struct tcp_diag_md5sig {
	__u8	tcpm_family;
	__u8	tcpm_prefixlen;
	__u16	tcpm_keylen;
	__be32	tcpm_addr[4];
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];
};

/* setsockopt(fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, ...) */

struct tcp_zerocopy_receive {
	__u64 address;		/* in: address of mapping */
	__u32 length;		/* in/out: number of bytes to map/mapped */
	__u32 recv_skip_hint;	/* out: amount of bytes to skip */
};
#endif /* _UAPI_LINUX_TCP_H */
