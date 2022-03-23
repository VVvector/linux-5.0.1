/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the AF_INET socket handler.
 *
 * Version:	@(#)sock.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *              Steve Whitehouse:       Default routines for sock_ops
 *              Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *              			protinfo be just a void pointer, as the
 *              			protocol specific parts were moved to
 *              			respective headers and ipv4/v6, etc now
 *              			use private slabcaches for its socks
 *              Pedro Hortas	:	New flags field for socket options
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _SOCK_H
#define _SOCK_H

#include <linux/hardirq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/bitops.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>	/* struct sk_buff */
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/page_counter.h>
#include <linux/memcontrol.h>
#include <linux/static_key.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/cgroup-defs.h>
#include <linux/rbtree.h>
#include <linux/filter.h>
#include <linux/rculist_nulls.h>
#include <linux/poll.h>

#include <linux/atomic.h>
#include <linux/refcount.h>
#include <net/dst.h>
#include <net/checksum.h>
#include <net/tcp_states.h>
#include <linux/net_tstamp.h>
#include <net/smc.h>
#include <net/l3mdev.h>

/*
 * This structure really needs to be cleaned up.
 * Most of it is for TCP, and not used by any of
 * the other protocols.
 */

/* Define this to get the SOCK_DBG debugging facility. */
#define SOCK_DEBUGGING
#ifdef SOCK_DEBUGGING
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)
#else
/* Validate arguments and do nothing */
static inline __printf(2, 3)
void SOCK_DEBUG(const struct sock *sk, const char *msg, ...)
{
}
#endif

/* This is the per-socket lock.  The spinlock provides a synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 */
 /* 保护socket的锁结构 */
typedef struct {
	/* 同步进程和下半部的自旋锁 */
	spinlock_t		slock;

	/* 实际只有两个值，0：表示未被用户进程锁定，1：表示被用户进程锁定。 */
	int			owned;

	/* 当软中断锁定socket时，用户进程不能获取锁，进入此等待队列。 */
	wait_queue_head_t	wq;
	/*
	 * We express the mutex-alike socket_lock semantics
	 * to the lock validator by explicitly managing
	 * the slock as a lock variant (in addition to
	 * the slock itself):
	 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} socket_lock_t;

struct sock;
struct proto;
struct net;

typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

/**
 *	struct sock_common - minimal network layer representation of sockets
 *	@skc_daddr: Foreign IPv4 addr
 *	@skc_rcv_saddr: Bound local IPv4 addr
 *	@skc_hash: hash value used with various protocol lookup tables
 *	@skc_u16hashes: two u16 hash values used by UDP lookup tables
 *	@skc_dport: placeholder for inet_dport/tw_dport
 *	@skc_num: placeholder for inet_num/tw_num
 *	@skc_family: network address family
 *	@skc_state: Connection state
 *	@skc_reuse: %SO_REUSEADDR setting
 *	@skc_reuseport: %SO_REUSEPORT setting
 *	@skc_bound_dev_if: bound device index if != 0
 *	@skc_bind_node: bind hash linkage for various protocol lookup tables
 *	@skc_portaddr_node: second hash linkage for UDP/UDP-Lite protocol
 *	@skc_prot: protocol handlers inside a network family
 *	@skc_net: reference to the network namespace of this socket
 *	@skc_node: main hash linkage for various protocol lookup tables
 *	@skc_nulls_node: main hash linkage for TCP/UDP/UDP-Lite protocol
 *	@skc_tx_queue_mapping: tx queue number for this connection
 *	@skc_rx_queue_mapping: rx queue number for this connection
 *	@skc_flags: place holder for sk_flags
 *		%SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE,
 *		%SO_OOBINLINE settings, %SO_TIMESTAMPING settings
 *	@skc_incoming_cpu: record/match cpu processing incoming packets
 *	@skc_refcnt: reference count
 *
 *	This is the minimal network layer representation of sockets, the header
 *	for struct sock and struct inet_timewait_sock.
 */
 /* socket的最小公共组成部分。由sock和inet_timewait_sock结构前面相同部分构成。 */
struct sock_common {
	/* skc_daddr and skc_rcv_saddr must be grouped on a 8 bytes aligned
	 * address on 64bit arches : cf INET_MATCH()
	 */
	union {
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;
			__be32	skc_rcv_saddr;
		};
	};
	union  {
		unsigned int	skc_hash;
		__u16		skc_u16hashes[2];
	};
	/* skc_dport && skc_num must be grouped as well */
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;
			__u16	skc_num;
		};
	};

	unsigned short		skc_family; /* 所属协议族 */
	volatile unsigned char	skc_state; /* 连接状态 */
	unsigned char		skc_reuse:4; /* 是否可以重用地址和端口 */
	unsigned char		skc_reuseport:1; /* 是否可以重用端口，例如tcp和udp同时使用一个端口。 */
	unsigned char		skc_ipv6only:1;
	unsigned char		skc_net_refcnt:1;
	int			skc_bound_dev_if;
	union {
		struct hlist_node	skc_bind_node;
		struct hlist_node	skc_portaddr_node;
	};
	struct proto		*skc_prot;
	possible_net_t		skc_net;

#if IS_ENABLED(CONFIG_IPV6)
	struct in6_addr		skc_v6_daddr;
	struct in6_addr		skc_v6_rcv_saddr;
#endif

	atomic64_t		skc_cookie;

	/* following fields are padding to force
	 * offset(struct sock, sk_refcnt) == 128 on 64bit arches
	 * assuming IPV6 is enabled. We use this padding differently
	 * for different kind of 'sockets'
	 */
	union {
		unsigned long	skc_flags;
		struct sock	*skc_listener; /* request_sock */
		struct inet_timewait_death_row *skc_tw_dr; /* inet_timewait_sock */
	};
	/*
	 * fields between dontcopy_begin/dontcopy_end
	 * are not copied in sock_copy()
	 */
	/* private: */
	int			skc_dontcopy_begin[0];
	/* public: */
	union {
		struct hlist_node	skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	unsigned short		skc_tx_queue_mapping;
#ifdef CONFIG_XPS
	unsigned short		skc_rx_queue_mapping;
#endif
	union {
		int		skc_incoming_cpu;
		u32		skc_rcv_wnd;
		u32		skc_tw_rcv_nxt; /* struct tcp_timewait_sock  */
	};

	refcount_t		skc_refcnt;
	/* private: */
	int                     skc_dontcopy_end[0];
	union {
		u32		skc_rxhash;
		u32		skc_window_clamp;
		u32		skc_tw_snd_nxt; /* struct tcp_timewait_sock */
	};
	/* public: */
};

/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_kern_sock: True if sock is using kernel lock classes
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_wq: sock wait queue and async head
  *	@sk_rx_dst: receive input route used by early demux
  *	@sk_dst_cache: destination cache
  *	@sk_dst_pending_confirm: need to confirm neighbour
  *	@sk_policy: flow policy
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_tsq_flags: TCP Small Queues flags
  *	@sk_write_queue: Packet sending queue
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_napi_id: id of the last napi context to receive data for sk
  *	@sk_ll_usec: usecs to busypoll when there is no data
  *	@sk_allocation: allocation mode
  *	@sk_pacing_rate: Pacing rate (if supported by transport/packet scheduler)
  *	@sk_pacing_status: Pacing status (requested, handled by sch_fq)
  *	@sk_max_pacing_rate: Maximum pacing rate (%SO_MAX_PACING_RATE)
  *	@sk_sndbuf: size of send buffer in bytes
  *	@__sk_flags_offset: empty field used to determine location of bitfield
  *	@sk_padding: unused element for alignment
  *	@sk_no_check_tx: %SO_NO_CHECK setting, set checksum in TX packets
  *	@sk_no_check_rx: allow zero checksum in RX packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_route_nocaps: forbidden route capabilities (e.g NETIF_F_GSO_MASK)
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_gso_max_size: Maximum GSO segment size to build
  *	@sk_gso_max_segs: Maximum number of GSO segments
  *	@sk_pacing_shift: scaling factor for TCP Small Queues
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt,
  *			  IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a
  *		      persistent failure not just 'timed out'
  *	@sk_drops: raw/udp drops counter
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_uid: user id of owner
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peer_pid: &struct pid for this socket's peer
  *	@sk_peer_cred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_txhash: computed flow hash for use on transmit
  *	@sk_filter: socket filtering instructions
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_stamp_seq: lock for accessing sk_stamp on 32 bit architectures only
  *	@sk_tsflags: SO_TIMESTAMPING socket options
  *	@sk_tskey: counter to disambiguate concurrent tstamp requests
  *	@sk_zckey: counter to order MSG_ZEROCOPY notifications
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_frag: cached page frag
  *	@sk_peek_off: current peek_offset value
  *	@sk_send_head: front of stuff to transmit
  *	@sk_security: used by security modules
  *	@sk_mark: generic packet mark
  *	@sk_cgrp_data: cgroup data for this cgroup
  *	@sk_memcg: this socket's memory cgroup association
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
  *	@sk_reuseport_cb: reuseport group container
  *	@sk_rcu: used during RCU grace period
  *	@sk_clockid: clockid used by time-based scheduling (SO_TXTIME)
  *	@sk_txtime_deadline_mode: set deadline mode for SO_TXTIME
  *	@sk_txtime_unused: unused txtime flags
  */

/*
 * sock 结构是比较通用的网络层描述块，构成 传输控制块层 的基础，与具体的协议族无关。
 * 它描述了各协议族的公共信息，因此不能直接作为传输层控制块来使用。不同协议族的
 * 传输层在使用该结构的时候都会对其进行拓展，来适合各自的传输特性。例如， inet_sock
 * 结构由 sock 结构及其它特性组成，构成了 IPV4 协议族传输控制块的基础。
 */
struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	 /* 公共信息，必须放在最前面。 */
	struct sock_common	__sk_common;
#define sk_node			__sk_common.skc_node
#define sk_nulls_node		__sk_common.skc_nulls_node
#define sk_refcnt		__sk_common.skc_refcnt
#define sk_tx_queue_mapping	__sk_common.skc_tx_queue_mapping
#ifdef CONFIG_XPS
#define sk_rx_queue_mapping	__sk_common.skc_rx_queue_mapping
#endif

#define sk_dontcopy_begin	__sk_common.skc_dontcopy_begin
#define sk_dontcopy_end		__sk_common.skc_dontcopy_end
#define sk_hash			__sk_common.skc_hash
#define sk_portpair		__sk_common.skc_portpair
#define sk_num			__sk_common.skc_num
#define sk_dport		__sk_common.skc_dport
#define sk_addrpair		__sk_common.skc_addrpair
#define sk_daddr		__sk_common.skc_daddr
#define sk_rcv_saddr		__sk_common.skc_rcv_saddr
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_reuse		__sk_common.skc_reuse
#define sk_reuseport		__sk_common.skc_reuseport
#define sk_ipv6only		__sk_common.skc_ipv6only
#define sk_net_refcnt		__sk_common.skc_net_refcnt
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_prot			__sk_common.skc_prot
#define sk_net			__sk_common.skc_net
#define sk_v6_daddr		__sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr	__sk_common.skc_v6_rcv_saddr
#define sk_cookie		__sk_common.skc_cookie
#define sk_incoming_cpu		__sk_common.skc_incoming_cpu
#define sk_flags		__sk_common.skc_flags
#define sk_rxhash		__sk_common.skc_rxhash

	/* 同步锁
	 * 1. 用于用户进程读取数据与网络层向传输层传递数据之间的同步。
	 * 2. 用于软中断之间同步访问传输块。
	 */
	socket_lock_t		sk_lock;
	atomic_t		sk_drops;
	int			sk_rcvlowat; /* 接收缓存下限值 */

	/* 错误链表。存放详细的出错信息。参见IP_RECVERR选项。 */
	struct sk_buff_head	sk_error_queue;

	/* 接收队列，等待用户进程读取。
	 * 对TCP来说，只有接收到的数据不能直接复制到用户空间时才缓存到此。
	 */
	struct sk_buff_head	sk_receive_queue;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 * Note : rmem_alloc is in this structure to fill a hole
	 * on 64bit arches, not because its logically part of
	 * backlog.
	 */
	/* 当接收数据时，锁被用户进程占用，就把数据先存放到该备用队列 sk_backlog 中。
	 * 等锁被释放时，用户进程再使用该队列数据。
	 * 只用于tcp，udp没有使用该队列。
	 */
	struct {
		atomic_t	rmem_alloc;
		int		len;
		struct sk_buff	*head;
		struct sk_buff	*tail;
	} sk_backlog;
#define sk_rmem_alloc sk_backlog.rmem_alloc

	/* 预分配缓存 */
	int			sk_forward_alloc;
#ifdef CONFIG_NET_RX_BUSY_POLL
	unsigned int		sk_ll_usec;
	/* ===== mostly read cache line ===== */
	unsigned int		sk_napi_id;
#endif
	int			sk_rcvbuf;

	struct sk_filter __rcu	*sk_filter; /* 套接口过滤器。*/
	union {
		struct socket_wq __rcu	*sk_wq;
		struct socket_wq	*sk_wq_raw;
	};
#ifdef CONFIG_XFRM
	struct xfrm_policy __rcu *sk_policy[2];
#endif
	struct dst_entry	*sk_rx_dst;
	struct dst_entry __rcu	*sk_dst_cache; /* 路由项缓存 */
	atomic_t		sk_omem_alloc;
	int			sk_sndbuf; /* 发送缓冲区长度上限。发送队列中报文数据总长度不能超过此值 */

	/* ===== cache line for TX ===== */
	int			sk_wmem_queued; /* 发送队列中所有报文数据的总长度，目前仅用于TCP. */
	
	/* 已发送给ip层以下的数据量， 在TSQ检查中，会与sk_pacing_rate等数据做比较，限制发送量。
	 * __tcp_transmit_skb()中，当成功发送给ip层以下，就会增加。
	 * 如果sk_wmem_alloc大于一定值，表示发送了太多的数据到qdisc或者设备队列。
	 * 可用于TSQ，控制本地队列的长度。
	 * 
	 * 如果本地队列过长，就会导致bufferbloat 和异常RTT等。
	 * tcp_transmit_skb()中增加，加上发送的skb的truesize。
	 * tcp_wfree()中减少，一般由网卡的tx done中进行 dev_kfree_skb_any() -> net_tx_action() -> skb->destructor() 中调用。
	 */
	refcount_t		sk_wmem_alloc;
	unsigned long		sk_tsq_flags;

	union {
		/* 指向发送队列中下一个要发送的数据包。
		 * 用来跟踪哪些包还未发送的，而不是用来进行发送的，如果为空，则意味着
		 * 发送队列上的所有数据包都已发送过了。
		 * 在发送方从接收方接收到ACK后，可扩大发送窗口，从sk_send_head开始遍历发送队列发送更多的段。
		 */
		struct sk_buff	*sk_send_head;
		struct rb_root	tcp_rtx_queue;
	};

	/**
	 * 向内核添加数据时，被缓冲的数据可能会在内核中形成多个待发送的IP分片。
	 * 通过该指针将这些分片缓冲区连接起来。
	 * 这是ip_append_data()函数的输出结果。
	 */
	struct sk_buff_head	sk_write_queue;

	__s32			sk_peek_off;
	int			sk_write_pending;
	__u32			sk_dst_pending_confirm;

	/* 两种情况会被设置为SK_PACING_NEEDED：
	 * 1. bbr算法中， bbr_init()。
	 * 2. 用户层的setsockopt()的 SO_MAX_PACING_RATE 来进行设置以及设置最大速率。
	 */
	u32			sk_pacing_status; /* see enum sk_pacing */
	
	long			sk_sndtimeo; /* 套接口层发送超时时间。参见SO_SNDTIMEO选项。*/
	struct timer_list	sk_timer;   /* 根据TCP的不同状态，来实现连接定时器、FIN_WAIT_2定时器和TCP保活定时器。*/
	__u32			sk_priority; /* 用于设置数据报的QoS类别。参见SO_PRIORITY和IP_TOS选项。*/
	__u32			sk_mark;

	/* pacing速率， tcp_update_pacing_rate()
	 * 1. 非bbr： tcp_rcv_state_process()中计算
	 * 2. bbr: .cong_control()，即bbr_main()中计算。
	 */
	unsigned long		sk_pacing_rate; /* bytes per second */
	unsigned long		sk_max_pacing_rate;

	/* 上次的skb frag buffer */
	struct page_frag	sk_frag;

	netdev_features_t	sk_route_caps;
	netdev_features_t	sk_route_nocaps;
	netdev_features_t	sk_route_forced_caps;
	int			sk_gso_type;
	unsigned int		sk_gso_max_size;
	gfp_t			sk_allocation;
	__u32			sk_txhash;

	/*
	 * Because of non atomicity rules, all
	 * changes are protected by socket lock.
	 */
	unsigned int		__sk_flags_offset[0];
#ifdef __BIG_ENDIAN_BITFIELD
#define SK_FL_PROTO_SHIFT  16
#define SK_FL_PROTO_MASK   0x00ff0000

#define SK_FL_TYPE_SHIFT   0
#define SK_FL_TYPE_MASK    0x0000ffff
#else
#define SK_FL_PROTO_SHIFT  8
#define SK_FL_PROTO_MASK   0x0000ff00

#define SK_FL_TYPE_SHIFT   16
#define SK_FL_TYPE_MASK    0xffff0000
#endif

	unsigned int		sk_padding : 1,
				sk_kern_sock : 1,
				sk_no_check_tx : 1, /* 是否对UDP和RAWSOCK进行校验和，参见SO_NO_CHECK选项 */
				sk_no_check_rx : 1,
				sk_userlocks : 4,
				sk_protocol  : 8, /* 在某个网络协议族中，该套接字属于哪个协议使用。*/
				sk_type      : 16; /* 套接字类型，其值为SOCK_XXX形式。eg: SOCK_STREAM */
#define SK_PROTOCOL_MAX U8_MAX
	u16			sk_gso_max_segs; /* 该sock支持的gso最大分段数 */
	u8			sk_pacing_shift; /* 定义为10，一般用于计算流量。2的十次方。即1ms。 */
	unsigned long	        sk_lingertime; /* 关闭套接口前发送剩余数据的时间。参见SO_LINGER选项 */
	struct proto		*sk_prot_creator; /* 传输层接口 */
	rwlock_t		sk_callback_lock;
	int			sk_err, /* 记录当前传输层最后一次致命错误的错误码。应用层读取后恢复。 */
				sk_err_soft; /* 非致命性错误，或者用作在socket被锁定时记录错误的后备成员。 */
	u32			sk_ack_backlog; /* 当前全连接队列的长度：当前已经建立的连接数。等待用户调用accept。 */
	u32			sk_max_ack_backlog; /* 全连接队列最大值：连接队列长度的上限。 */
	kuid_t			sk_uid;
	struct pid		*sk_peer_pid;
	const struct cred	*sk_peer_cred;
	long			sk_rcvtimeo; /* 套接口层接收超时时间。参见SO_RCVTIMEO选项。 */

	/**
	 * 在未启用SOCK_RCVTSTAMP选项时，记录报文接收数据到应用层的时间戳。
	 * 当启用SOCK_RCVTSTAMP选项时，接收数据的时间戳记录在SKB的tstamp中。
	 */
	ktime_t			sk_stamp;
#if BITS_PER_LONG==32
	seqlock_t		sk_stamp_seq;
#endif
	u16			sk_tsflags;
	u8			sk_shutdown; //存放套接字的RCV_SHUTDOWN和SEND_SHUTDOWN选项。
	u32			sk_tskey;
	atomic_t		sk_zckey;

	u8			sk_clockid;
	u8			sk_txtime_deadline_mode : 1,
				sk_txtime_report_errors : 1,
				sk_txtime_unused : 6;

	struct socket		*sk_socket; /* 指向相关套接口的指针 */
	void			*sk_user_data; /* RPC层存放私有数据的指针，IPV4中未使用。 */
#ifdef CONFIG_SECURITY
	void			*sk_security;
#endif
	struct sock_cgroup_data	sk_cgrp_data;
	struct mem_cgroup	*sk_memcg;

	/* 当socket状态发生变化时，唤醒那些等待本套接口的进程。在创建套接口时初始化。 */
	void			(*sk_state_change)(struct sock *sk);

	/* 当收到数据时，协议成调用唤醒等待读数据的用户进程。例如：tcp_rcv_established() -> tcp_data_ready() */
	void			(*sk_data_ready)(struct sock *sk);

	/**
	 * 在发送缓存大小发生变化时，或者套接口被释放时，唤醒等待本套接口的进程。
	 * ipv4默认为 sock_def_write_space() ，TCP中默认为 sk_stream_write_space() 。
	 * tcp:
	 *	1. tcp_init_sock()进行初始化 sk_write_space= sk_stream_write_space()
	 *	2. 在 tcp_data_snd_check() -> tcp_check_space() -> tcp_new_space() 中进行唤醒。
	 */
	void			(*sk_write_space)(struct sock *sk);

	/**
	 * 报告错误的回调函数。如果等待该套接口的进程正在睡眠，则将其唤醒。
	 * ipv4中为sock_def_error_report。
	 */
	void			(*sk_error_report)(struct sock *sk);

	/**
	 * 后备队列接收函数。用于ipv4和PPPoE。
	 */
	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);
#ifdef CONFIG_SOCK_VALIDATE_XMIT
	struct sk_buff*		(*sk_validate_xmit_skb)(struct sock *sk,
							struct net_device *dev,
							struct sk_buff *skb);
#endif

	/**
	 * 在释放传输控制块时，回调此函数释放相关资源。
	 * ipv4中为inet_sock_destruct。
	 */
	void                    (*sk_destruct)(struct sock *sk);
	struct sock_reuseport __rcu	*sk_reuseport_cb;
	struct rcu_head		sk_rcu;
};

enum sk_pacing {
	SK_PACING_NONE		= 0,
	SK_PACING_NEEDED	= 1,
	SK_PACING_FQ		= 2,
};

#define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))

#define rcu_dereference_sk_user_data(sk)	rcu_dereference(__sk_user_data((sk)))
#define rcu_assign_sk_user_data(sk, ptr)	rcu_assign_pointer(__sk_user_data((sk)), ptr)

/*
 * SK_CAN_REUSE and SK_NO_REUSE on a socket mean that the socket is OK
 * or not whether his port will be reused by someone else. SK_FORCE_REUSE
 * on a socket means that the socket will reuse everybody else's port
 * without looking at the other's sk_reuse value.
 */

#define SK_NO_REUSE	0
#define SK_CAN_REUSE	1
#define SK_FORCE_REUSE	2

int sk_set_peek_off(struct sock *sk, int val);

static inline int sk_peek_offset(struct sock *sk, int flags)
{
	if (unlikely(flags & MSG_PEEK)) {
		return READ_ONCE(sk->sk_peek_off);
	}

	return 0;
}

static inline void sk_peek_offset_bwd(struct sock *sk, int val)
{
	s32 off = READ_ONCE(sk->sk_peek_off);

	if (unlikely(off >= 0)) {
		off = max_t(s32, off - val, 0);
		WRITE_ONCE(sk->sk_peek_off, off);
	}
}

static inline void sk_peek_offset_fwd(struct sock *sk, int val)
{
	sk_peek_offset_bwd(sk, -val);
}

/*
 * Hashed lists helper routines
 */
static inline struct sock *sk_entry(const struct hlist_node *node)
{
	return hlist_entry(node, struct sock, sk_node);
}

static inline struct sock *__sk_head(const struct hlist_head *head)
{
	return hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(const struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *__sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_entry(head->first, struct sock, sk_nulls_node);
}

static inline struct sock *sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_empty(head) ? NULL : __sk_nulls_head(head);
}

static inline struct sock *sk_next(const struct sock *sk)
{
	return hlist_entry_safe(sk->sk_node.next, struct sock, sk_node);
}

static inline struct sock *sk_nulls_next(const struct sock *sk)
{
	return (!is_a_nulls(sk->sk_nulls_node.next)) ?
		hlist_nulls_entry(sk->sk_nulls_node.next,
				  struct sock, sk_nulls_node) :
		NULL;
}

static inline bool sk_unhashed(const struct sock *sk)
{
	return hlist_unhashed(&sk->sk_node);
}

static inline bool sk_hashed(const struct sock *sk)
{
	return !sk_unhashed(sk);
}

static inline void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static inline void sk_nulls_node_init(struct hlist_nulls_node *node)
{
	node->pprev = NULL;
}

static inline void __sk_del_node(struct sock *sk)
{
	__hlist_del(&sk->sk_node);
}

/* NB: equivalent to hlist_del_init_rcu */
static inline bool __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return true;
	}
	return false;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static __always_inline void sock_hold(struct sock *sk)
{
	refcount_inc(&sk->sk_refcnt);
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static __always_inline void __sock_put(struct sock *sk)
{
	refcount_dec(&sk->sk_refcnt);
}

static inline bool sk_del_node_init(struct sock *sk)
{
	bool rc = __sk_del_node_init(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(refcount_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}
#define sk_del_node_init_rcu(sk)	sk_del_node_init(sk)

static inline bool __sk_nulls_del_node_init_rcu(struct sock *sk)
{
	if (sk_hashed(sk)) {
		hlist_nulls_del_init_rcu(&sk->sk_nulls_node);
		return true;
	}
	return false;
}

static inline bool sk_nulls_del_node_init_rcu(struct sock *sk)
{
	bool rc = __sk_nulls_del_node_init_rcu(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(refcount_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}

static inline void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&sk->sk_node, list);
}

static inline void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

static inline void sk_add_node_rcu(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	if (IS_ENABLED(CONFIG_IPV6) && sk->sk_reuseport &&
	    sk->sk_family == AF_INET6)
		hlist_add_tail_rcu(&sk->sk_node, list);
	else
		hlist_add_head_rcu(&sk->sk_node, list);
}

static inline void __sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	hlist_nulls_add_head_rcu(&sk->sk_nulls_node, list);
}

static inline void sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	sock_hold(sk);
	__sk_nulls_add_node_rcu(sk, list);
}

static inline void __sk_del_bind_node(struct sock *sk)
{
	__hlist_del(&sk->sk_bind_node);
}

static inline void sk_add_bind_node(struct sock *sk,
					struct hlist_head *list)
{
	hlist_add_head(&sk->sk_bind_node, list);
}

#define sk_for_each(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_node)
#define sk_for_each_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, sk_node)
#define sk_nulls_for_each(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, sk_nulls_node)
#define sk_nulls_for_each_rcu(__sk, node, list) \
	hlist_nulls_for_each_entry_rcu(__sk, node, list, sk_nulls_node)
#define sk_for_each_from(__sk) \
	hlist_for_each_entry_from(__sk, sk_node)
#define sk_nulls_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_nulls_node; 1; })) \
		hlist_nulls_for_each_entry_from(__sk, node, sk_nulls_node)
#define sk_for_each_safe(__sk, tmp, list) \
	hlist_for_each_entry_safe(__sk, tmp, list, sk_node)
#define sk_for_each_bound(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_bind_node)

/**
 * sk_for_each_entry_offset_rcu - iterate over a list at a given struct offset
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @offset:	offset of hlist_node within the struct.
 *
 */
#define sk_for_each_entry_offset_rcu(tpos, pos, head, offset)		       \
	for (pos = rcu_dereference(hlist_first_rcu(head));		       \
	     pos != NULL &&						       \
		({ tpos = (typeof(*tpos) *)((void *)pos - offset); 1;});       \
	     pos = rcu_dereference(hlist_next_rcu(pos)))

static inline struct user_namespace *sk_user_ns(struct sock *sk)
{
	/* Careful only use this in a context where these parameters
	 * can not change and must all be valid, such as recvmsg from
	 * userspace.
	 */
	return sk->sk_socket->file->f_cred->user_ns;
}

/* Sock flags */
enum sock_flags {
	SOCK_DEAD, /* 连接已经断开，套接口即将关闭 */
	SOCK_DONE, /* 标志TCP会话即将结束，在接收到FIN报文时设置 */
	SOCK_URGINLINE, /* 将带外数据放入正常数据流 */
	SOCK_KEEPOPEN, /* 启动了保活选项 */
	SOCK_LINGER, /* 关闭套接口前发送剩余数据的时间 */
	SOCK_DESTROY, /* 控制块已经释放，IPV4未使用 */
	SOCK_BROADCAST, /* 套接口支持收发广播报文 */
	SOCK_TIMESTAMP, /* 是否将段的接收时间作为时间戳 */
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	SOCK_DBG, /* %SO_DEBUG setting */
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	SOCK_RCVTSTAMPNS, /* %SO_TIMESTAMPNS setting */
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
	SOCK_MEMALLOC, /* VM depends on this socket for swapping */
	SOCK_TIMESTAMPING_RX_SOFTWARE,  /* %SOF_TIMESTAMPING_RX_SOFTWARE */
	SOCK_FASYNC, /* fasync() active */
	SOCK_RXQ_OVFL,
	SOCK_ZEROCOPY, /* buffers from userspace */
	SOCK_WIFI_STATUS, /* push wifi status to userspace */
	SOCK_NOFCS, /* Tell NIC not to do the Ethernet FCS.
		     * Will use last 4 bytes of packet sent from
		     * user-space instead.
		     */
	SOCK_FILTER_LOCKED, /* Filter cannot be changed anymore */
	SOCK_SELECT_ERR_QUEUE, /* Wake select on error queue */
	SOCK_RCU_FREE, /* wait rcu grace period in sk_destruct() */
	SOCK_TXTIME,
	SOCK_XDP, /* XDP is attached */
};

#define SK_FLAGS_TIMESTAMP ((1UL << SOCK_TIMESTAMP) | (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE))

static inline void sock_copy_flags(struct sock *nsk, struct sock *osk)
{
	nsk->sk_flags = osk->sk_flags;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline bool sock_flag(const struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}

#ifdef CONFIG_NET
DECLARE_STATIC_KEY_FALSE(memalloc_socks_key);
static inline int sk_memalloc_socks(void)
{
	return static_branch_unlikely(&memalloc_socks_key);
}
#else

static inline int sk_memalloc_socks(void)
{
	return 0;
}

#endif

static inline gfp_t sk_gfp_mask(const struct sock *sk, gfp_t gfp_mask)
{
	return gfp_mask | (sk->sk_allocation & __GFP_MEMALLOC);
}

static inline void sk_acceptq_removed(struct sock *sk)
{
	sk->sk_ack_backlog--;
}

static inline void sk_acceptq_added(struct sock *sk)
{
	sk->sk_ack_backlog++;
}

/* 检测全连接队列是否满了 */
static inline bool sk_acceptq_is_full(const struct sock *sk)
{
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
}

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(const struct sock *sk)
{
	return sk->sk_wmem_queued >> 1;
}

static inline int sk_stream_wspace(const struct sock *sk)
{
	return sk->sk_sndbuf - sk->sk_wmem_queued;
}

void sk_stream_write_space(struct sock *sk);

/* OOB backlog add */
static inline void __sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	/* dont let skb dst not refcounted, we are going to leave rcu lock */
	skb_dst_force(skb);

	if (!sk->sk_backlog.tail)
		sk->sk_backlog.head = skb;
	else
		sk->sk_backlog.tail->next = skb;

	sk->sk_backlog.tail = skb;
	skb->next = NULL;
}

/*
 * Take into account size of receive queue and backlog queue
 * Do not take into account this skb truesize,
 * to allow even a single big packet to come.
 */
static inline bool sk_rcvqueues_full(const struct sock *sk, unsigned int limit)
{
	unsigned int qsize = sk->sk_backlog.len + atomic_read(&sk->sk_rmem_alloc);

	return qsize > limit;
}

/* The per-socket spinlock must be held here. */
static inline __must_check int sk_add_backlog(struct sock *sk, struct sk_buff *skb,
					      unsigned int limit)
{
	if (sk_rcvqueues_full(sk, limit))
		return -ENOBUFS;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC))
		return -ENOMEM;

	__sk_add_backlog(sk, skb);
	sk->sk_backlog.len += skb->truesize;
	return 0;
}

int __sk_backlog_rcv(struct sock *sk, struct sk_buff *skb);

static inline int sk_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (sk_memalloc_socks() && skb_pfmemalloc(skb))
		return __sk_backlog_rcv(sk, skb);

	return sk->sk_backlog_rcv(sk, skb);
}

static inline void sk_incoming_cpu_update(struct sock *sk)
{
	int cpu = raw_smp_processor_id();

	if (unlikely(sk->sk_incoming_cpu != cpu))
		sk->sk_incoming_cpu = cpu;
}

static inline void sock_rps_record_flow_hash(__u32 hash)
{
#ifdef CONFIG_RPS
	struct rps_sock_flow_table *sock_flow_table;

	rcu_read_lock();
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	rps_record_sock_flow(sock_flow_table, hash);
	rcu_read_unlock();
#endif
}

static inline void sock_rps_record_flow(const struct sock *sk)
{
#ifdef CONFIG_RPS
	if (static_key_false(&rfs_needed)) {
		/* Reading sk->sk_rxhash might incur an expensive cache line
		 * miss.
		 *
		 * TCP_ESTABLISHED does cover almost all states where RFS
		 * might be useful, and is cheaper [1] than testing :
		 *	IPv4: inet_sk(sk)->inet_daddr
		 * 	IPv6: ipv6_addr_any(&sk->sk_v6_daddr)
		 * OR	an additional socket flag
		 * [1] : sk_state and sk_prot are in the same cache line.
		 */
		if (sk->sk_state == TCP_ESTABLISHED)
			sock_rps_record_flow_hash(sk->sk_rxhash);
	}
#endif
}

static inline void sock_rps_save_rxhash(struct sock *sk,
					const struct sk_buff *skb)
{
#ifdef CONFIG_RPS
	if (unlikely(sk->sk_rxhash != skb->hash))
		sk->sk_rxhash = skb->hash;
#endif
}

static inline void sock_rps_reset_rxhash(struct sock *sk)
{
#ifdef CONFIG_RPS
	sk->sk_rxhash = 0;
#endif
}

#define sk_wait_event(__sk, __timeo, __condition, __wait)		\
	({	int __rc;						\
		release_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = wait_woken(__wait,			\
						TASK_INTERRUPTIBLE,	\
						*(__timeo));		\
		}							\
		sched_annotate_sleep();					\
		lock_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})

int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
void sk_stream_wait_close(struct sock *sk, long timeo_p);
int sk_stream_error(struct sock *sk, int flags, int err);
void sk_stream_kill_queues(struct sock *sk);
void sk_set_memalloc(struct sock *sk);
void sk_clear_memalloc(struct sock *sk);

void __sk_flush_backlog(struct sock *sk);

static inline bool sk_flush_backlog(struct sock *sk)
{
	if (unlikely(READ_ONCE(sk->sk_backlog.tail))) {
		__sk_flush_backlog(sk);
		return true;
	}
	return false;
}

int sk_wait_data(struct sock *sk, long *timeo, const struct sk_buff *skb);

struct request_sock_ops;
struct timewait_sock_ops;
struct inet_hashinfo;
struct raw_hashinfo;
struct smc_hashinfo;
struct module;

/*
 * caches using SLAB_TYPESAFE_BY_RCU should let .next pointer from nulls nodes
 * un-modified. Special care is taken when initializing object to zero.
 */
static inline void sk_prot_clear_nulls(struct sock *sk, int size)
{
	if (offsetof(struct sock, sk_node.next) != 0)
		memset(sk, 0, offsetof(struct sock, sk_node.next));
	memset(&sk->sk_node.pprev, 0,
	       size - offsetof(struct sock, sk_node.pprev));
}

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 */
/**
 * 传输层接口 
 * 实现传输层的操作和从传输层到网络层调用的跳转。
 */
struct proto {
	/* 在关闭socket时使用。*/
	void			(*close)(struct sock *sk,
					long timeout);
	int			(*pre_connect)(struct sock *sk,
					struct sockaddr *uaddr,
					int addr_len);
	int			(*connect)(struct sock *sk,
					struct sockaddr *uaddr,
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept)(struct sock *sk, int flags, int *err,
					  bool kern);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);

	/* 传输层初始化接口。在创建socket时。在inet_create中调用。 */
	int			(*init)(struct sock *sk);
	void			(*destroy)(struct sock *sk);
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level,
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*getsockopt)(struct sock *sk, int level,
					int optname, char __user *optval,
					int __user *option);
	void			(*keepalive)(struct sock *sk, int valbool);
#ifdef CONFIG_COMPAT
	int			(*compat_setsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*compat_getsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					int __user *option);
	int			(*compat_ioctl)(struct sock *sk,
					unsigned int cmd, unsigned long arg);
#endif
	int			(*sendmsg)(struct sock *sk, struct msghdr *msg,
					   size_t len);
	int			(*recvmsg)(struct sock *sk, struct msghdr *msg,
					   size_t len, int noblock, int flags,
					   int *addr_len);
	int			(*sendpage)(struct sock *sk, struct page *page,
					int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk,
					struct sockaddr *uaddr, int addr_len);

	/* 用于接收预备队列和后备队列中的TCP段。*/
	int			(*backlog_rcv) (struct sock *sk,
						struct sk_buff *skb);

	void		(*release_cb)(struct sock *sk);

	/* Keeping track of sk's, looking them up, and port selection methods. */
	/* 将socket添加到散列表的接口。如tcp_v4_hash */
	int			(*hash)(struct sock *sk);
	/* 将socket从散列表中移除。如tcp_unhash */
	void			(*unhash)(struct sock *sk);
	void			(*rehash)(struct sock *sk);
	/* 将套接口与端口进行绑定。如果snum为0，表示可以选择任意端口。 */
	int			(*get_port)(struct sock *sk, unsigned short snum);

	/* Keeping track of sockets in use */
#ifdef CONFIG_PROC_FS
	unsigned int		inuse_idx;
#endif

	bool			(*stream_memory_free)(const struct sock *sk, int wake);
	bool			(*stream_memory_read)(const struct sock *sk);
	/* Memory pressure */
	/**
	 * 只有TCP使用。当缓存区分配的内存超过tcp_mem[1]时，调用此函数进入告警状态。
	 * TCP中回调是tcp_enter_memory_pressure
	 */
	void			(*enter_memory_pressure)(struct sock *sk);
	void			(*leave_memory_pressure)(struct sock *sk);
	/* 只有TCP使用。表示整个TCP层为缓存区分配的内存(包括输入队列)。指向变量tcp_memory_allocated。*/
	atomic_long_t		*memory_allocated;	/* Current allocated memory. */
	/* 只有TCP使用，表示整个TCP层创建的套接口数目。指向tcp_sockets_allocated。 */
	struct percpu_counter	*sockets_allocated;	/* Current number of sockets. */
	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the __sk_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	 /* 指向标志tcp_memory_pressure，表示是否进入缓冲区警告状态。 */
	unsigned long		*memory_pressure;
	long			*sysctl_mem; /* 指向sysctl_tcp_mem */

	int			*sysctl_wmem; /* 指向sysctl_tcp_wmem */
	int			*sysctl_rmem; /* 指向sysctl_tcp_rmem */
	u32			sysctl_wmem_offset;
	u32			sysctl_rmem_offset;

	int			max_header; /* 只有TCP使用，表示TCP首部的最大长度，包括所有选项。 */
	bool			no_autobind;

	struct kmem_cache	*slab; /* 分配socket的slab高速缓存。 */
	unsigned int		obj_size;
	slab_flags_t		slab_flags;
	unsigned int		useroffset;	/* Usercopy region offset */
	unsigned int		usersize;	/* Usercopy region size */

	struct percpu_counter	*orphan_count;

	struct request_sock_ops	*rsk_prot;
	struct timewait_sock_ops *twsk_prot;

	union {
		struct inet_hashinfo	*hashinfo;
		struct udp_table	*udp_table;
		struct raw_hashinfo	*raw_hash;
		struct smc_hashinfo	*smc_hash;
	} h;

	struct module		*owner;

	char			name[32]; /* 协议名称，如"TCP" */

	struct list_head	node;
#ifdef SOCK_REFCNT_DEBUG
	atomic_t		socks;
#endif
	int			(*diag_destroy)(struct sock *sk, int err);
} __randomize_layout;

int proto_register(struct proto *prot, int alloc_slab);
void proto_unregister(struct proto *prot);
int sock_load_diag_module(int family, int protocol);

#ifdef SOCK_REFCNT_DEBUG
static inline void sk_refcnt_debug_inc(struct sock *sk)
{
	atomic_inc(&sk->sk_prot->socks);
}

static inline void sk_refcnt_debug_dec(struct sock *sk)
{
	atomic_dec(&sk->sk_prot->socks);
	printk(KERN_DEBUG "%s socket %p released, %d are still alive\n",
	       sk->sk_prot->name, sk, atomic_read(&sk->sk_prot->socks));
}

static inline void sk_refcnt_debug_release(const struct sock *sk)
{
	if (refcount_read(&sk->sk_refcnt) != 1)
		printk(KERN_DEBUG "Destruction of the %s socket %p delayed, refcnt=%d\n",
		       sk->sk_prot->name, sk, refcount_read(&sk->sk_refcnt));
}
#else /* SOCK_REFCNT_DEBUG */
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#endif /* SOCK_REFCNT_DEBUG */

static inline bool __sk_stream_memory_free(const struct sock *sk, int wake)
{
	if (sk->sk_wmem_queued >= sk->sk_sndbuf)
		return false;

	return sk->sk_prot->stream_memory_free ?
		sk->sk_prot->stream_memory_free(sk, wake) : true;
}

static inline bool sk_stream_memory_free(const struct sock *sk)
{
	return __sk_stream_memory_free(sk, 0);
}

static inline bool __sk_stream_is_writeable(const struct sock *sk, int wake)
{
	return sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) &&
	       __sk_stream_memory_free(sk, wake);
}

static inline bool sk_stream_is_writeable(const struct sock *sk)
{
	return __sk_stream_is_writeable(sk, 0);
}

static inline int sk_under_cgroup_hierarchy(struct sock *sk,
					    struct cgroup *ancestor)
{
#ifdef CONFIG_SOCK_CGROUP_DATA
	return cgroup_is_descendant(sock_cgroup_ptr(&sk->sk_cgrp_data),
				    ancestor);
#else
	return -ENOTSUPP;
#endif
}

static inline bool sk_has_memory_pressure(const struct sock *sk)
{
	return sk->sk_prot->memory_pressure != NULL;
}

static inline bool sk_under_memory_pressure(const struct sock *sk)
{
	if (!sk->sk_prot->memory_pressure)
		return false;

	if (mem_cgroup_sockets_enabled && sk->sk_memcg &&
	    mem_cgroup_under_socket_pressure(sk->sk_memcg))
		return true;

	return !!*sk->sk_prot->memory_pressure;
}

static inline long
sk_memory_allocated(const struct sock *sk)
{
	return atomic_long_read(sk->sk_prot->memory_allocated);
}

static inline long
sk_memory_allocated_add(struct sock *sk, int amt)
{
	return atomic_long_add_return(amt, sk->sk_prot->memory_allocated);
}

static inline void
sk_memory_allocated_sub(struct sock *sk, int amt)
{
	atomic_long_sub(amt, sk->sk_prot->memory_allocated);
}

static inline void sk_sockets_allocated_dec(struct sock *sk)
{
	percpu_counter_dec(sk->sk_prot->sockets_allocated);
}

static inline void sk_sockets_allocated_inc(struct sock *sk)
{
	percpu_counter_inc(sk->sk_prot->sockets_allocated);
}

static inline u64
sk_sockets_allocated_read_positive(struct sock *sk)
{
	return percpu_counter_read_positive(sk->sk_prot->sockets_allocated);
}

static inline int
proto_sockets_allocated_sum_positive(struct proto *prot)
{
	return percpu_counter_sum_positive(prot->sockets_allocated);
}

static inline long
proto_memory_allocated(struct proto *prot)
{
	return atomic_long_read(prot->memory_allocated);
}

static inline bool
proto_memory_pressure(struct proto *prot)
{
	if (!prot->memory_pressure)
		return false;
	return !!*prot->memory_pressure;
}


#ifdef CONFIG_PROC_FS
/* Called with local bh disabled */
void sock_prot_inuse_add(struct net *net, struct proto *prot, int inc);
int sock_prot_inuse_get(struct net *net, struct proto *proto);
int sock_inuse_get(struct net *net);
#else
static inline void sock_prot_inuse_add(struct net *net, struct proto *prot,
		int inc)
{
}
#endif


/* With per-bucket locks this operation is not-atomic, so that
 * this version is not worse.
 */
static inline int __sk_prot_rehash(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	return sk->sk_prot->hash(sk);
}

/* About 10 seconds */
#define SOCK_DESTROY_TIME (10*HZ)

/* Sockets 0-1023 can't be bound to unless you are superuser */
#define PROT_SOCK	1024

#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

/*
 * Functions for memory accounting
 */
int __sk_mem_raise_allocated(struct sock *sk, int size, int amt, int kind);
int __sk_mem_schedule(struct sock *sk, int size, int kind);
void __sk_mem_reduce_allocated(struct sock *sk, int amount);
void __sk_mem_reclaim(struct sock *sk, int amount);

/* We used to have PAGE_SIZE here, but systems with 64KB pages
 * do not necessarily have 16x time more memory than 4KB ones.
 */
#define SK_MEM_QUANTUM 4096
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SK_MEM_SEND	0
#define SK_MEM_RECV	1

/* sysctl_mem values are in pages, we convert them in SK_MEM_QUANTUM units */
static inline long sk_prot_mem_limits(const struct sock *sk, int index)
{
	long val = sk->sk_prot->sysctl_mem[index];

#if PAGE_SIZE > SK_MEM_QUANTUM
	val <<= PAGE_SHIFT - SK_MEM_QUANTUM_SHIFT;
#elif PAGE_SIZE < SK_MEM_QUANTUM
	val >>= SK_MEM_QUANTUM_SHIFT - PAGE_SHIFT;
#endif
	return val;
}

static inline int sk_mem_pages(int amt)
{
	return (amt + SK_MEM_QUANTUM - 1) >> SK_MEM_QUANTUM_SHIFT;
}

/* sock是否有内存统计，例如, TCP层就会用内存统计 */
static inline bool sk_has_account(struct sock *sk)
{
	/* return true if protocol supports memory accounting */
	return !!sk->sk_prot->memory_allocated;
}

static inline bool sk_wmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return true;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_SEND);
}

static inline bool
sk_rmem_schedule(struct sock *sk, struct sk_buff *skb, int size)
{
	if (!sk_has_account(sk))
		return true;
	return size<= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_RECV) ||
		skb_pfmemalloc(skb);
}

static inline void sk_mem_reclaim(struct sock *sk)
{
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc >= SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk, sk->sk_forward_alloc);
}

static inline void sk_mem_reclaim_partial(struct sock *sk)
{
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc > SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk, sk->sk_forward_alloc - 1);
}

static inline void sk_mem_charge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc -= size;
}

static inline void sk_mem_uncharge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc += size;

	/* Avoid a possible overflow.
	 * TCP send queues can make this happen, if sk_mem_reclaim()
	 * is not called and more than 2 GBytes are released at once.
	 *
	 * If we reach 2 MBytes, reclaim 1 MBytes right now, there is
	 * no need to hold that much forward allocation anyway.
	 */
	if (unlikely(sk->sk_forward_alloc >= 1 << 21))
		__sk_mem_reclaim(sk, 1 << 20);
}

static inline void sk_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk->sk_wmem_queued -= skb->truesize;
	sk_mem_uncharge(sk, skb->truesize);
	__kfree_skb(skb);
}

static inline void sock_release_ownership(struct sock *sk)
{
	if (sk->sk_lock.owned) {
		sk->sk_lock.owned = 0;

		/* The sk_lock has mutex_unlock() semantics: */
		mutex_release(&sk->sk_lock.dep_map, 1, _RET_IP_);
	}
}

/*
 * Macro so as to not evaluate some arguments when
 * lockdep is not enabled.
 *
 * Mark both the sk_lock and the sk_lock.slock as a
 * per-address-family lock class.
 */
#define sock_lock_init_class_and_name(sk, sname, skey, name, key)	\
do {									\
	sk->sk_lock.owned = 0;						\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
				(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)

#ifdef CONFIG_LOCKDEP
static inline bool lockdep_sock_is_held(const struct sock *sk)
{
	return lockdep_is_held(&sk->sk_lock) ||
	       lockdep_is_held(&sk->sk_lock.slock);
}
#endif

/*
 * https://blog.csdn.net/xiaoyu_750516366/article/details/83422075
 *
 * 传输控制块TCB是协议栈中非常重要的一个数据结构，它代表了一个套接字。
 * 该结构在进程上下文和软中断上下文都会被访问，所以保证该结构的数据一致性，就引入了sk_lock来保证。
 *
 * slock：该自旋锁是用于同步进程上下文和软中断上下文的关键；
 * owned：非0表示该TCB已经被进程上下文锁定，取值为0表示没有被进程上下文锁定；
 * wq：等待队列，当进程上下文需要持有该传输控制块，但是其当前又被软中断锁定时，进程会在该队列上等待；
 *
 * 1. 进程上下文的访问操作：
 *	进程上下文在访问该传输控制块之前需要调用lock_sock()锁定，在访问完成后调用release_sock()将其释放。
 *	lock_sock()：
 * 		a. 自旋锁保护的实际上是 owned 变量，该变量非0说明该TCB已经被某个用户进程锁定；
 *		b. 一个很重要的事实是用户进程锁定TCB后，就释放了自旋锁并开启了下半部。
 * 			这种设计的意义是协议栈的处理过程可能很长，如果只是简单的在开始时持有自旋锁并关闭下半部，
 *			在处理结束时释放自旋锁并打开下半部，那么会降低系统性能，更要命的是长时间关闭下半部，
 *			还可能使得网卡接收软中断得不到及时调用，导致丢包。
 *		特别注意：上述设计也说明，sk->sk_lock锁并不能保护TCB中的所有字段。
 *	release_sock():
 *		a. 进程上下文在结束TCB的操作之后，需要调用release_sock()释放对TCB的锁定。
 *			可以想象的到，释放的核心是将owned设置为0并通知其它等待该传输控制块的进程。
 *
 * 2. 软中断上下文的访问操作
 *	
 * 对TCB成员进行访问时，如果只是访问那些一旦创建就不会再变的成员，那么只要保证在访问期间该TCB不被释放就行
 *（引用计数不会被减为0），没有必要一定要持有该传输控制块。但是如果要访问那些可变的成员就必须要先锁定。
 * 牢记这个原则非常重要。
 */

void lock_sock_nested(struct sock *sk, int subclass);

static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
}

void __release_sock(struct sock *sk);
void release_sock(struct sock *sk);

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))

bool lock_sock_fast(struct sock *sk);
/**
 * unlock_sock_fast - complement of lock_sock_fast
 * @sk: socket
 * @slow: slow mode
 *
 * fast unlock socket for user context.
 * If slow mode is on, we call regular release_sock()
 */
static inline void unlock_sock_fast(struct sock *sk, bool slow)
{
	if (slow)
		release_sock(sk);
	else
		spin_unlock_bh(&sk->sk_lock.slock);
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */

static inline void sock_owned_by_me(const struct sock *sk)
{
#ifdef CONFIG_LOCKDEP
	WARN_ON_ONCE(!lockdep_sock_is_held(sk) && debug_locks);
#endif
}

static inline bool sock_owned_by_user(const struct sock *sk)
{
	sock_owned_by_me(sk);
	return sk->sk_lock.owned;
}

static inline bool sock_owned_by_user_nocheck(const struct sock *sk)
{
	return sk->sk_lock.owned;
}

/* no reclassification while locks are held */
static inline bool sock_allow_reclassification(const struct sock *csk)
{
	struct sock *sk = (struct sock *)csk;

	return !sk->sk_lock.owned && !spin_is_locked(&sk->sk_lock.slock);
}

struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot, int kern);
void sk_free(struct sock *sk);
void sk_destruct(struct sock *sk);
struct sock *sk_clone_lock(const struct sock *sk, const gfp_t priority);
void sk_free_unlock_clone(struct sock *sk);

struct sk_buff *sock_wmalloc(struct sock *sk, unsigned long size, int force,
			     gfp_t priority);
void __sock_wfree(struct sk_buff *skb);
void sock_wfree(struct sk_buff *skb);
struct sk_buff *sock_omalloc(struct sock *sk, unsigned long size,
			     gfp_t priority);
void skb_orphan_partial(struct sk_buff *skb);
void sock_rfree(struct sk_buff *skb);
void sock_efree(struct sk_buff *skb);
#ifdef CONFIG_INET
void sock_edemux(struct sk_buff *skb);
#else
#define sock_edemux sock_efree
#endif

int sock_setsockopt(struct socket *sock, int level, int op,
		    char __user *optval, unsigned int optlen);

int sock_getsockopt(struct socket *sock, int level, int op,
		    char __user *optval, int __user *optlen);
struct sk_buff *sock_alloc_send_skb(struct sock *sk, unsigned long size,
				    int noblock, int *errcode);
struct sk_buff *sock_alloc_send_pskb(struct sock *sk, unsigned long header_len,
				     unsigned long data_len, int noblock,
				     int *errcode, int max_page_order);
void *sock_kmalloc(struct sock *sk, int size, gfp_t priority);
void sock_kfree_s(struct sock *sk, void *mem, int size);
void sock_kzfree_s(struct sock *sk, void *mem, int size);
void sk_send_sigurg(struct sock *sk);

struct sockcm_cookie {
	u64 transmit_time;
	u32 mark;
	u16 tsflags;
};

static inline void sockcm_init(struct sockcm_cookie *sockc,
			       const struct sock *sk)
{
	*sockc = (struct sockcm_cookie) { .tsflags = sk->sk_tsflags };
}

int __sock_cmsg_send(struct sock *sk, struct msghdr *msg, struct cmsghdr *cmsg,
		     struct sockcm_cookie *sockc);
int sock_cmsg_send(struct sock *sk, struct msghdr *msg,
		   struct sockcm_cookie *sockc);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * does not implement a particular function.
 */
int sock_no_bind(struct socket *, struct sockaddr *, int);
int sock_no_connect(struct socket *, struct sockaddr *, int, int);
int sock_no_socketpair(struct socket *, struct socket *);
int sock_no_accept(struct socket *, struct socket *, int, bool);
int sock_no_getname(struct socket *, struct sockaddr *, int);
int sock_no_ioctl(struct socket *, unsigned int, unsigned long);
int sock_no_listen(struct socket *, int);
int sock_no_shutdown(struct socket *, int);
int sock_no_getsockopt(struct socket *, int , int, char __user *, int __user *);
int sock_no_setsockopt(struct socket *, int, int, char __user *, unsigned int);
int sock_no_sendmsg(struct socket *, struct msghdr *, size_t);
int sock_no_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t len);
int sock_no_recvmsg(struct socket *, struct msghdr *, size_t, int);
int sock_no_mmap(struct file *file, struct socket *sock,
		 struct vm_area_struct *vma);
ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset,
			 size_t size, int flags);
ssize_t sock_no_sendpage_locked(struct sock *sk, struct page *page,
				int offset, size_t size, int flags);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * uses the inet style.
 */
int sock_common_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen);
int sock_common_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			int flags);
int sock_common_setsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, unsigned int optlen);
int compat_sock_common_getsockopt(struct socket *sock, int level,
		int optname, char __user *optval, int __user *optlen);
int compat_sock_common_setsockopt(struct socket *sock, int level,
		int optname, char __user *optval, unsigned int optlen);

void sk_common_release(struct sock *sk);

/*
 *	Default socket callbacks and setup code
 */

/* Initialise core socket variables */
void sock_init_data(struct socket *sock, struct sock *sk);

/*
 * Socket reference counting postulates.
 *
 * * Each user of socket SHOULD hold a reference count.
 * * Each access point to socket (an hash table bucket, reference from a list,
 *   running timer, skb in flight MUST hold a reference count.
 * * When reference count hits 0, it means it will never increase back.
 * * When reference count hits 0, it means that no references from
 *   outside exist to this socket and current process on current CPU
 *   is last user and may/should destroy this socket.
 * * sk_free is called from any context: process, BH, IRQ. When
 *   it is called, socket has no references from outside -> sk_free
 *   may release descendant resources allocated by the socket, but
 *   to the time when it is called, socket is NOT referenced by any
 *   hash tables, lists etc.
 * * Packets, delivered from outside (from network or from another process)
 *   and enqueued on receive/error queues SHOULD NOT grab reference count,
 *   when they sit in queue. Otherwise, packets will leak to hole, when
 *   socket is looked up by one cpu and unhasing is made by another CPU.
 *   It is true for udp/raw, netlink (leak to receive and error queues), tcp
 *   (leak to backlog). Packet socket does all the processing inside
 *   BR_NETPROTO_LOCK, so that it has not this race condition. UNIX sockets
 *   use separate SMP lock, so that they are prone too.
 */

/* Ungrab socket and destroy it, if it was the last reference. */
static inline void sock_put(struct sock *sk)
{
	if (refcount_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}
/* Generic version of sock_put(), dealing with all sockets
 * (TCP_TIMEWAIT, TCP_NEW_SYN_RECV, ESTABLISHED...)
 */
void sock_gen_put(struct sock *sk);

int __sk_receive_skb(struct sock *sk, struct sk_buff *skb, const int nested,
		     unsigned int trim_cap, bool refcounted);
static inline int sk_receive_skb(struct sock *sk, struct sk_buff *skb,
				 const int nested)
{
	return __sk_receive_skb(sk, skb, nested, 1, true);
}

static inline void sk_tx_queue_set(struct sock *sk, int tx_queue)
{
	/* sk_tx_queue_mapping accept only upto a 16-bit value */
	if (WARN_ON_ONCE((unsigned short)tx_queue >= USHRT_MAX))
		return;
	sk->sk_tx_queue_mapping = tx_queue;
}

#define NO_QUEUE_MAPPING	USHRT_MAX

static inline void sk_tx_queue_clear(struct sock *sk)
{
	sk->sk_tx_queue_mapping = NO_QUEUE_MAPPING;
}

static inline int sk_tx_queue_get(const struct sock *sk)
{
	if (sk && sk->sk_tx_queue_mapping != NO_QUEUE_MAPPING)
		return sk->sk_tx_queue_mapping;

	return -1;
}

static inline void sk_rx_queue_set(struct sock *sk, const struct sk_buff *skb)
{
#ifdef CONFIG_XPS
	if (skb_rx_queue_recorded(skb)) {
		u16 rx_queue = skb_get_rx_queue(skb);

		if (WARN_ON_ONCE(rx_queue == NO_QUEUE_MAPPING))
			return;

		sk->sk_rx_queue_mapping = rx_queue;
	}
#endif
}

static inline void sk_rx_queue_clear(struct sock *sk)
{
#ifdef CONFIG_XPS
	sk->sk_rx_queue_mapping = NO_QUEUE_MAPPING;
#endif
}

#ifdef CONFIG_XPS
static inline int sk_rx_queue_get(const struct sock *sk)
{
	if (sk && sk->sk_rx_queue_mapping != NO_QUEUE_MAPPING)
		return sk->sk_rx_queue_mapping;

	return -1;
}
#endif

static inline void sk_set_socket(struct sock *sk, struct socket *sock)
{
	sk_tx_queue_clear(sk);
	sk->sk_socket = sock;
}

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	BUILD_BUG_ON(offsetof(struct socket_wq, wait) != 0);
	return &rcu_dereference_raw(sk->sk_wq)->wait;
}
/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 */
static inline void sock_orphan(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk_set_socket(sk, NULL);
	sk->sk_wq  = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	WARN_ON(parent->sk);
	write_lock_bh(&sk->sk_callback_lock);
	rcu_assign_pointer(sk->sk_wq, parent->wq);
	parent->sk = sk;
	sk_set_socket(sk, parent);
	sk->sk_uid = SOCK_INODE(parent)->i_uid;
	security_sock_graft(sk, parent);
	write_unlock_bh(&sk->sk_callback_lock);
}

kuid_t sock_i_uid(struct sock *sk);
unsigned long sock_i_ino(struct sock *sk);

static inline kuid_t sock_net_uid(const struct net *net, const struct sock *sk)
{
	return sk ? sk->sk_uid : make_kuid(net->user_ns, 0);
}

static inline u32 net_tx_rndhash(void)
{
	u32 v = prandom_u32();

	return v ?: 1;
}

static inline void sk_set_txhash(struct sock *sk)
{
	sk->sk_txhash = net_tx_rndhash();
}

static inline void sk_rethink_txhash(struct sock *sk)
{
	if (sk->sk_txhash)
		sk_set_txhash(sk);
}

static inline struct dst_entry *
__sk_dst_get(struct sock *sk)
{
	return rcu_dereference_check(sk->sk_dst_cache,
				     lockdep_sock_is_held(sk));
}

static inline struct dst_entry *
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	rcu_read_lock();
	dst = rcu_dereference(sk->sk_dst_cache);
	if (dst && !atomic_inc_not_zero(&dst->__refcnt))
		dst = NULL;
	rcu_read_unlock();
	return dst;
}

static inline void dst_negative_advice(struct sock *sk)
{
	struct dst_entry *ndst, *dst = __sk_dst_get(sk);

	sk_rethink_txhash(sk);

	if (dst && dst->ops->negative_advice) {
		ndst = dst->ops->negative_advice(dst);

		if (ndst != dst) {
			rcu_assign_pointer(sk->sk_dst_cache, ndst);
			sk_tx_queue_clear(sk);
			sk->sk_dst_pending_confirm = 0;
		}
	}
}

static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	sk->sk_dst_pending_confirm = 0;
	old_dst = rcu_dereference_protected(sk->sk_dst_cache,
					    lockdep_sock_is_held(sk));
	rcu_assign_pointer(sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	sk->sk_dst_pending_confirm = 0;
	old_dst = xchg((__force struct dst_entry **)&sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	__sk_dst_set(sk, NULL);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	sk_dst_set(sk, NULL);
}

struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie);

struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie);

static inline void sk_dst_confirm(struct sock *sk)
{
	if (!sk->sk_dst_pending_confirm)
		sk->sk_dst_pending_confirm = 1;
}

static inline void sock_confirm_neigh(struct sk_buff *skb, struct neighbour *n)
{
	if (skb_get_dst_pending_confirm(skb)) {
		struct sock *sk = skb->sk;
		unsigned long now = jiffies;

		/* avoid dirtying neighbour */
		if (n->confirmed != now)
			n->confirmed = now;
		if (sk && sk->sk_dst_pending_confirm)
			sk->sk_dst_pending_confirm = 0;
	}
}

bool sk_mc_loop(struct sock *sk);

/* 实际上检查的就是sk->sk_route_caps是否设定了sk->gso_type能力标记。
 * sk_route_caps字段代表的是路由能力；sk_gso_type表示的是L4协议期望底层支持的GSO技术。
 * 这两个字段都是在三次握手过程中设定的。
 * 客户端在tcp_v4_connect()中完成设定。-- SKB_GSO_TCPV4
 * 服务器端在收到客户端传过来的ACK后，即三次握手的最后一步，会新建一个sock并进行初始化
 * tcp_v4_syn_recv_sock() -- SKB_GSO_TCPV4
 * 注：
 *  由于对于tcp 在sk_setup_caps()中sk->sk_route_caps也被设置有SKB_GSO_TCPV4，所以整个sk_can_gso成立。
 */
static inline bool sk_can_gso(const struct sock *sk)
{
	return net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);
}

void sk_setup_caps(struct sock *sk, struct dst_entry *dst);

static inline void sk_nocaps_add(struct sock *sk, netdev_features_t flags)
{
	sk->sk_route_nocaps |= flags;
	sk->sk_route_caps &= ~flags;
}

static inline int skb_do_copy_data_nocache(struct sock *sk, struct sk_buff *skb,
					   struct iov_iter *from, char *to,
					   int copy, int offset)
{
	/* 需要TCP自己计算校验和，即net dev没有HW checksum offload */
	if (skb->ip_summed == CHECKSUM_NONE) {
		__wsum csum = 0;

		/* 拷贝用户空间的数据到内核空间，同时计算用户数据的校验和 */
		if (!csum_and_copy_from_iter_full(to, copy, &csum, from))
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, offset);
	} else if (sk->sk_route_caps & NETIF_F_NOCACHE_COPY) {
		if (!copy_from_iter_full_nocache(to, copy, from))
			return -EFAULT;
	} else if (!copy_from_iter_full(to, copy, from))
		return -EFAULT;

	return 0;
}

static inline int skb_add_data_nocache(struct sock *sk, struct sk_buff *skb,
				       struct iov_iter *from, int copy)
{
	int err, offset = skb->len;

	
	/* 拷贝用户空间的数据到内核空间，根据skb->ip_summed情况进行校验和的计算。 */
	err = skb_do_copy_data_nocache(sk, skb, from, skb_put(skb, copy),
				       copy, offset);
					   
	/* 如果拷贝失败，恢复skb->len和data room的大小 */
	if (err)
		__skb_trim(skb, offset);

	return err;
}

static inline int skb_copy_to_page_nocache(struct sock *sk, struct iov_iter *from,
					   struct sk_buff *skb,
					   struct page *page,
					   int off, int copy)
{
	int err;

	err = skb_do_copy_data_nocache(sk, skb, from, page_address(page) + off,
				       copy, skb->len);
	if (err)
		return err;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	sk->sk_wmem_queued   += copy;
	sk_mem_charge(sk, copy);
	return 0;
}

/**
 * sk_wmem_alloc_get - returns write allocations
 * @sk: socket
 *
 * Returns sk_wmem_alloc minus initial offset of one
 */
static inline int sk_wmem_alloc_get(const struct sock *sk)
{
	return refcount_read(&sk->sk_wmem_alloc) - 1;
}

/**
 * sk_rmem_alloc_get - returns read allocations
 * @sk: socket
 *
 * Returns sk_rmem_alloc
 */
static inline int sk_rmem_alloc_get(const struct sock *sk)
{
	return atomic_read(&sk->sk_rmem_alloc);
}

/**
 * sk_has_allocations - check if allocations are outstanding
 * @sk: socket
 *
 * Returns true if socket has write or read allocations
 */
static inline bool sk_has_allocations(const struct sock *sk)
{
	return sk_wmem_alloc_get(sk) || sk_rmem_alloc_get(sk);
}

/**
 * skwq_has_sleeper - check if there are any waiting processes
 * @wq: struct socket_wq
 *
 * Returns true if socket_wq has waiting processes
 *
 * The purpose of the skwq_has_sleeper and sock_poll_wait is to wrap the memory
 * barrier call. They were added due to the race found within the tcp code.
 *
 * Consider following tcp code paths::
 *
 *   CPU1                CPU2
 *   sys_select          receive packet
 *   ...                 ...
 *   __add_wait_queue    update tp->rcv_nxt
 *   ...                 ...
 *   tp->rcv_nxt check   sock_def_readable
 *   ...                 {
 *   schedule               rcu_read_lock();
 *                          wq = rcu_dereference(sk->sk_wq);
 *                          if (wq && waitqueue_active(&wq->wait))
 *                              wake_up_interruptible(&wq->wait)
 *                          ...
 *                       }
 *
 * The race for tcp fires when the __add_wait_queue changes done by CPU1 stay
 * in its cache, and so does the tp->rcv_nxt update on CPU2 side.  The CPU1
 * could then endup calling schedule and sleep forever if there are no more
 * data on the socket.
 *
 */
static inline bool skwq_has_sleeper(struct socket_wq *wq)
{
	return wq && wq_has_sleeper(&wq->wait);
}

/**
 * sock_poll_wait - place memory barrier behind the poll_wait call.
 * @filp:           file
 * @sock:           socket to wait on
 * @p:              poll_table
 *
 * See the comments in the wq_has_sleeper function.
 *
 * Do not derive sock from filp->private_data here. An SMC socket establishes
 * an internal TCP socket that is used in the fallback case. All socket
 * operations on the SMC socket are then forwarded to the TCP socket. In case of
 * poll, the filp->private_data pointer references the SMC socket because the
 * TCP socket has no file assigned.
 */
static inline void sock_poll_wait(struct file *filp, struct socket *sock,
				  poll_table *p)
{
	if (!poll_does_not_wait(p)) {

		/* 以select为例：
		 * 这里实际调用 poll_initwait() 中设置的 __pollwait()。
		 * 即添加wait queue中。
		 */
		poll_wait(filp, &sock->wq->wait, p);
		/* We need to be sure we are in sync with the
		 * socket flags modification.
		 *
		 * This memory barrier is paired in the wq_has_sleeper.
		 */
		smp_mb();
	}
}

static inline void skb_set_hash_from_sk(struct sk_buff *skb, struct sock *sk)
{
	if (sk->sk_txhash) {
		skb->l4_hash = 1;
		skb->hash = sk->sk_txhash;
	}
}

void skb_set_owner_w(struct sk_buff *skb, struct sock *sk);

/*
 *	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 *	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */
static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, skb->truesize);
}

void sk_reset_timer(struct sock *sk, struct timer_list *timer,
		    unsigned long expires);

void sk_stop_timer(struct sock *sk, struct timer_list *timer);

int __sk_queue_drop_skb(struct sock *sk, struct sk_buff_head *sk_queue,
			struct sk_buff *skb, unsigned int flags,
			void (*destructor)(struct sock *sk,
					   struct sk_buff *skb));
int __sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);
int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);

int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb);
struct sk_buff *sock_dequeue_err_skb(struct sock *sk);

/*
 *	Recover an error report and clear atomically
 */

static inline int sock_error(struct sock *sk)
{
	int err;
	if (likely(!sk->sk_err))
		return 0;
	err = xchg(&sk->sk_err, 0);
	return -err;
}

static inline unsigned long sock_wspace(struct sock *sk)
{
	int amt = 0;

	if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
		amt = sk->sk_sndbuf - refcount_read(&sk->sk_wmem_alloc);
		if (amt < 0)
			amt = 0;
	}
	return amt;
}

/* Note:
 *  We use sk->sk_wq_raw, from contexts knowing this
 *  pointer is not NULL and cannot disappear/change.
 */
static inline void sk_set_bit(int nr, struct sock *sk)
{
	if ((nr == SOCKWQ_ASYNC_NOSPACE || nr == SOCKWQ_ASYNC_WAITDATA) &&
	    !sock_flag(sk, SOCK_FASYNC))
		return;

	set_bit(nr, &sk->sk_wq_raw->flags);
}

static inline void sk_clear_bit(int nr, struct sock *sk)
{
	if ((nr == SOCKWQ_ASYNC_NOSPACE || nr == SOCKWQ_ASYNC_WAITDATA) &&
	    !sock_flag(sk, SOCK_FASYNC))
		return;

	clear_bit(nr, &sk->sk_wq_raw->flags);
}

/**
 * 将SIGIO或SIGURG信号发送给socket上等待的线程
 *		sk:		该socket上有事件
 *		how:	0-检查是否有rcv调用的进程，1-检查发送队列是否已经达到了上限，
 *			2-不做任何检查，直接发送SIGIO信号，3-向等待进程发送SIGURG信号。
 *		band:	通知进程的IO读写类型，如POLL_IN
 */
static inline void sk_wake_async(const struct sock *sk, int how, int band)
{
	if (sock_flag(sk, SOCK_FASYNC)) {
		rcu_read_lock();
		sock_wake_async(rcu_dereference(sk->sk_wq), how, band);
		rcu_read_unlock();
	}
}

/* Since sk_{r,w}mem_alloc sums skb->truesize, even a small frame might
 * need sizeof(sk_buff) + MTU + padding, unless net driver perform copybreak.
 * Note: for send buffers, TCP works better if we can build two skbs at
 * minimum.
 */
#define TCP_SKB_MIN_TRUESIZE	(2048 + SKB_DATA_ALIGN(sizeof(struct sk_buff)))

#define SOCK_MIN_SNDBUF		(TCP_SKB_MIN_TRUESIZE * 2)
#define SOCK_MIN_RCVBUF		 TCP_SKB_MIN_TRUESIZE

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK)) {
		sk->sk_sndbuf = min(sk->sk_sndbuf, sk->sk_wmem_queued >> 1);
		sk->sk_sndbuf = max_t(u32, sk->sk_sndbuf, SOCK_MIN_SNDBUF);
	}
}

struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp,
				    bool force_schedule);

/**
 * sk_page_frag - return an appropriate page_frag
 * @sk: socket
 *
 * If socket allocation mode allows current thread to sleep, it means its
 * safe to use the per task page_frag instead of the per socket one.
 */
static inline struct page_frag *sk_page_frag(struct sock *sk)
{
	if (gfpflags_allow_blocking(sk->sk_allocation))
		return &current->task_frag;

	return &sk->sk_frag;
}

bool sk_page_frag_refill(struct sock *sk, struct page_frag *pfrag);

/*
 *	Default write policy as shown to user space via poll/select/SIGIO
 */
static inline bool sock_writeable(const struct sock *sk)
{
	return refcount_read(&sk->sk_wmem_alloc) < (sk->sk_sndbuf >> 1);
}

static inline gfp_t gfp_any(void)
{
	return in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
}

static inline long sock_rcvtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	return (waitall ? len : min_t(int, sk->sk_rcvlowat, len)) ? : 1;
}

/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

struct sock_skb_cb {
	u32 dropcount;
};

/* Store sock_skb_cb at the end of skb->cb[] so protocol families
 * using skb->cb[] would keep using it directly and utilize its
 * alignement guarantee.
 */
#define SOCK_SKB_CB_OFFSET ((FIELD_SIZEOF(struct sk_buff, cb) - \
			    sizeof(struct sock_skb_cb)))

#define SOCK_SKB_CB(__skb) ((struct sock_skb_cb *)((__skb)->cb + \
			    SOCK_SKB_CB_OFFSET))

#define sock_skb_cb_check_size(size) \
	BUILD_BUG_ON((size) > SOCK_SKB_CB_OFFSET)

static inline void
sock_skb_set_dropcount(const struct sock *sk, struct sk_buff *skb)
{
	SOCK_SKB_CB(skb)->dropcount = sock_flag(sk, SOCK_RXQ_OVFL) ?
						atomic_read(&sk->sk_drops) : 0;
}

static inline void sk_drops_add(struct sock *sk, const struct sk_buff *skb)
{
	int segs = max_t(u16, 1, skb_shinfo(skb)->gso_segs);

	atomic_add(segs, &sk->sk_drops);
}

static inline ktime_t sock_read_timestamp(struct sock *sk)
{
#if BITS_PER_LONG==32
	unsigned int seq;
	ktime_t kt;

	do {
		seq = read_seqbegin(&sk->sk_stamp_seq);
		kt = sk->sk_stamp;
	} while (read_seqretry(&sk->sk_stamp_seq, seq));

	return kt;
#else
	return sk->sk_stamp;
#endif
}

static inline void sock_write_timestamp(struct sock *sk, ktime_t kt)
{
#if BITS_PER_LONG==32
	write_seqlock(&sk->sk_stamp_seq);
	sk->sk_stamp = kt;
	write_sequnlock(&sk->sk_stamp_seq);
#else
	sk->sk_stamp = kt;
#endif
}

void __sock_recv_timestamp(struct msghdr *msg, struct sock *sk,
			   struct sk_buff *skb);
void __sock_recv_wifi_status(struct msghdr *msg, struct sock *sk,
			     struct sk_buff *skb);

static inline void
sock_recv_timestamp(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
	ktime_t kt = skb->tstamp;
	struct skb_shared_hwtstamps *hwtstamps = skb_hwtstamps(skb);

	/*
	 * generate control messages if
	 * - receive time stamping in software requested
	 * - software time stamp available and wanted
	 * - hardware time stamps available and wanted
	 */
	if (sock_flag(sk, SOCK_RCVTSTAMP) ||
	    (sk->sk_tsflags & SOF_TIMESTAMPING_RX_SOFTWARE) ||
	    (kt && sk->sk_tsflags & SOF_TIMESTAMPING_SOFTWARE) ||
	    (hwtstamps->hwtstamp &&
	     (sk->sk_tsflags & SOF_TIMESTAMPING_RAW_HARDWARE)))
		__sock_recv_timestamp(msg, sk, skb);
	else
		sock_write_timestamp(sk, kt);

	if (sock_flag(sk, SOCK_WIFI_STATUS) && skb->wifi_acked_valid)
		__sock_recv_wifi_status(msg, sk, skb);
}

void __sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
			      struct sk_buff *skb);

#define SK_DEFAULT_STAMP (-1L * NSEC_PER_SEC)
static inline void sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
					  struct sk_buff *skb)
{
#define FLAGS_TS_OR_DROPS ((1UL << SOCK_RXQ_OVFL)			| \
			   (1UL << SOCK_RCVTSTAMP))
#define TSFLAGS_ANY	  (SOF_TIMESTAMPING_SOFTWARE			| \
			   SOF_TIMESTAMPING_RAW_HARDWARE)

	if (sk->sk_flags & FLAGS_TS_OR_DROPS || sk->sk_tsflags & TSFLAGS_ANY)
		__sock_recv_ts_and_drops(msg, sk, skb);
	else if (unlikely(sock_flag(sk, SOCK_TIMESTAMP)))
		sock_write_timestamp(sk, skb->tstamp);
	else if (unlikely(sk->sk_stamp == SK_DEFAULT_STAMP))
		sock_write_timestamp(sk, 0);
}

void __sock_tx_timestamp(__u16 tsflags, __u8 *tx_flags);

/**
 * _sock_tx_timestamp - checks whether the outgoing packet is to be time stamped
 * @sk:		socket sending this packet
 * @tsflags:	timestamping flags to use
 * @tx_flags:	completed with instructions for time stamping
 * @tskey:      filled in with next sk_tskey (not for TCP, which uses seqno)
 *
 * Note: callers should take care of initial ``*tx_flags`` value (usually 0)
 */
static inline void _sock_tx_timestamp(struct sock *sk, __u16 tsflags,
				      __u8 *tx_flags, __u32 *tskey)
{
	if (unlikely(tsflags)) {
		__sock_tx_timestamp(tsflags, tx_flags);
		if (tsflags & SOF_TIMESTAMPING_OPT_ID && tskey &&
		    tsflags & SOF_TIMESTAMPING_TX_RECORD_MASK)
			*tskey = sk->sk_tskey++;
	}
	if (unlikely(sock_flag(sk, SOCK_WIFI_STATUS)))
		*tx_flags |= SKBTX_WIFI_STATUS;
}

static inline void sock_tx_timestamp(struct sock *sk, __u16 tsflags,
				     __u8 *tx_flags)
{
	_sock_tx_timestamp(sk, tsflags, tx_flags, NULL);
}

static inline void skb_setup_tx_timestamp(struct sk_buff *skb, __u16 tsflags)
{
	_sock_tx_timestamp(skb->sk, tsflags, &skb_shinfo(skb)->tx_flags,
			   &skb_shinfo(skb)->tskey);
}

/**
 * sk_eat_skb - Release a skb if it is no longer needed
 * @sk: socket to eat this skb from
 * @skb: socket buffer to eat
 *
 * This routine must be called with interrupts disabled or with the socket
 * locked so that the sk_buff queue operation is ok.
*/
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}

static inline
struct net *sock_net(const struct sock *sk)
{
	return read_pnet(&sk->sk_net);
}

static inline
void sock_net_set(struct sock *sk, struct net *net)
{
	write_pnet(&sk->sk_net, net);
}

static inline struct sock *skb_steal_sock(struct sk_buff *skb)
{
	if (skb->sk) {
		struct sock *sk = skb->sk;

		skb->destructor = NULL;
		skb->sk = NULL;
		return sk;
	}
	return NULL;
}

/* This helper checks if a socket is a full socket,
 * ie _not_ a timewait or request socket.
 */
static inline bool sk_fullsock(const struct sock *sk)
{
	return (1 << sk->sk_state) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
}

/* Checks if this SKB belongs to an HW offloaded socket
 * and whether any SW fallbacks are required based on dev.
 */
static inline struct sk_buff *sk_validate_xmit_skb(struct sk_buff *skb,
						   struct net_device *dev)
{
	/* ubuntu默认打开的 */
#ifdef CONFIG_SOCK_VALIDATE_XMIT
	struct sock *sk = skb->sk;

	if (sk && sk_fullsock(sk) && sk->sk_validate_xmit_skb)
		skb = sk->sk_validate_xmit_skb(sk, dev, skb);
#endif

	return skb;
}

/* This helper checks if a socket is a LISTEN or NEW_SYN_RECV
 * SYNACK messages can be attached to either ones (depending on SYNCOOKIE)
 */
static inline bool sk_listener(const struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_LISTEN | TCPF_NEW_SYN_RECV);
}

void sock_enable_timestamp(struct sock *sk, int flag);
int sock_get_timestamp(struct sock *, struct timeval __user *);
int sock_get_timestampns(struct sock *, struct timespec __user *);
int sock_recv_errqueue(struct sock *sk, struct msghdr *msg, int len, int level,
		       int type);

bool sk_ns_capable(const struct sock *sk,
		   struct user_namespace *user_ns, int cap);
bool sk_capable(const struct sock *sk, int cap);
bool sk_net_capable(const struct sock *sk, int cap);

void sk_get_meminfo(const struct sock *sk, u32 *meminfo);

/* Take into consideration the size of the struct sk_buff overhead in the
 * determination of these values, since that is non-constant across
 * platforms.  This makes socket queueing behavior and performance
 * not depend upon such differences.
 */
#define _SK_MEM_PACKETS		256
#define _SK_MEM_OVERHEAD	SKB_TRUESIZE(256)
#define SK_WMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)
#define SK_RMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)

extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

extern int sysctl_tstamp_allow_data;
extern int sysctl_optmem_max;

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

static inline int sk_get_wmem0(const struct sock *sk, const struct proto *proto)
{
	/* Does this proto have per netns sysctl_wmem ? */
	if (proto->sysctl_wmem_offset)
		return *(int *)((void *)sock_net(sk) + proto->sysctl_wmem_offset);

	return *proto->sysctl_wmem;
}

static inline int sk_get_rmem0(const struct sock *sk, const struct proto *proto)
{
	/* Does this proto have per netns sysctl_rmem ? */
	if (proto->sysctl_rmem_offset)
		return *(int *)((void *)sock_net(sk) + proto->sysctl_rmem_offset);

	return *proto->sysctl_rmem;
}

/* Default TCP Small queue budget is ~1 ms of data (1sec >> 10)
 * Some wifi drivers need to tweak it to get more chunks.
 * They can use this helper from their ndo_start_xmit()
 */
static inline void sk_pacing_shift_update(struct sock *sk, int val)
{
	if (!sk || !sk_fullsock(sk) || sk->sk_pacing_shift == val)
		return;
	sk->sk_pacing_shift = val;
}

/* if a socket is bound to a device, check that the given device
 * index is either the same or that the socket is bound to an L3
 * master device and the given device index is also enslaved to
 * that L3 master
 */
static inline bool sk_dev_equal_l3scope(struct sock *sk, int dif)
{
	int mdif;

	if (!sk->sk_bound_dev_if || sk->sk_bound_dev_if == dif)
		return true;

	mdif = l3mdev_master_ifindex_by_index(sock_net(sk), dif);
	if (mdif && mdif == sk->sk_bound_dev_if)
		return true;

	return false;
}

#endif	/* _SOCK_H */
