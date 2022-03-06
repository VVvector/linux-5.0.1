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
 *
 * Fixes:
 *		Alan Cox	:	Numerous verify_area() calls
 *		Alan Cox	:	Set the ACK bit on a reset
 *		Alan Cox	:	Stopped it crashing if it closed while
 *					sk->inuse=1 and was trying to connect
 *					(tcp_err()).
 *		Alan Cox	:	All icmp error handling was broken
 *					pointers passed where wrong and the
 *					socket was looked up backwards. Nobody
 *					tested any icmp error code obviously.
 *		Alan Cox	:	tcp_err() now handled properly. It
 *					wakes people on errors. poll
 *					behaves and the icmp error race
 *					has gone by moving it into sock.c
 *		Alan Cox	:	tcp_send_reset() fixed to work for
 *					everything not just packets for
 *					unknown sockets.
 *		Alan Cox	:	tcp option processing.
 *		Alan Cox	:	Reset tweaked (still not 100%) [Had
 *					syn rule wrong]
 *		Herp Rosmanith  :	More reset fixes
 *		Alan Cox	:	No longer acks invalid rst frames.
 *					Acking any kind of RST is right out.
 *		Alan Cox	:	Sets an ignore me flag on an rst
 *					receive otherwise odd bits of prattle
 *					escape still
 *		Alan Cox	:	Fixed another acking RST frame bug.
 *					Should stop LAN workplace lockups.
 *		Alan Cox	: 	Some tidyups using the new skb list
 *					facilities
 *		Alan Cox	:	sk->keepopen now seems to work
 *		Alan Cox	:	Pulls options out correctly on accepts
 *		Alan Cox	:	Fixed assorted sk->rqueue->next errors
 *		Alan Cox	:	PSH doesn't end a TCP read. Switched a
 *					bit to skb ops.
 *		Alan Cox	:	Tidied tcp_data to avoid a potential
 *					nasty.
 *		Alan Cox	:	Added some better commenting, as the
 *					tcp is hard to follow
 *		Alan Cox	:	Removed incorrect check for 20 * psh
 *	Michael O'Reilly	:	ack < copied bug fix.
 *	Johannes Stille		:	Misc tcp fixes (not all in yet).
 *		Alan Cox	:	FIN with no memory -> CRASH
 *		Alan Cox	:	Added socket option proto entries.
 *					Also added awareness of them to accept.
 *		Alan Cox	:	Added TCP options (SOL_TCP)
 *		Alan Cox	:	Switched wakeup calls to callbacks,
 *					so the kernel can layer network
 *					sockets.
 *		Alan Cox	:	Use ip_tos/ip_ttl settings.
 *		Alan Cox	:	Handle FIN (more) properly (we hope).
 *		Alan Cox	:	RST frames sent on unsynchronised
 *					state ack error.
 *		Alan Cox	:	Put in missing check for SYN bit.
 *		Alan Cox	:	Added tcp_select_window() aka NET2E
 *					window non shrink trick.
 *		Alan Cox	:	Added a couple of small NET2E timer
 *					fixes
 *		Charles Hedrick :	TCP fixes
 *		Toomas Tamm	:	TCP window fixes
 *		Alan Cox	:	Small URG fix to rlogin ^C ack fight
 *		Charles Hedrick	:	Rewrote most of it to actually work
 *		Linus		:	Rewrote tcp_read() and URG handling
 *					completely
 *		Gerhard Koerting:	Fixed some missing timer handling
 *		Matthew Dillon  :	Reworked TCP machine states as per RFC
 *		Gerhard Koerting:	PC/TCP workarounds
 *		Adam Caldwell	:	Assorted timer/timing errors
 *		Matthew Dillon	:	Fixed another RST bug
 *		Alan Cox	:	Move to kernel side addressing changes.
 *		Alan Cox	:	Beginning work on TCP fastpathing
 *					(not yet usable)
 *		Arnt Gulbrandsen:	Turbocharged tcp_check() routine.
 *		Alan Cox	:	TCP fast path debugging
 *		Alan Cox	:	Window clamping
 *		Michael Riepe	:	Bug in tcp_check()
 *		Matt Dillon	:	More TCP improvements and RST bug fixes
 *		Matt Dillon	:	Yet more small nasties remove from the
 *					TCP code (Be very nice to this man if
 *					tcp finally works 100%) 8)
 *		Alan Cox	:	BSD accept semantics.
 *		Alan Cox	:	Reset on closedown bug.
 *	Peter De Schrijver	:	ENOTCONN check missing in tcp_sendto().
 *		Michael Pall	:	Handle poll() after URG properly in
 *					all cases.
 *		Michael Pall	:	Undo the last fix in tcp_read_urg()
 *					(multi URG PUSH broke rlogin).
 *		Michael Pall	:	Fix the multi URG PUSH problem in
 *					tcp_readable(), poll() after URG
 *					works now.
 *		Michael Pall	:	recv(...,MSG_OOB) never blocks in the
 *					BSD api.
 *		Alan Cox	:	Changed the semantics of sk->socket to
 *					fix a race and a signal problem with
 *					accept() and async I/O.
 *		Alan Cox	:	Relaxed the rules on tcp_sendto().
 *		Yury Shevchuk	:	Really fixed accept() blocking problem.
 *		Craig I. Hagan  :	Allow for BSD compatible TIME_WAIT for
 *					clients/servers which listen in on
 *					fixed ports.
 *		Alan Cox	:	Cleaned the above up and shrank it to
 *					a sensible code size.
 *		Alan Cox	:	Self connect lockup fix.
 *		Alan Cox	:	No connect to multicast.
 *		Ross Biro	:	Close unaccepted children on master
 *					socket close.
 *		Alan Cox	:	Reset tracing code.
 *		Alan Cox	:	Spurious resets on shutdown.
 *		Alan Cox	:	Giant 15 minute/60 second timer error
 *		Alan Cox	:	Small whoops in polling before an
 *					accept.
 *		Alan Cox	:	Kept the state trace facility since
 *					it's handy for debugging.
 *		Alan Cox	:	More reset handler fixes.
 *		Alan Cox	:	Started rewriting the code based on
 *					the RFC's for other useful protocol
 *					references see: Comer, KA9Q NOS, and
 *					for a reference on the difference
 *					between specifications and how BSD
 *					works see the 4.4lite source.
 *		A.N.Kuznetsov	:	Don't time wait on completion of tidy
 *					close.
 *		Linus Torvalds	:	Fin/Shutdown & copied_seq changes.
 *		Linus Torvalds	:	Fixed BSD port reuse to work first syn
 *		Alan Cox	:	Reimplemented timers as per the RFC
 *					and using multiple timers for sanity.
 *		Alan Cox	:	Small bug fixes, and a lot of new
 *					comments.
 *		Alan Cox	:	Fixed dual reader crash by locking
 *					the buffers (much like datagram.c)
 *		Alan Cox	:	Fixed stuck sockets in probe. A probe
 *					now gets fed up of retrying without
 *					(even a no space) answer.
 *		Alan Cox	:	Extracted closing code better
 *		Alan Cox	:	Fixed the closing state machine to
 *					resemble the RFC.
 *		Alan Cox	:	More 'per spec' fixes.
 *		Jorge Cwik	:	Even faster checksumming.
 *		Alan Cox	:	tcp_data() doesn't ack illegal PSH
 *					only frames. At least one pc tcp stack
 *					generates them.
 *		Alan Cox	:	Cache last socket.
 *		Alan Cox	:	Per route irtt.
 *		Matt Day	:	poll()->select() match BSD precisely on error
 *		Alan Cox	:	New buffers
 *		Marc Tamsky	:	Various sk->prot->retransmits and
 *					sk->retransmits misupdating fixed.
 *					Fixed tcp_write_timeout: stuck close,
 *					and TCP syn retries gets used now.
 *		Mark Yarvis	:	In tcp_read_wakeup(), don't send an
 *					ack if state is TCP_CLOSED.
 *		Alan Cox	:	Look up device on a retransmit - routes may
 *					change. Doesn't yet cope with MSS shrink right
 *					but it's a start!
 *		Marc Tamsky	:	Closing in closing fixes.
 *		Mike Shaver	:	RFC1122 verifications.
 *		Alan Cox	:	rcv_saddr errors.
 *		Alan Cox	:	Block double connect().
 *		Alan Cox	:	Small hooks for enSKIP.
 *		Alexey Kuznetsov:	Path MTU discovery.
 *		Alan Cox	:	Support soft errors.
 *		Alan Cox	:	Fix MTU discovery pathological case
 *					when the remote claims no mtu!
 *		Marc Tamsky	:	TCP_CLOSE fix.
 *		Colin (G3TNE)	:	Send a reset on syn ack replies in
 *					window but wrong (fixes NT lpd problems)
 *		Pedro Roque	:	Better TCP window handling, delayed ack.
 *		Joerg Reuter	:	No modification of locked buffers in
 *					tcp_do_retransmit()
 *		Eric Schenk	:	Changed receiver side silly window
 *					avoidance algorithm to BSD style
 *					algorithm. This doubles throughput
 *					against machines running Solaris,
 *					and seems to result in general
 *					improvement.
 *	Stefan Magdalinski	:	adjusted tcp_readable() to fix FIONREAD
 *	Willy Konynenberg	:	Transparent proxying support.
 *	Mike McLagan		:	Routing by source
 *		Keith Owens	:	Do proper merging with partial SKB's in
 *					tcp_do_sendmsg to avoid burstiness.
 *		Eric Schenk	:	Fix fast close down bug with
 *					shutdown() followed by close().
 *		Andi Kleen 	:	Make poll agree with SIGIO
 *	Salvatore Sanfilippo	:	Support SO_LINGER with linger == 1 and
 *					lingertime == 0 (RFC 793 ABORT Call)
 *	Hirokazu Takahashi	:	Use copy_from_user() instead of
 *					csum_and_copy_from_user() if possible.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 *
 * Description of States:
 *
 *	TCP_SYN_SENT		sent a connection request, waiting for ack
 *
 *	TCP_SYN_RECV		received a connection request, sent ack,
 *				waiting for final ack in three-way handshake.
 *
 *	TCP_ESTABLISHED		connection established
 *
 *	TCP_FIN_WAIT1		our side has shutdown, waiting to complete
 *				transmission of remaining buffered data
 *
 *	TCP_FIN_WAIT2		all buffered data sent, waiting for remote
 *				to shutdown
 *
 *	TCP_CLOSING		both sides have shutdown but we still have
 *				data we have to finish sending
 *
 *	TCP_TIME_WAIT		timeout to catch resent junk before entering
 *				closed, can only be entered from FIN_WAIT2
 *				or CLOSING.  Required because the other end
 *				may not have gotten our last ACK causing it
 *				to retransmit the data packet (which we ignore)
 *
 *	TCP_CLOSE_WAIT		remote side has shutdown and is waiting for
 *				us to finish writing our data and to shutdown
 *				(we have to close() to move on to LAST_ACK)
 *
 *	TCP_LAST_ACK		out side has shutdown after remote has
 *				shutdown.  There may still be data in our
 *				buffer that we have to finish sending
 *
 *	TCP_CLOSE		socket is finished
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <crypto/hash.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/inet_diag.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>
#include <linux/splice.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <linux/memblock.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/cache.h>
#include <linux/err.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/errqueue.h>
#include <linux/static_key.h>

#include <net/icmp.h>
#include <net/inet_common.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/ip.h>
#include <net/sock.h>

#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <net/busy_poll.h>

struct percpu_counter tcp_orphan_count;
EXPORT_SYMBOL_GPL(tcp_orphan_count);

long sysctl_tcp_mem[3] __read_mostly;
EXPORT_SYMBOL(sysctl_tcp_mem);

atomic_long_t tcp_memory_allocated;	/* Current allocated memory. */
EXPORT_SYMBOL(tcp_memory_allocated);

#if IS_ENABLED(CONFIG_SMC)
DEFINE_STATIC_KEY_FALSE(tcp_have_smc);
EXPORT_SYMBOL(tcp_have_smc);
#endif

/*
 * Current number of TCP sockets.
 */
struct percpu_counter tcp_sockets_allocated;
EXPORT_SYMBOL(tcp_sockets_allocated);

/*
 * TCP splice context
 */
struct tcp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

/*
 * Pressure flag: try to collapse.
 * Technical note: it is used by multiple contexts non atomically.
 * All the __sk_mem_schedule() is of this nature: accounting
 * is strict, actions are advisory and have some latency.
 */
unsigned long tcp_memory_pressure __read_mostly;
EXPORT_SYMBOL_GPL(tcp_memory_pressure);

void tcp_enter_memory_pressure(struct sock *sk)
{
	unsigned long val;

	if (tcp_memory_pressure)
		return;
	val = jiffies;

	if (!val)
		val--;
	if (!cmpxchg(&tcp_memory_pressure, 0, val))
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMEMORYPRESSURES);
}
EXPORT_SYMBOL_GPL(tcp_enter_memory_pressure);

void tcp_leave_memory_pressure(struct sock *sk)
{
	unsigned long val;

	if (!tcp_memory_pressure)
		return;
	val = xchg(&tcp_memory_pressure, 0);
	if (val)
		NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPMEMORYPRESSURESCHRONO,
			      jiffies_to_msecs(jiffies - val));
}
EXPORT_SYMBOL_GPL(tcp_leave_memory_pressure);

/* Convert seconds to retransmits based on initial and max timeout */
static u8 secs_to_retrans(int seconds, int timeout, int rto_max)
{
	u8 res = 0;

	if (seconds > 0) {
		int period = timeout;

		res = 1;
		while (seconds > period && res < 255) {
			res++;
			timeout <<= 1;
			if (timeout > rto_max)
				timeout = rto_max;
			period += timeout;
		}
	}
	return res;
}

/* Convert retransmits to seconds based on initial and max timeout */
static int retrans_to_secs(u8 retrans, int timeout, int rto_max)
{
	int period = 0;

	if (retrans > 0) {
		period = timeout;
		while (--retrans) {
			timeout <<= 1;
			if (timeout > rto_max)
				timeout = rto_max;
			period += timeout;
		}
	}
	return period;
}

static u64 tcp_compute_delivery_rate(const struct tcp_sock *tp)
{
	u32 rate = READ_ONCE(tp->rate_delivered);
	u32 intv = READ_ONCE(tp->rate_interval_us);
	u64 rate64 = 0;

	if (rate && intv) {
		rate64 = (u64)rate * tp->mss_cache * USEC_PER_SEC;
		do_div(rate64, intv);
	}
	return rate64;
}

/* Address-family independent initialization for a tcp_sock.
 *
 * NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
/* 应用层创建socket时，会被调用到。
 * socket() -> inet_creat() -> .init()
 */
void tcp_init_sock(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* 初始化乱序队列，重传队列 */
	tp->out_of_order_queue = RB_ROOT;
	sk->tcp_rtx_queue = RB_ROOT;

	/* tcp 相关的timer初始化 */
	tcp_init_xmit_timers(sk);
	INIT_LIST_HEAD(&tp->tsq_node);
	INIT_LIST_HEAD(&tp->tsorted_sent_queue);

	/* 初始化数据包重传时间为  1秒。*/
	icsk->icsk_rto = TCP_TIMEOUT_INIT;
	/* 设置为1秒 */
	tp->mdev_us = jiffies_to_usecs(TCP_TIMEOUT_INIT);

	minmax_reset(&tp->rtt_min, tcp_jiffies32, ~0U);

	/* 拥塞算法相关 */
	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	/* 发送拥塞窗口的大小 google研究表明 10 */
	tp->snd_cwnd = TCP_INIT_CWND;

	/* There's a bubble in the pipe until at least the first ACK. */
	tp->app_limited = ~0U;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	/* send slow start threshold */
	/* 慢启动和拥塞避免的阈值，初始值很大。0x7fffffff */
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH; 
	tp->snd_cwnd_clamp = ~0;
	tp->mss_cache = TCP_MSS_DEFAULT;

	/* 按系统配置控制值初始化TCP选项结构的重排序域 */
	tp->reordering = sock_net(sk)->ipv4.sysctl_tcp_reordering;
	tcp_assign_congestion_control(sk);

	tp->tsoffset = 0;
	tp->rack.reo_wnd_steps = 1;

	sk->sk_state = TCP_CLOSE;

	/* 当套接字的写缓冲区有效时，调用该函数。 */
	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	icsk->icsk_sync_mss = tcp_sync_mss;

	/* socket的发送缓冲区和接收缓冲区初始化 */
	sk->sk_sndbuf = sock_net(sk)->ipv4.sysctl_tcp_wmem[1];
	sk->sk_rcvbuf = sock_net(sk)->ipv4.sysctl_tcp_rmem[1];

	sk_sockets_allocated_inc(sk);
	sk->sk_route_forced_caps = NETIF_F_GSO;
}
EXPORT_SYMBOL(tcp_init_sock);

void tcp_init_transfer(struct sock *sk, int bpf_op)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	tcp_mtup_init(sk);
	icsk->icsk_af_ops->rebuild_header(sk);
	tcp_init_metrics(sk);
	tcp_call_bpf(sk, bpf_op, 0, NULL);
	tcp_init_congestion_control(sk);
	tcp_init_buffer_space(sk);
}

static void tcp_tx_timestamp(struct sock *sk, u16 tsflags)
{
	struct sk_buff *skb = tcp_write_queue_tail(sk);

	if (tsflags && skb) {
		struct skb_shared_info *shinfo = skb_shinfo(skb);
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

		sock_tx_timestamp(sk, tsflags, &shinfo->tx_flags);
		if (tsflags & SOF_TIMESTAMPING_TX_ACK)
			tcb->txstamp_ack = 1;
		if (tsflags & SOF_TIMESTAMPING_TX_RECORD_MASK)
			shinfo->tskey = TCP_SKB_CB(skb)->seq + skb->len - 1;
	}
}

static inline bool tcp_stream_is_readable(const struct tcp_sock *tp,
					  int target, struct sock *sk)
{
	return (tp->rcv_nxt - tp->copied_seq >= target) ||
		(sk->sk_prot->stream_memory_read ?
		sk->sk_prot->stream_memory_read(sk) : false);
}

/*
 *	Wait for a TCP event.
 *
 *	Note that we don't need to lock the socket, as the upper poll layers
 *	take care of normal races (between the test and the event) and we don't
 *	go look at any of the socket buffers directly.
 */
__poll_t tcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	__poll_t mask;
	struct sock *sk = sock->sk;
	const struct tcp_sock *tp = tcp_sk(sk);
	int state;

	sock_poll_wait(file, sock, wait);

	state = inet_sk_state_load(sk);
	if (state == TCP_LISTEN)
		return inet_csk_listen_poll(sk);

	/* Socket is not locked. We are protected from async events
	 * by poll logic and correct handling of state changes
	 * made by other threads is impossible in any case.
	 */

	mask = 0;

	/*
	 * EPOLLHUP is certainly not done right. But poll() doesn't
	 * have a notion of HUP in just one direction, and for a
	 * socket the read side is more interesting.
	 *
	 * Some poll() documentation says that EPOLLHUP is incompatible
	 * with the EPOLLOUT/POLLWR flags, so somebody should check this
	 * all. But careful, it tends to be safer to return too many
	 * bits than too few, and you can easily break real applications
	 * if you don't tell them that something has hung up!
	 *
	 * Check-me.
	 *
	 * Check number 1. EPOLLHUP is _UNMASKABLE_ event (see UNIX98 and
	 * our fs/select.c). It means that after we received EOF,
	 * poll always returns immediately, making impossible poll() on write()
	 * in state CLOSE_WAIT. One solution is evident --- to set EPOLLHUP
	 * if and only if shutdown has been made in both directions.
	 * Actually, it is interesting to look how Solaris and DUX
	 * solve this dilemma. I would prefer, if EPOLLHUP were maskable,
	 * then we could set it on SND_SHUTDOWN. BTW examples given
	 * in Stevens' books assume exactly this behaviour, it explains
	 * why EPOLLHUP is incompatible with EPOLLOUT.	--ANK
	 *
	 * NOTE. Check for TCP_CLOSE is added. The goal is to prevent
	 * blocking on fresh not-connected or disconnected socket. --ANK
	 */
	if (sk->sk_shutdown == SHUTDOWN_MASK || state == TCP_CLOSE)
		mask |= EPOLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;

	/* Connected or passive Fast Open socket? */
	if (state != TCP_SYN_SENT &&
	    (state != TCP_SYN_RECV || tp->fastopen_rsk)) {
		int target = sock_rcvlowat(sk, 0, INT_MAX);

		if (tp->urg_seq == tp->copied_seq &&
		    !sock_flag(sk, SOCK_URGINLINE) &&
		    tp->urg_data)
			target++;

		if (tcp_stream_is_readable(tp, target, sk))
			mask |= EPOLLIN | EPOLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_is_writeable(sk)) {
				mask |= EPOLLOUT | EPOLLWRNORM;
			} else {  /* send SIGIO later */
				sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost. Memory barrier
				 * pairs with the input side.
				 */
				smp_mb__after_atomic();
				if (sk_stream_is_writeable(sk))
					mask |= EPOLLOUT | EPOLLWRNORM;
			}
		} else
			mask |= EPOLLOUT | EPOLLWRNORM;

		if (tp->urg_data & TCP_URG_VALID)
			mask |= EPOLLPRI;
	} else if (state == TCP_SYN_SENT && inet_sk(sk)->defer_connect) {
		/* Active TCP fastopen socket with defer_connect
		 * Return EPOLLOUT so application can call write()
		 * in order for kernel to generate SYN+data
		 */
		mask |= EPOLLOUT | EPOLLWRNORM;
	}
	/* This barrier is coupled with smp_wmb() in tcp_reset() */
	smp_rmb();
	if (sk->sk_err || !skb_queue_empty(&sk->sk_error_queue))
		mask |= EPOLLERR;

	return mask;
}
EXPORT_SYMBOL(tcp_poll);

int tcp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int answ;
	bool slow;

	switch (cmd) {
	case SIOCINQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		slow = lock_sock_fast(sk);
		answ = tcp_inq(sk);
		unlock_sock_fast(sk, slow);
		break;
	case SIOCATMARK:
		answ = tp->urg_data && tp->urg_seq == tp->copied_seq;
		break;
	case SIOCOUTQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else
			answ = tp->write_seq - tp->snd_una;
		break;
	case SIOCOUTQNSD:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else
			answ = tp->write_seq - tp->snd_nxt;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return put_user(answ, (int __user *)arg);
}
EXPORT_SYMBOL(tcp_ioctl);

/* 标记一个数据包的 PUSH 位 */
static inline void tcp_mark_push(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH; /* 设置PSH标志 */
	tp->pushed_seq = tp->write_seq; /* 记录本次PUSH的最后一个字节序号 */
	
}

/*
 * TCP 协议提供了 PUSH 功能，只要添加了该标志位， TCP 层会尽快地将数据发送
 * 出去。以往多用于传输程序的控制命令。在目前的多数 TCP 实现中，用户往往不会自
 * 行指定 PUSH。 TCP 的实现会根据情况自行指定 PUSH 位
*/
static inline bool forced_push(const struct tcp_sock *tp)
{
	/* 当上一次被 PUSH 出去的包的序号和当前的序号
	 * 相差超过窗口的一半时，会强行被 PUSH。
	 * 从这里可以看出，在 Linux 中，如果缓存的数据量超过了窗口大小的一半以上，就会被尽快发送出去。
	 */
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

static void skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	skb->csum    = 0;

	/* 更新该packet的发送 sequence */
	tcb->seq     = tcb->end_seq = tp->write_seq;

	/* 设置ack flag */
	tcb->tcp_flags = TCPHDR_ACK;
	tcb->sacked  = 0;
	__skb_header_release(skb);

	/* 将本skb添加到发送队列中 */
	tcp_add_write_queue_tail(sk, skb);

	/* 更新该socket的还未发送的data长度 */
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);

	if (tp->nonagle & TCP_NAGLE_PUSH)
		tp->nonagle &= ~TCP_NAGLE_PUSH;

	/* 慢启动检查 SSR - Slow Start Restart
	 * TCP实现了一个慢启动重新启动（SSR）机制，该机制在一段时间内空闲后重新设置连接的拥塞窗口。
	 * 理由很简单：在连接空闲时，网络条件可能发生了变化，为了避免拥塞，窗口被重置为“安全”默认值。
	 * 如果当前时间与最后一次的发送时间差值大于RTO时长，开启慢启动。
	 * sysctl -w net.ipv4.tcp_slow_start_after_idle=0
	 */
	tcp_slow_start_after_idle_check(sk);
}

static inline void tcp_mark_urg(struct tcp_sock *tp, int flags)
{
	if (flags & MSG_OOB)
		tp->snd_up = tp->write_seq;
}

/* If a not yet filled skb is pushed, do not send it if
 * we have data packets in Qdisc or NIC queues :
 * Because TX completion will happen shortly, it gives a chance
 * to coalesce future sendmsg() payload into this skb, without
 * need for a timer, and with no latency trade off.
 * As packets containing data payload have a bigger truesize
 * than pure acks (dataless) packets, the last checks prevent
 * autocorking if we only have an ACK in Qdisc/NIC queues,
 * or if TX completion was delayed after we processed ACK packet.
 */
/*
 * 当应用程序连续地发送小包时，如果能够把这些小包合成一个全尺寸的包再发送，无疑可以减少
 * 总的发包个数。tcp_autocorking的思路是：当规则队列Qdisc、或网卡的发送队列中有尚未发出的
 * 数据包时，那么就延迟小包的发送，等待应用层的后续数据，直到Qdisc或网卡发送队列的数据
 * 包成功发送出去为止。
 * 
 * 同时满足以下条件时，tcp_push()才会自动阻塞：
 * 	1. 数据包为小包，即数据长度小于最大值size_goal( MSS )。
 * 	2. 使用了tcp_autocorking( /proc/sys/net/ipv4/tcp_autocorking )，这个值默认为1。
 * 	3. 当前skb不是发送队列头，表明已经有数据发送。（此数据包不是发送队列的第一个包，即前面有数据包被发送了。）
 * 	4. 当前正在发送的数据的总truesize长度大于此skb的truesize，
 * 	   表明位于Qdisc或者设备队列中的数据不是仅有ACK报文，所以TX发送处理不会被延迟。
 * 
 * Q：什么时候会取消自动阻塞呢？
 * A：在tcp_push()中会检查，if (atomic_read(&sk->sk_wmem_alloc) > skb->truesize)
 * 当提交给IP层的数据包都发送出去后，sk_wmem_alloc的值就会变小，此时这个条件就为假，
 * 之后可以发送被阻塞的数据包了。
 */
static bool tcp_should_autocork(struct sock *sk, struct sk_buff *skb,
				int size_goal)
{
	return skb->len < size_goal &&
	       sock_net(sk)->ipv4.sysctl_tcp_autocorking &&
	       !tcp_rtx_queue_empty(sk) &&
	       refcount_read(&sk->sk_wmem_alloc) > skb->truesize;
}

/* 
 * tcp_sendmsg()中，在sock发送缓存不足、系统内存不足或应用层的数据都拷贝完毕等情况下，
 * 都会调用tcp_push()来把已经拷贝到发送队列中的数据给发送出去。
	工作：
		1. 检查是否有未发送过的数据
		2. 检查是否需要设置PSH标志
		3. 检查是否使用紧急模式
		4. 检查是否需要使用自动阻塞
		5. 尽可能地把发送队列中的skb发送出去
*/
static void tcp_push(struct sock *sk, int flags, int mss_now,
		     int nonagle, int size_goal)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* 如果没有未发送过的数据了，就直接返回。*/
	skb = tcp_write_queue_tail(sk);
	if (!skb)
		return;

	/* 如果接下来没有更多的数据需要发送，或者距离上次PUSH后又有比较多的数据，
	 * 那么就需要设置PSH标志，让接收端马上把接收缓存中的数据提交给应用程序。
	 */
	if (!(flags & MSG_MORE) || forced_push(tp))
		tcp_mark_push(tp, skb);

	/* 如果设置了MSG_OOB标志，就记录紧急指针。 */
	tcp_mark_urg(tp, flags);

	/* 当应用程序连续地发送小包时，如果能够把这些小包合成一个全尺寸的包再发送，无疑可以减少
		总的发包个数。tcp_autocorking的思路是当规则队列Qdisc、或网卡的发送队列中有尚未发出的
		数据包时，那么就延迟小包的发送，等待应用层的后续数据，直到Qdisc或网卡发送队列的数据
		包成功发送出去为止。
	*/
	/* 如果需要自动阻塞小包, 有相关条件进行判断。*/
	if (tcp_should_autocork(sk, skb, size_goal)) {

		/* 设置阻塞标志位 */
		/* avoid atomic op if TSQ_THROTTLED bit is already set */
		if (!test_bit(TSQ_THROTTLED, &sk->sk_tsq_flags)) {
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPAUTOCORKING);
			set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);
		}

		/* 当提交给IP层的数据包都发送出去后，sk_wmem_alloc的值就会变小，
		 * 此时这个条件就为假，之后就可以发送被阻塞的数据包了。
		 */
		/* It is possible TX completion already happened
		 * before we set TSQ_THROTTLED.
		 */
		if (refcount_read(&sk->sk_wmem_alloc) > skb->truesize)
			return;
	}

	/* 如果之后还有更多的数据，那么使用TCP_CORK,  显式地阻塞发送 */
	if (flags & MSG_MORE)
		nonagle = TCP_NAGLE_CORK;

	/* 尽可能地把发送队列中的skb发送出去，
	 * 如果发送失败，检查是否需要启动零窗口探测定时器。
	 */
	__tcp_push_pending_frames(sk, mss_now, nonagle);
}

static int tcp_splice_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
				unsigned int offset, size_t len)
{
	struct tcp_splice_state *tss = rd_desc->arg.data;
	int ret;

	ret = skb_splice_bits(skb, skb->sk, offset, tss->pipe,
			      min(rd_desc->count, len), tss->flags);
	if (ret > 0)
		rd_desc->count -= ret;
	return ret;
}

static int __tcp_splice_read(struct sock *sk, struct tcp_splice_state *tss)
{
	/* Store TCP splice context information in read_descriptor_t. */
	read_descriptor_t rd_desc = {
		.arg.data = tss,
		.count	  = tss->len,
	};

	return tcp_read_sock(sk, &rd_desc, tcp_splice_data_recv);
}

/**
 *  tcp_splice_read - splice data from TCP socket to a pipe
 * @sock:	socket to splice from
 * @ppos:	position (not valid)
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given socket and fill them into a pipe.
 *
 **/
ssize_t tcp_splice_read(struct socket *sock, loff_t *ppos,
			struct pipe_inode_info *pipe, size_t len,
			unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct tcp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	long timeo;
	ssize_t spliced;
	int ret;

	sock_rps_record_flow(sk);
	/*
	 * We can't seek on a socket input
	 */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, sock->file->f_flags & O_NONBLOCK);
	while (tss.len) {
		ret = __tcp_splice_read(sk, &tss);
		if (ret < 0)
			break;
		else if (!ret) {
			if (spliced)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			/* if __tcp_splice_read() got nothing while we have
			 * an skb in receive queue, we do not want to loop.
			 * This might happen with URG data.
			 */
			if (!skb_queue_empty(&sk->sk_receive_queue))
				break;
			sk_wait_data(sk, &timeo, NULL);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;

		if (!timeo)
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);

	if (spliced)
		return spliced;

	return ret;
}
EXPORT_SYMBOL(tcp_splice_read);

struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp,
				    bool force_schedule)
{
	struct sk_buff *skb;

	/* The TCP header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);

	if (unlikely(tcp_under_memory_pressure(sk)))
		sk_mem_reclaim_partial(sk);

	/* 分配指定长度的skb */
	skb = alloc_skb_fclone(size + sk->sk_prot->max_header, gfp);
	if (likely(skb)) {
		bool mem_scheduled;

		if (force_schedule) {
			mem_scheduled = true;
			sk_forced_mem_schedule(sk, skb->truesize);
		} else {
			mem_scheduled = sk_wmem_schedule(sk, skb->truesize);
		}
		if (likely(mem_scheduled)) {
			skb_reserve(skb, sk->sk_prot->max_header);
			/*
			 * Make sure that we have exactly size bytes
			 * available to the caller, no more, no less.
			 */
			skb->reserved_tailroom = skb->end - skb->tail - size;
			INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
			return skb;
		}
		__kfree_skb(skb);
	} else {
		/* 内存不足，进入警告状态，同时调整发送缓存大小上限 */
		sk->sk_prot->enter_memory_pressure(sk);
		sk_stream_moderate_sndbuf(sk);
	}
	return NULL;
}

static unsigned int tcp_xmit_size_goal(struct sock *sk, u32 mss_now,
				       int large_allowed)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 new_size_goal, size_goal;

	/* 这里的larg_allowed表示是否是紧急数据
	 * 这里表示是紧急数据，就不会做gso，即返回skb大小为mss。
	 */
	if (!large_allowed)
		return mss_now;

	/* Note : tcp_tso_autosize() will eventually split this later */

	/* sk->sk_gso_max_size 是从对应的 dev->gso_max_size 获取到的。即该sock对应
	 * 的最大gso size是由device决定。默认是65535。
	 * 这里表示 65535减去协议层头部（包括选项部分）
	 */
	new_size_goal = sk->sk_gso_max_size - 1 - MAX_TCP_HEADER;

	/* 调整 new_size_goal 不能超过对端接收窗口的一半。 */
	new_size_goal = tcp_bound_to_half_wnd(tp, new_size_goal);

	/* We try hard to avoid divides here */
	/* 调整返回的skb最大容量为mss的整数倍 */
	size_goal = tp->gso_segs * mss_now;
	if (unlikely(new_size_goal < size_goal ||
		     new_size_goal >= size_goal + mss_now)) {
		tp->gso_segs = min_t(u16, new_size_goal / mss_now,
				     sk->sk_gso_max_segs);
		size_goal = tp->gso_segs * mss_now;
	}

	return max(size_goal, mss_now);
}

/* gso数据包长度：
 * 对于紧急数据包或者GSO/TSO都不开启的情况，才不会推迟发送，默认使用当前MSS。
 * 开启GSO后，用tcp_send_mss()获取一个gso skb的大小(为MSS的整数倍)和MSS分段大小。
 */
static int tcp_send_mss(struct sock *sk, int *size_goal, int flags)
{
	int mss_now;

	/* 获取tcp mss */
	mss_now = tcp_current_mss(sk);

	/* 计算获取skb能容纳的最大数据量，为MSS的整数倍。
	 * 后续tcp_sendmsg()在组织skb时，就以size_goal为上界填充数据。
	 */
	*size_goal = tcp_xmit_size_goal(sk, mss_now, !(flags & MSG_OOB));

	return mss_now;
}

ssize_t do_tcp_sendpages(struct sock *sk, struct page *page, int offset,
			 size_t size, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mss_now, size_goal;
	int err;
	ssize_t copied;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&
	    !tcp_passive_fastopen(sk)) {
		err = sk_stream_wait_connect(sk, &timeo);
		if (err != 0)
			goto out_err;
	}

	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	mss_now = tcp_send_mss(sk, &size_goal, flags);
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	while (size > 0) {
		struct sk_buff *skb = tcp_write_queue_tail(sk);
		int copy, i;
		bool can_coalesce;

		if (!skb || (copy = size_goal - skb->len) <= 0 ||
		    !tcp_skb_can_collapse_to(skb)) {
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			skb = sk_stream_alloc_skb(sk, 0, sk->sk_allocation,
					tcp_rtx_and_write_queues_empty(sk));
			if (!skb)
				goto wait_for_memory;

			skb_entail(sk, skb);
			copy = size_goal;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		can_coalesce = skb_can_coalesce(skb, i, page, offset);
		if (!can_coalesce && i >= sysctl_max_skb_frags) {
			tcp_mark_push(tp, skb);
			goto new_segment;
		}
		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		if (can_coalesce) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		}

		if (!(flags & MSG_NO_SHARED_FRAGS))
			skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;

		skb->len += copy;
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		sk_mem_charge(sk, copy);
		skb->ip_summed = CHECKSUM_PARTIAL;
		tp->write_seq += copy;
		TCP_SKB_CB(skb)->end_seq += copy;
		tcp_skb_pcount_set(skb, 0);

		if (!copied)
			TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;

		copied += copy;
		offset += copy;
		size -= copy;
		if (!size)
			goto out;

		if (skb->len < size_goal || (flags & MSG_OOB))
			continue;

		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
		} else if (skb == tcp_send_head(sk))
			tcp_push_one(sk, mss_now);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

wait_for_memory:
		tcp_push(sk, flags & ~MSG_MORE, mss_now,
			 TCP_NAGLE_PUSH, size_goal);

		err = sk_stream_wait_memory(sk, &timeo);
		if (err != 0)
			goto do_error;

		mss_now = tcp_send_mss(sk, &size_goal, flags);
	}

out:
	if (copied) {
		tcp_tx_timestamp(sk, sk->sk_tsflags);
		if (!(flags & MSG_SENDPAGE_NOTLAST))
			tcp_push(sk, flags, mss_now, tp->nonagle, size_goal);
	}
	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 &&
		     err == -EAGAIN)) {
		sk->sk_write_space(sk);
		tcp_chrono_stop(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
	return sk_stream_error(sk, flags, err);
}
EXPORT_SYMBOL_GPL(do_tcp_sendpages);

int tcp_sendpage_locked(struct sock *sk, struct page *page, int offset,
			size_t size, int flags)
{
	if (!(sk->sk_route_caps & NETIF_F_SG))
		return sock_no_sendpage_locked(sk, page, offset, size, flags);

	tcp_rate_check_app_limited(sk);  /* is sending application-limited? */

	return do_tcp_sendpages(sk, page, offset, size, flags);
}
EXPORT_SYMBOL_GPL(tcp_sendpage_locked);

int tcp_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	int ret;

	lock_sock(sk);
	ret = tcp_sendpage_locked(sk, page, offset, size, flags);
	release_sock(sk);

	return ret;
}
EXPORT_SYMBOL(tcp_sendpage);

/* Do not bother using a page frag for very small frames.
 * But use this heuristic only for the first skb in write queue.
 *
 * Having no payload in skb->head allows better SACK shifting
 * in tcp_shift_skb_data(), reducing sack/rack overhead, because
 * write queue has less skbs.
 * Each skb can hold up to MAX_SKB_FRAGS * 32Kbytes, or ~0.5 MB.
 * This also speeds up tso_fragment(), since it wont fallback
 * to tcp_fragment().
 */
static int linear_payload_sz(bool first_skb)
{
	if (first_skb)
		return SKB_WITH_OVERHEAD(2048 - MAX_TCP_HEADER);
	return 0;
}

static int select_size(bool first_skb, bool zc)
{
	if (zc)
		return 0;
	return linear_payload_sz(first_skb);
}

void tcp_free_fastopen_req(struct tcp_sock *tp)
{
	if (tp->fastopen_req) {
		kfree(tp->fastopen_req);
		tp->fastopen_req = NULL;
	}
}

/* 如果启用了 Fast Open，则会在这里分配一个tcp_fastopen_request结构体，并将
 * 用户消息和大小填写到对应的字段上。
*/
static int tcp_sendmsg_fastopen(struct sock *sk, struct msghdr *msg,
				int *copied, size_t size)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr *uaddr = msg->msg_name;
	int err, flags;

	/* 如果没有开启该功能，返回错误值 */
	if (!(sock_net(sk)->ipv4.sysctl_tcp_fastopen & TFO_CLIENT_ENABLE) ||
	    (uaddr && msg->msg_namelen >= sizeof(uaddr->sa_family) &&
	     uaddr->sa_family == AF_UNSPEC))
		return -EOPNOTSUPP;

	/* 如果已经有要发送的数据了，返回错误值 */
	if (tp->fastopen_req)
		return -EALREADY; /* Another Fast Open is in progress */

	/* 分配空间, 并将用户数据块赋值给相应字段 */
	tp->fastopen_req = kzalloc(sizeof(struct tcp_fastopen_request),
				   sk->sk_allocation);
	if (unlikely(!tp->fastopen_req))
		return -ENOBUFS;
	tp->fastopen_req->data = msg;
	tp->fastopen_req->size = size;

	if (inet->defer_connect) {
		err = tcp_connect(sk);
		/* Same failure procedure as in tcp_v4/6_connect */
		if (err) {
			tcp_set_state(sk, TCP_CLOSE);
			inet->inet_dport = 0;
			sk->sk_route_caps = 0;
		}
	}
	flags = (msg->msg_flags & MSG_DONTWAIT) ? O_NONBLOCK : 0;

	/* 由于 fast open 时，连接还未建立，因此，这里直接调用了下面的
	 * 函数建立连接。这样数据就可以在连接建立的过程中被发送出去了。
	 */
	err = __inet_stream_connect(sk->sk_socket, uaddr,
				    msg->msg_namelen, flags, 1);
	/* fastopen_req could already be freed in __inet_stream_connect
	 * if the connection times out or gets rst
	 */
	if (tp->fastopen_req) {
		*copied = tp->fastopen_req->copied;
		tcp_free_fastopen_req(tp);
		inet->defer_connect = 0;
	}
	return err;
}

/* tcp 发送函数
 * sendmsg系统调用在tcp层的实现是tcp_sendmsg函数，该函数完成以下任务：
 * 从用户空间读取数据，拷贝到内核skb，将skb加入到发送队列的任务，调用发送函数；
 * 函数在执行过程中会锁定控制块，避免软中断在tcp层的影响；
 * 函数核心流程：
 * 在发送数据时，查看是否能够将数据合并到发送队列中最后一个skb中，如果不能合并，
 * 则新申请一个skb；拷贝过程中，如果skb的线性区域有空间，则优先使用线性区域，
 * 线性区域空间不足，则使用分页区域；拷贝完成后，调用发送函数发送数据；
 *
 * 注：这时不一定会真正开始发送，如果没有达到发送条件的话，很可能这次系统调用就直接返回了。
 *
 * 应用程序send()数据后，会在tcp_sendmsg()中尝试在同一个skb，
 * 保存size_goal大小的数据，然后再通过tcp_push()把这些包通过tcp_write_xmit()发出去
 */
int tcp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ubuf_info *uarg = NULL;
	struct sk_buff *skb;
	struct sockcm_cookie sockc;
	int flags, err, copied = 0;
	int mss_now = 0, size_goal, copied_syn = 0;
	bool process_backlog = false;
	bool zc = false;
	long timeo;

	/* user space是通过socket sendmsg()接口下发数据。 */
	flags = msg->msg_flags;

	/* 零拷贝的传输，例如 sendfile() */
	if (flags & MSG_ZEROCOPY && size && sock_flag(sk, SOCK_ZEROCOPY)) {
		/* 连接情况检查, 即socket只有在下面两个状态才能发送数据。 */
		if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) {
			err = -EINVAL;
			goto out_err;
		}

		/* 写入skb到sk_write_queue发送队列中 */
		skb = tcp_write_queue_tail(sk);
		uarg = sock_zerocopy_realloc(sk, size, skb_zcopy(skb));
		if (!uarg) {
			err = -ENOBUFS;
			goto out_err;
		}

		/* 检查给sock对应的route 即net dev是否有SG能力 */
		zc = sk->sk_route_caps & NETIF_F_SG;
		if (!zc)
			uarg->zerocopy = 0;
	}

	/* 1.如果使用了TCP Fast Open, 则会发送SYN包, 同时携带上数据 */
	if (unlikely(flags & MSG_FASTOPEN || inet_sk(sk)->defer_connect) &&
	    !tp->repair) {
		err = tcp_sendmsg_fastopen(sk, msg, &copied_syn, size);
		if (err == -EINPROGRESS && copied_syn > 0)
			goto out;
		else if (err)
			goto out_err;
	}

	/* 获取socket timetout时间 */
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	tcp_rate_check_app_limited(sk);  /* is sending application-limited? */

	/* 2. 如果连接尚未建立好，即不处于ESTABLISHED或者CLOSE_WAIT状态，那么
	 * 进程进行睡眠，等待三次握手的完成。即不允许发送数据，不过，这里有一种例外情况，
	 * 如果是处于 Fast Open 的被动端的话，是可以在三次连接的过程中带上数据的。 */
	
	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&
	    !tcp_passive_fastopen(sk)) {
	    	/* 等待连接的建立，成功时，返回0. */
		err = sk_stream_wait_connect(sk, &timeo);
		if (err != 0)
			goto do_error;
	}

	/* TCP repair 是 Linux3.5 引入的新补丁，它能够实现容器在不同的物理主机间迁移。
	 * 它能够在迁移之后，将 TCP 连接重新设置到之前的状态。 
	 */
	if (unlikely(tp->repair)) {
		if (tp->repair_queue == TCP_RECV_QUEUE) {
			/* 发送到接收队列中 */
			copied = tcp_send_rcvq(sk, msg, size);
			goto out_nopush;
		}

		err = -EINVAL;
		if (tp->repair_queue == TCP_NO_QUEUE)
			goto out_err;

		/* 'common' sending to sendq */
	}

	sockcm_init(&sockc, sk);
	if (msg->msg_controllen) {
		err = sock_cmsg_send(sk, msg, &sockc);
		if (unlikely(err)) {
			err = -EINVAL;
			goto out_err;
		}
	}

	/* 清除使用异步情况下，发送队列满了的标志 */
	/* This should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	/* copied 是已经从用户数据块复制出来的字节数。 */
	/* Ok commence sending. */
	copied = 0;

restart:
	/* 3. 获取当前的MSS, 网络设备支持的最大单个skb长度size_goal,
		如果支持GSO, size_goal会是MSS的整数倍，否则，会等于mss。*/
	mss_now = tcp_send_mss(sk, &size_goal, flags);

	/* 如果连接有错误，或者不允许发送数据了，则返回-EPIPE */
	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	/* 4. 遍历用户层的数据块数组, 把用户数据全部发送出去。 */
	/* 从用户地址空间复制数据到socket buffer，即sk->sk_write_queue*/
	while (msg_data_left(msg)) {

		/* copy 代表本次需要从用户数据块中复制的数据量。 */
		int copy = 0;

		/* 4.1 获取发送队列的最后一个skb，并且判断当前skb剩余的能携带的数据量。
		 * 如果是尚未发送的，且长度尚未达到size_goal,那么可以往此skb继续追加数据。
		 */
		skb = tcp_write_queue_tail(sk);
		if (skb)
			copy = size_goal - skb->len;

		/* 如果剩余空间为0，或者不能合并，则需要重新申请skb进行发送。
 		 * 也隐含着数据不能合并到之前的skb做gso了。MSG_EOR - end of record
 		 */
		if (copy <= 0 || !tcp_skb_can_collapse_to(skb)) {
			bool first_skb;
			int linear;

new_segment:
			/* 如果发送队列的总大小sk_wmen_queued大于等于发送缓存的上限sk_sndbuf,
			 * 或者发送缓存中尚未发送的数据量超过了用户的设置值，就进入等待sock的发送缓存可写事件。
			 */
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			/* 这里也会flush因为在memory不足而等待的这段时间里，RX方向的收包数据。
			 * 将backlog的数据包flush给user。即调用 tcp_v4_do_rcv()
			 */
			if (process_backlog && sk_flush_backlog(sk)) {
				process_backlog = false;
				goto restart;
			}

			/* 申请一个skb，其线性数据区的大小为：
			 * 通过select_size()得到线性数区中TCP负荷的大小 + 最大的协议头长度。
			 * 如果申请失败，就进入等待。
			 * 注：
			 * 这里会从TCP层面来判断发送缓存的申请是否合法。即需要判断TCP层面的内存
			 * 使用量，以及此socket的发送缓存使用量。
			 * 这里会在数据区的头部预留足够的空间，即可以存放tcp, ip, ethernet的首部。
			 */
			first_skb = tcp_rtx_and_write_queues_empty(sk);
			linear = select_size(first_skb, zc); //2048 - tcp header
			skb = sk_stream_alloc_skb(sk, linear, sk->sk_allocation,
						  first_skb);
			if (!skb)
				goto wait_for_memory;

			process_backlog = true;

			/* 这里tcp checksum初始化为CHECKSUM_PARTIAL。
			 * 1. 表示协议栈只做ip头和伪头部的checksum，payload需要硬件帮忙做。
			 * 2. 后面的数据，放到 /net/core/dev.c中的 xmit_one()中做最后确定是否计算。
			 * 如果网卡支持校验和计算，那么由硬件计算报头和首部的校验和。
			 */
			skb->ip_summed = CHECKSUM_PARTIAL;

			/* 更新skb的TCP控制块字段tcb，并把skb加入到sock发送队列的尾部。
			 * 增加发送队列 sk_write_queue 的大小，减少预分配缓存的大小。
			 * 注：
			 * 如果该tcp sock有TCP_NAGLE_PUSH, 这里会去掉该flag。因为已经进行了聚包GSO。
			 */
			skb_entail(sk, skb);

			/* 这里将每次copy的大小设置为size_goal，上面动态获取的 */
			copy = size_goal;

			/* 如果使用了TCP_REPAIR选项，即不为skb设置“发送时间” */
			/* All packets are restored as if they have
			 * already been sent. skb_mstamp_ns isn't set to
			 * avoid wrong rtt estimation.
			 */
			if (tp->repair)
				TCP_SKB_CB(skb)->sacked |= TCPCB_REPAIRED;
		}

		/* 本次可拷贝的user数据量不能超过数据块的长度 */
		/* Try to append data to the end of skb. */
		if (copy > msg_data_left(msg))
			copy = msg_data_left(msg);

		/* 1. 如果skb的线性数据区还有剩余空间，就先复制到线性数据区 */
		/* Where to copy to? */
		if (skb_availroom(skb) > 0 && !zc) {
			/* We have some space in skb head. Superb! */
			copy = min_t(int, copy, skb_availroom(skb));

			/* 拷贝用户空间的数据到skb的线性区 */
			err = skb_add_data_nocache(sk, skb, &msg->msg_iter, copy);
			if (err)
				goto do_fault;

		/* 2. 如果skb的线性数据区已经用完了，那么就使用分页区 skb->frags[] */
		} else if (!zc) {
			bool merge = true;
			int i = skb_shinfo(skb)->nr_frags; //分页数
			struct page_frag *pfrag = sk_page_frag(sk); //上次缓存的分页

			/* 检查分页是否有可用空间，如果没有，就申请新的page。例如，会先尝试申请8 pages。 */
			if (!sk_page_frag_refill(sk, pfrag))
				goto wait_for_memory;

			/* 判断能否往最后一个分页中追加数据 */
			/* 如果不能追加了，就重新分配skb。 */
			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				/* 检查分页数是否达到了上限，如果是，就设置PSH标志，并尽快发送出去
				 * 然后，跳转到new_segment处申请新的skb，来继续填装数据。
				 */
				if (i >= sysctl_max_skb_frags) {
					tcp_mark_push(tp, skb);
					goto new_segment;
				}
				merge = false;
			}

			copy = min_t(int, copy, pfrag->size - pfrag->offset);

			/* 从系统层面判断发送缓存的申请是否合法 */
			if (!sk_wmem_schedule(sk, copy))
				goto wait_for_memory;

			/* 拷贝用户空间的数据到内核空间page中。
			 * 更新skb的长度，更新sock的发送队列大小和预分配缓存
			 */
			err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
						       pfrag->page,
						       pfrag->offset,
						       copy);
			if (err)
				goto do_error;


			/* 如果把数据追加到最后一个分页了，更新最后一个分页的数据大小。 */
			/* Update the skb. */
			if (merge) {
				skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			} else {
				/* 初始化新增加的页 */
				skb_fill_page_desc(skb, i, pfrag->page,
						   pfrag->offset, copy);
				page_ref_inc(pfrag->page);
			}

			/* 更新pfrag的page offset */
			pfrag->offset += copy;

		/* 支持零拷贝模式 */
		} else {
			err = skb_zerocopy_iter_stream(sk, skb, msg, copy, uarg);
			if (err == -EMSGSIZE || err == -EEXIST) {
				tcp_mark_push(tp, skb);
				goto new_segment;
			}
			if (err < 0)
				goto do_error;
			copy = err;
		}

		/* 如果这是第一次拷贝，就取消PSH标志 */
		if (!copied)
			TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;


		/* 更新该tcp socket的写sequence */
		tp->write_seq += copy; 

		/* 更新该skb的结束序号 */
		TCP_SKB_CB(skb)->end_seq += copy;

		/* 清零tso分段数，后面 tcp_write_xmit() 会计算 */
		tcp_skb_pcount_set(skb, 0);

		/* 已经拷贝到发送队列的数据量 */
		copied += copy; 

		/* 如果所有的用户数据都已经被copy到skb，就尝试发送。*/
		if (!msg_data_left(msg)) {
			if (unlikely(flags & MSG_EOR))
				TCP_SKB_CB(skb)->eor = 1;
			goto out;
		}

		/* 如果用户数据没有全部被copy到skb，即skb还可用继续填充，或者发送的是带外数据，
		 *或者使用了TCP_REPAIR选项，就继续拷贝数据，先不发送。*/
		if (skb->len < size_goal || (flags & MSG_OOB) || unlikely(tp->repair))
			continue;

		/* 如果本skb的数据量已经大于了size_goal，就要开始发送数据。 */

		/* 判断是否需要立即发送：
		 *	如果待发送的数据量大于对方接收窗口的一半了，就马上发送。
		 */
		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			
			/* 尽可能的将发送队列中的skb发送出去，禁用nalge */
			__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);

		/*如果sk->sk_write_queue中只有一个skb，就发送一个skb */
		} else if (skb == tcp_send_head(sk))
			tcp_push_one(sk, mss_now);

		continue;

		/* 如果socket没有了足够的缓冲区或者页面，则等到有一定数据量的有效缓冲区后再发送。
		 * 即socket的发送buffer中的数据量大于了本socket设置的最大send buffer 上限了。
		 */
wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

wait_for_memory:
		/* 如果已经有数据复制到发送队列了，就尝试立即发送。 */
		if (copied)
			tcp_push(sk, flags & ~MSG_MORE, mss_now,
				 TCP_NAGLE_PUSH, size_goal);

		/* 有两种等待情况：
		 * 1. sock的发送缓存不足，等待sock有发送缓存可写事件，或者超时。
		 * 2. TCP层内存不足，等待2-202ms之间的一个随机时间。
		 */
		err = sk_stream_wait_memory(sk, &timeo);
		if (err != 0)
			goto do_error;

		/* 睡眠后，MSS和TSO段长可能会发生变化，重新计算。 */
		mss_now = tcp_send_mss(sk, &size_goal, flags);
	}

	
out:
	/* 如果发生了超时或者要正常退出，且已经拷贝了数据，那么尝试将该数据发出 */
	if (copied) {
		tcp_tx_timestamp(sk, sockc.tsflags);
		tcp_push(sk, flags, mss_now, tp->nonagle, size_goal);
	}

out_nopush:
	/* 返回已经发出的数据量。 */
	sock_zerocopy_put(uarg);
	return copied + copied_syn;

do_fault:
	/* 当拷贝数据发送异常时，会进入这个分支。如果当前的 SKB 是新分配的，
	 * 那么，将该 SKB 从发送队列中去除，并释放该 SKB。
	 */
	if (!skb->len) {
		tcp_unlink_write_queue(skb, sk); //把skb从发送队列中删除
		/* It is the one place in all of TCP, except connection
		 * reset, where we can be unlinking the send_head.
		 */
		tcp_check_send_head(sk, skb); //是否要撤销sk->sk_send_head
		sk_wmem_free_skb(sk, skb); //更新发送队列的大小和预分配缓存，释放skb
	}

do_error:
	/* 如果已经拷贝了数据，那么，就将其发出。 */
	if (copied + copied_syn)
		goto out;
out_err:
	sock_zerocopy_put_abort(uarg, true);
	err = sk_stream_error(sk, flags, err);
	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 &&
		     err == -EAGAIN)) {
		sk->sk_write_space(sk);
		tcp_chrono_stop(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
	return err;
}
EXPORT_SYMBOL_GPL(tcp_sendmsg_locked);

/*tcp 的 send 函数：
 *	将数据从用户地址空间复制到内核socket buffer
*/
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	int ret;

	/* 对套接字加锁，防止多user同时写的并发，以及软中断的影响。 */
	lock_sock(sk);
	ret = tcp_sendmsg_locked(sk, msg, size);
	release_sock(sk);

	return ret;
}
EXPORT_SYMBOL(tcp_sendmsg);

/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int tcp_recv_urg(struct sock *sk, struct msghdr *msg, int len, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data ||
	    tp->urg_data == TCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (tp->urg_data & TCP_URG_VALID) {
		int err = 0;
		char c = tp->urg_data;

		if (!(flags & MSG_PEEK))
			tp->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_to_msg(msg, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

static int tcp_peek_sndq(struct sock *sk, struct msghdr *msg, int len)
{
	struct sk_buff *skb;
	int copied = 0, err = 0;

	/* XXX -- need to support SO_PEEK_OFF */

	skb_rbtree_walk(skb, &sk->tcp_rtx_queue) {
		err = skb_copy_datagram_msg(skb, 0, msg, skb->len);
		if (err)
			return err;
		copied += skb->len;
	}

	skb_queue_walk(&sk->sk_write_queue, skb) {
		err = skb_copy_datagram_msg(skb, 0, msg, skb->len);
		if (err)
			break;

		copied += skb->len;
	}

	return err ?: copied;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
static void tcp_cleanup_rbuf(struct sock *sk, int copied)
{
	struct tcp_sock *tp = tcp_sk(sk);
	bool time_to_ack = false;

	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

	WARN(skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq),
	     "cleanup rbuf bug: copied %X seq %X rcvnxt %X\n",
	     tp->copied_seq, TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt);

	if (inet_csk_ack_scheduled(sk)) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = true;
	}

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2*rcv_window_now <= tp->window_clamp) {
			__u32 new_window = __tcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = true;
		}
	}
	if (time_to_ack)
		tcp_send_ack(sk);
}

static struct sk_buff *tcp_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;
	u32 offset;

	while ((skb = skb_peek(&sk->sk_receive_queue)) != NULL) {
		offset = seq - TCP_SKB_CB(skb)->seq;
		if (unlikely(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
			pr_err_once("%s: found a SYN, please report !\n", __func__);
			offset--;
		}
		if (offset < skb->len || (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)) {
			*off = offset;
			return skb;
		}
		/* This looks weird, but this can happen if TCP collapsing
		 * splitted a fat GRO packet, while we released socket lock
		 * in skb_splice_bits()
		 */
		sk_eat_skb(sk, skb);
	}
	return NULL;
}

/*
 * This routine provides an alternative to tcp_recvmsg() for routines
 * that would like to handle copying from skbuffs directly in 'sendfile'
 * fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int tcp_read_sock(struct sock *sk, read_descriptor_t *desc,
		  sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;

	if (sk->sk_state == TCP_LISTEN)
		return -ENOTCONN;
	while ((skb = tcp_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			int used;
			size_t len;

			len = skb->len - offset;
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;
				if (!len)
					break;
			}
			used = recv_actor(desc, skb, offset, len);
			if (used <= 0) {
				if (!copied)
					copied = used;
				break;
			} else if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			/* If recv_actor drops the lock (e.g. TCP splice
			 * receive) the skb pointer might be invalid when
			 * getting here: tcp_collapse might have deleted it
			 * while aggregating skbs from the socket queue.
			 */
			skb = tcp_recv_skb(sk, seq - 1, &offset);
			if (!skb)
				break;
			/* TCP coalescing might have appended data to the skb.
			 * Try to splice more frags
			 */
			if (offset + 1 != skb->len)
				continue;
		}
		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) {
			sk_eat_skb(sk, skb);
			++seq;
			break;
		}
		sk_eat_skb(sk, skb);
		if (!desc->count)
			break;
		tp->copied_seq = seq;
	}
	tp->copied_seq = seq;

	tcp_rcv_space_adjust(sk);

	/* Clean up data we have read: This will do ACK frames. */
	if (copied > 0) {
		tcp_recv_skb(sk, seq, &offset);
		tcp_cleanup_rbuf(sk, copied);
	}
	return copied;
}
EXPORT_SYMBOL(tcp_read_sock);

int tcp_peek_len(struct socket *sock)
{
	return tcp_inq(sock->sk);
}
EXPORT_SYMBOL(tcp_peek_len);

/* Make sure sk_rcvbuf is big enough to satisfy SO_RCVLOWAT hint */
int tcp_set_rcvlowat(struct sock *sk, int val)
{
	int cap;

	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK)
		cap = sk->sk_rcvbuf >> 1;
	else
		cap = sock_net(sk)->ipv4.sysctl_tcp_rmem[2] >> 1;
	val = min(val, cap);
	sk->sk_rcvlowat = val ? : 1;

	/* Check if we need to signal EPOLLIN right now */
	tcp_data_ready(sk);

	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK)
		return 0;

	val <<= 1;
	if (val > sk->sk_rcvbuf) {
		sk->sk_rcvbuf = val;
		tcp_sk(sk)->window_clamp = tcp_win_from_space(sk, val);
	}
	return 0;
}
EXPORT_SYMBOL(tcp_set_rcvlowat);

#ifdef CONFIG_MMU
static const struct vm_operations_struct tcp_vm_ops = {
};

int tcp_mmap(struct file *file, struct socket *sock,
	     struct vm_area_struct *vma)
{
	if (vma->vm_flags & (VM_WRITE | VM_EXEC))
		return -EPERM;
	vma->vm_flags &= ~(VM_MAYWRITE | VM_MAYEXEC);

	/* Instruct vm_insert_page() to not down_read(mmap_sem) */
	vma->vm_flags |= VM_MIXEDMAP;

	vma->vm_ops = &tcp_vm_ops;
	return 0;
}
EXPORT_SYMBOL(tcp_mmap);

static int tcp_zerocopy_receive(struct sock *sk,
				struct tcp_zerocopy_receive *zc)
{
	unsigned long address = (unsigned long)zc->address;
	const skb_frag_t *frags = NULL;
	u32 length = 0, seq, offset;
	struct vm_area_struct *vma;
	struct sk_buff *skb = NULL;
	struct tcp_sock *tp;
	int inq;
	int ret;

	if (address & (PAGE_SIZE - 1) || address != zc->address)
		return -EINVAL;

	if (sk->sk_state == TCP_LISTEN)
		return -ENOTCONN;

	sock_rps_record_flow(sk);

	down_read(&current->mm->mmap_sem);

	ret = -EINVAL;
	vma = find_vma(current->mm, address);
	if (!vma || vma->vm_start > address || vma->vm_ops != &tcp_vm_ops)
		goto out;
	zc->length = min_t(unsigned long, zc->length, vma->vm_end - address);

	tp = tcp_sk(sk);
	seq = tp->copied_seq;
	inq = tcp_inq(sk);
	zc->length = min_t(u32, zc->length, inq);
	zc->length &= ~(PAGE_SIZE - 1);
	if (zc->length) {
		zap_page_range(vma, address, zc->length);
		zc->recv_skip_hint = 0;
	} else {
		zc->recv_skip_hint = inq;
	}
	ret = 0;
	while (length + PAGE_SIZE <= zc->length) {
		if (zc->recv_skip_hint < PAGE_SIZE) {
			if (skb) {
				skb = skb->next;
				offset = seq - TCP_SKB_CB(skb)->seq;
			} else {
				skb = tcp_recv_skb(sk, seq, &offset);
			}

			zc->recv_skip_hint = skb->len - offset;
			offset -= skb_headlen(skb);
			if ((int)offset < 0 || skb_has_frag_list(skb))
				break;
			frags = skb_shinfo(skb)->frags;
			while (offset) {
				if (frags->size > offset)
					goto out;
				offset -= frags->size;
				frags++;
			}
		}
		if (frags->size != PAGE_SIZE || frags->page_offset) {
			int remaining = zc->recv_skip_hint;

			while (remaining && (frags->size != PAGE_SIZE ||
					     frags->page_offset)) {
				remaining -= frags->size;
				frags++;
			}
			zc->recv_skip_hint -= remaining;
			break;
		}
		ret = vm_insert_page(vma, address + length,
				     skb_frag_page(frags));
		if (ret)
			break;
		length += PAGE_SIZE;
		seq += PAGE_SIZE;
		zc->recv_skip_hint -= PAGE_SIZE;
		frags++;
	}
out:
	up_read(&current->mm->mmap_sem);
	if (length) {
		tp->copied_seq = seq;
		tcp_rcv_space_adjust(sk);

		/* Clean up data we have read: This will do ACK frames. */
		tcp_recv_skb(sk, seq, &offset);
		tcp_cleanup_rbuf(sk, length);
		ret = 0;
		if (length == zc->length)
			zc->recv_skip_hint = 0;
	} else {
		if (!zc->recv_skip_hint && sock_flag(sk, SOCK_DONE))
			ret = -EIO;
	}
	zc->length = length;
	return ret;
}
#endif

static void tcp_update_recv_tstamps(struct sk_buff *skb,
				    struct scm_timestamping *tss)
{
	if (skb->tstamp)
		tss->ts[0] = ktime_to_timespec(skb->tstamp);
	else
		tss->ts[0] = (struct timespec) {0};

	if (skb_hwtstamps(skb)->hwtstamp)
		tss->ts[2] = ktime_to_timespec(skb_hwtstamps(skb)->hwtstamp);
	else
		tss->ts[2] = (struct timespec) {0};
}

/* Similar to __sock_recv_timestamp, but does not require an skb */
static void tcp_recv_timestamp(struct msghdr *msg, const struct sock *sk,
			       struct scm_timestamping *tss)
{
	struct timeval tv;
	bool has_timestamping = false;

	if (tss->ts[0].tv_sec || tss->ts[0].tv_nsec) {
		if (sock_flag(sk, SOCK_RCVTSTAMP)) {
			if (sock_flag(sk, SOCK_RCVTSTAMPNS)) {
				put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMPNS,
					 sizeof(tss->ts[0]), &tss->ts[0]);
			} else {
				tv.tv_sec = tss->ts[0].tv_sec;
				tv.tv_usec = tss->ts[0].tv_nsec / 1000;

				put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMP,
					 sizeof(tv), &tv);
			}
		}

		if (sk->sk_tsflags & SOF_TIMESTAMPING_SOFTWARE)
			has_timestamping = true;
		else
			tss->ts[0] = (struct timespec) {0};
	}

	if (tss->ts[2].tv_sec || tss->ts[2].tv_nsec) {
		if (sk->sk_tsflags & SOF_TIMESTAMPING_RAW_HARDWARE)
			has_timestamping = true;
		else
			tss->ts[2] = (struct timespec) {0};
	}

	if (has_timestamping) {
		tss->ts[1] = (struct timespec) {0};
		put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMPING,
			 sizeof(*tss), tss);
	}
}

static int tcp_inq_hint(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 copied_seq = READ_ONCE(tp->copied_seq);
	u32 rcv_nxt = READ_ONCE(tp->rcv_nxt);
	int inq;

	inq = rcv_nxt - copied_seq;
	if (unlikely(inq < 0 || copied_seq != READ_ONCE(tp->copied_seq))) {
		lock_sock(sk);
		inq = tp->rcv_nxt - tp->copied_seq;
		release_sock(sk);
	}
	return inq;
}

/*
 *	This routine copies from a sock struct into the user buffer.
 *
 *	Technical note: in 2.3 we work on _locked_ socket, so that
 *	tricks with *seq access order and skb->users are not required.
 *	Probably, code can be easily improved even more.
 */
/* TCP套接字层的接收函数：
	当用户进程通过获得信号得知在打开的套接字上有数据等待用户进程来接收时，
	用户进程调用receive和read系统调用来读取套接字缓冲区中的数据。当这些
	系统调用将读取的数据传送到套接字层时，转而会调用tcp_recvmsg函数来执行
	具体的传送操作。tcp_recvmsg函数从打开的套接字上将数据复制到用户缓冲区。
*/
int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{
	/* 从套接字数据结构获取TCP套接字结构 */
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err, inq;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct sk_buff *skb, *last;
	u32 urg_hole = 0;
	struct scm_timestamping tss;
	bool has_tss = false;
	bool has_cmsg;

	/* 如果只是为了接收来自套接字错误队列的错误，那就直接执行如下函数。 */
	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len, addr_len);

	if (sk_can_busy_loop(sk) && skb_queue_empty(&sk->sk_receive_queue) &&
	    (sk->sk_state == TCP_ESTABLISHED))
		sk_busy_loop(sk, nonblock);

	/*
	 * 在用户进程进行读取数据之前，必须对传输层进行加锁，这主要时为了在读的过程中，软中断
	 * 操作传输层，从而造成数据的不同步甚至更为严重的不可预料的结果。
	 */

	lock_sock(sk);

	/* 如果当前套接字处于侦听状态，说明还没数据等待接收，跳出。 */
	err = -ENOTCONN;

	/*
	 * 如果此时只是处于 LISTEN 状态，表明尚未建立连接，
	 * 此时不允许用户读取数据, 只能返回。
	 */
	if (sk->sk_state == TCP_LISTEN)
		goto out;

	has_cmsg = tp->recvmsg_inq;

	/*
	 * 获取阻塞读取的超时时间，如果进行非阻塞读取，则超时时间为 0。
	 */
	timeo = sock_rcvtimeo(sk, nonblock);

	/* 如果设置了MSG_OOB标志处理紧急数据 - 即输入段设置了URG标志，seq
	初始化为下一个准备读的字节。读取带外数据 */
	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)
		goto recv_urg;

	if (unlikely(tp->repair)) {
		err = -EPERM;

		/* 如果只是查看数据的话，就直接跳转到 out 处理 */
		if (!(flags & MSG_PEEK))
			goto out;

		if (tp->repair_queue == TCP_SEND_QUEUE)
			goto recv_sndq;

		err = -EINVAL;
		if (tp->repair_queue == TCP_NO_QUEUE)
			goto out;

		/* 'common' recv queue MSG_PEEK-ing */
	}

	/*
	 * 接下来进行数据复制。在把数据从接收缓存复制到用户空间的过程中，会更新当前
	 * 已复制位置，以及段序号。如果接收数据，则会更新 copied_seq, 但是如果只是查看数
	 * 据而并不是从系统缓冲区移走数据，那么不能更新 copied_seq。因此，数据复制到用户
	 * 空间的过程中，区别接收数据还是查看数据是根据是否更新 copied_seq，所以这里时根
	 * 据接收数据还是查看来获取要更新标记的地址，而后面的复制操作就完全不关心时接收
	 * 还是查看。
	 */
	seq = &tp->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}

	/* 将本次读的字节数target，设置为sk->rcvlowat和len中小的值。MSG_WAITALL指明本次调用是否会阻塞。
	 * 根据是否设置了 MSG_WAITALL 来确定本次调用需要接
	 * 收数据的长度。如果设置了 MSG_WAITALL 标志，则读取数据长度为用户调用时输入
	 * 的参数 len。
	 */
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	/* 循环复制字节到用户空间，直到达到target。 */
	do {
		u32 offset;

		/* 接下来通过 urg_data 和 urg_seq 来检测当前是否读取到紧急数据。如果在读紧急
		 * 数据，则终止本次正常数据的读取。否则，如果用户进程有信号待处理，则也终止本次
		 * 的读取。 
		 */
		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		if (tp->urg_data && tp->urg_seq == *seq) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
				break;
			}
		}

		/* Next get a buffer. */
	
		/* 从socket的接收队列中取出一个skb。*/
		last = skb_peek_tail(&sk->sk_receive_queue);

		/* 遍历接收队列接收数据 */
		skb_queue_walk(&sk->sk_receive_queue, skb) {
			last = skb;

			/*
			 * 如果接收队列中的段序号比较大，则说明也获取不到下一个待获取的段，
			 * 这样也只能接着处理后备队列，实际上这种情况不应该发生。
			 */
			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(*seq, TCP_SKB_CB(skb)->seq),
				 "TCP recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
				 *seq, TCP_SKB_CB(skb)->seq, tp->rcv_nxt,
				 flags))
				break;

			/* 到此，我们已经获取了下一个要读取的数据段，计算该段开始读取数据的偏移位置，
			 * 当然，该偏移值必须在该段的数据长度范围内才有效。 
			 */
			offset = *seq - TCP_SKB_CB(skb)->seq;

			/*
			 * 由于 SYN 标志占用了一个序号，因此如果存在 SYN 标志，则需要调整
			 * 偏移。由于偏移 offset 为无符号整型，因此，不会出现负数的情况。
			 */
			if (unlikely(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
				pr_err_once("%s: found a SYN, please report !\n", __func__);
				offset--;
			}

			/*
			 * 只有当偏移在该段的数据长度范围内，才说明待读的段才是有效的，因此，接下来
			 * 跳转到 found_ok_skb 标签处读取数据。
			 */
			if (offset < skb->len)
				goto found_ok_skb;

			/* 如果接收到的段中有 FIN 标识，则跳转到 found_fin_ok 处处理。 */
			if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
				goto found_fin_ok;
			WARN(!(flags & MSG_PEEK),
			     "TCP recvmsg seq # bug 2: copied %X, seq %X, rcvnxt %X, fl %X\n",
			     *seq, TCP_SKB_CB(skb)->seq, tp->rcv_nxt, flags);
		}

		/* 只有在读取完数据后，才能在后备队列不为空的情况下区处理接收到后备队列中的
		 * TCP 段。否则终止本次读取。 
		 * 由于是因为用户进程对传输控制块进行的锁定，网卡上来的数据 TCP 段会被缓存到后备队列，故
		 * 而，一旦用户进程释放传输控制块就应该立即处理后备队列。处理后备队列直接在 release_sock() 中实现，
		 * 以确保在任何时候解锁传输控制块时能立即处理后备队列。
		 */
		/* Well, if we have backlog, try to process it now yet. */
		if (copied >= target && !sk->sk_backlog.tail)
			break;

		/* 这里必须做一些相应的检查看是否应停止处理数据包，看套接字是否已经关闭或从远端收到端口连接要求 -  
		 * 在接收数据包中有RST标志。

		 * 当接收队列中可以读取的段已经读完，在处理后备队列之前，我们需
		 * 要先检查是否会存在一些异常的情况。如果存在这类情况，就需要结束这次读取，返回
		 * 前当然还顺便检测后备队列是否存在数据，如果有则还需要处理。
		 */
		if (copied) {
			/* 1. 有错误发生 2.TCP处于CLOSE状态 3.shutdown状态 4.收到信号 5.只是查看数据 */
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			/* 检测 TCP 会话是否即将终结 */
			if (sock_flag(sk, SOCK_DONE))
				break;

			/* 如果有错误，返回错误码 */
			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			/* 如果是 shutdown，返回 */
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			/* 说明应用程序试图从未建立起连接的套接字上读数据，这是一个错误条件。 */
			if (sk->sk_state == TCP_CLOSE) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
				copied = -ENOTCONN;
				break;
			}

			/* 未读到数据，且是非阻塞读取，则返回错误码 Try again。 */
			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			/* 检测是否收到数据，并返回相应的错误码 */
			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		/* 检测是否有确认需要立即发送 */
		tcp_cleanup_rbuf(sk, copied);

		/*
		 * 继续处理, 如果读取完数据，则调用 release_sock 来解锁传输控制块，主要用来处
		 * 理后备队列，完成后再调用 lock_sock 锁定传输控制块。在调用 release_sock 的时候，
		 * 进程有可能会出现休眠。
		 * 如果数据尚未读取，且是阻塞读取，则进入睡眠等待接收数据。这种情况下， tcp_v4_do_rcv
		 * 处理 TCP 段时可能会把数据直接复制到用户空间
		*/
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else {
			/* 没有收到足够的数据，就阻塞当前进程。 */
			sk_wait_data(sk, &timeo, last);
		}

		/* 如果有更新 copied_seq，且只是查看数据，则需要更新 peek_seq。
		 * 然后继续获取下一个段进行处理。 
		 */
		if ((flags & MSG_PEEK) &&
		    (peek_seq - copied - urg_hole != tp->copied_seq)) {
			net_dbg_ratelimited("TCP(%s:%d): Application bug, race in MSG_PEEK\n",
					    current->comm,
					    task_pid_nr(current));
			peek_seq = tp->copied_seq;
		}
		continue;


		/* 这里前面的循环中，我们发现在接收队列中有数据段时，就跳到此处。从skb->len数据域计算有
		 * 多少数据要复制，以及它们的偏移量。
		* 获取该可读取段的数据长度，在前面的处理中已由 TCP 序号得到本次读取数据在该段中的偏移。
		*/
found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;

		/* Do we have urgent data here? */
		/*
		 * 如果该段中包含紧急数据，则获取紧急数据在该段中的偏移。
		 * 如果偏移在该段可读的范围内，则表示紧急数据有效。
		 * 进而
		 * 如果紧急数据偏移为 0, 则说明目前需要的数据正是紧急数据，
		 * 且紧急数据不允许放入到正常的数据流中，即在普通的数据数据
		 * 流中接受紧急数据，则需要调整读取正常数据流的一些参数，如已
		 * 读取数据的序号、正常数据的偏移等。最后，如果可读数据经过调
		 * 整之后为 0，则说明没有数据可读，跳过本次读数据过程到 skip_copy 处
		 * 处理。
		 * 如果紧急数据偏移不为 0, 则需要调整本次读取的正常长度直到读到紧急
		 * 数据为止。
		 */

		*/
		if (tp->urg_data) {
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						urg_hole++;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}


		/* 复制数据到用户地址空间 */
		if (!(flags & MSG_TRUNC)) {
			/*
			 * 调用 skb_copy_datagram_msg 来将数据复制到用户空间
			 * 并且根据返回的值来判断是否出现了错误。
			 */
			err = skb_copy_datagram_msg(skb, offset, msg, used);
			if (err) {
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}

		/*
		 * 调整读正常数据流的一些参数，如, 已读取数据的序号、已读取
		 * 数据的长度，剩余的可以使用的用户空间缓存大小。如果是截短，
		 * 则通过调整这些参数，多余的数据就默默被丢弃了。
		 */
		*seq += used;
		copied += used;
		len -= used;

		/*tcp_rcv_space_adjust 调整合理的 TCP 接收缓存的大小 */
		tcp_rcv_space_adjust(sk);

skip_copy:
		/*
		 * 如果已经完成了对紧急数据的处理，则将紧急数据标志清零，
		 * 设置首部预测标志，下一个接收到的段，就又可以通过首部预测执行快速路径还是慢速路径了。
		 */
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
			/* 紧急数据是由慢速路径处理，需要保持在慢速路径模式直到收完紧急数据，
			 * 读完后就能检测是否能开启fast path了。
			 */
			tp->urg_data = 0;
			tcp_fast_path_check(sk);
		}

		/*
		 * 如果该段还有数据没有读取 (如紧急数据)，则只能继续处理该段，而不能将
		 * 该段从接收队列中删除。
		 */
		if (used + offset < skb->len)
			continue;

		if (TCP_SKB_CB(skb)->has_rxtstamp) {
			tcp_update_recv_tstamps(skb, &tss);
			has_tss = true;
			has_cmsg = true;
		}

		/* 如果发现段中存在 FIN 标志，则跳转到 found\_fin\_ok 标签处处理 */
		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			goto found_fin_ok;

		/*
		 * 如果已经读完该段的全部数据，且不是查看数据，则可以将该段从接收队列中
		 * 删除，然后继续处理后续的段。
		 */
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb);
		continue;

		/* 如果在接收队列中的数据包有FIN标志，跳如此处。
		 * 按照RFC793规范，必须在序列号中计算FIN的一个字节，并重新计算TCP窗口。
		 * 如果已经读完该段的全部数据并且不是查看数据，则可以将该段从
		 * 接收队列中删除。然后就可以退出了，无需处理后续的段了。
		 */
found_fin_ok:
		/* Process the FIN. */
		++*seq;
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb);
		break;
	} while (len > 0);

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* 清除TCP接收缓冲区，如果需要它，也会发送ACK。 */
	/* Clean up data we have read: This will do ACK frames. */
	tcp_cleanup_rbuf(sk, copied);

	release_sock(sk);

	if (has_cmsg) {
		if (has_tss)
			tcp_recv_timestamp(msg, sk, &tss);
		if (tp->recvmsg_inq) {
			inq = tcp_inq_hint(sk);
			put_cmsg(msg, SOL_TCP, TCP_CM_INQ, sizeof(inq), &inq);
		}
	}

	return copied;

	/* 如果在读取的过程中遇到错误，就会跳转到此，解锁传输层然后返回错误码。 */
out:
	release_sock(sk);
	return err;

	/* 在处理数据段时，遇到紧急数据，跳出此片。 复制紧急数据到用户空间。 */
recv_urg:
	err = tcp_recv_urg(sk, msg, len, flags);
	goto out;

recv_sndq:
	err = tcp_peek_sndq(sk, msg, len);
	goto out;
}
EXPORT_SYMBOL(tcp_recvmsg);

void tcp_set_state(struct sock *sk, int state)
{
	int oldstate = sk->sk_state;

	/* We defined a new enum for TCP states that are exported in BPF
	 * so as not force the internal TCP states to be frozen. The
	 * following checks will detect if an internal state value ever
	 * differs from the BPF value. If this ever happens, then we will
	 * need to remap the internal value to the BPF value before calling
	 * tcp_call_bpf_2arg.
	 */
	BUILD_BUG_ON((int)BPF_TCP_ESTABLISHED != (int)TCP_ESTABLISHED);
	BUILD_BUG_ON((int)BPF_TCP_SYN_SENT != (int)TCP_SYN_SENT);
	BUILD_BUG_ON((int)BPF_TCP_SYN_RECV != (int)TCP_SYN_RECV);
	BUILD_BUG_ON((int)BPF_TCP_FIN_WAIT1 != (int)TCP_FIN_WAIT1);
	BUILD_BUG_ON((int)BPF_TCP_FIN_WAIT2 != (int)TCP_FIN_WAIT2);
	BUILD_BUG_ON((int)BPF_TCP_TIME_WAIT != (int)TCP_TIME_WAIT);
	BUILD_BUG_ON((int)BPF_TCP_CLOSE != (int)TCP_CLOSE);
	BUILD_BUG_ON((int)BPF_TCP_CLOSE_WAIT != (int)TCP_CLOSE_WAIT);
	BUILD_BUG_ON((int)BPF_TCP_LAST_ACK != (int)TCP_LAST_ACK);
	BUILD_BUG_ON((int)BPF_TCP_LISTEN != (int)TCP_LISTEN);
	BUILD_BUG_ON((int)BPF_TCP_CLOSING != (int)TCP_CLOSING);
	BUILD_BUG_ON((int)BPF_TCP_NEW_SYN_RECV != (int)TCP_NEW_SYN_RECV);
	BUILD_BUG_ON((int)BPF_TCP_MAX_STATES != (int)TCP_MAX_STATES);

	if (BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk), BPF_SOCK_OPS_STATE_CB_FLAG))
		tcp_call_bpf_2arg(sk, BPF_SOCK_OPS_STATE_CB, oldstate, state);

	switch (state) {
	case TCP_ESTABLISHED:
		if (oldstate != TCP_ESTABLISHED)
			TCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
		break;

	case TCP_CLOSE:
		if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
			TCP_INC_STATS(sock_net(sk), TCP_MIB_ESTABRESETS);

		sk->sk_prot->unhash(sk);
		if (inet_csk(sk)->icsk_bind_hash &&
		    !(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
			inet_put_port(sk);
		/* fall through */
	default:
		if (oldstate == TCP_ESTABLISHED)
			TCP_DEC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
	}

	/* Change state AFTER socket is unhashed to avoid closed
	 * socket sitting in hash tables.
	 */
	inet_sk_state_store(sk, state);
}
EXPORT_SYMBOL_GPL(tcp_set_state);

/*
 *	State processing on a close. This implements the state shift for
 *	sending our FIN frame. Note that we only send a FIN for some
 *	states. A shutdown() may have already sent the FIN, or we may be
 *	closed.
 */

static const unsigned char new_state[16] = {
  /* current state:        new state:      action:	*/
  [0 /* (Invalid) */]	= TCP_CLOSE,
  [TCP_ESTABLISHED]	= TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  [TCP_SYN_SENT]	= TCP_CLOSE,
  [TCP_SYN_RECV]	= TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  [TCP_FIN_WAIT1]	= TCP_FIN_WAIT1,
  [TCP_FIN_WAIT2]	= TCP_FIN_WAIT2,
  [TCP_TIME_WAIT]	= TCP_CLOSE,
  [TCP_CLOSE]		= TCP_CLOSE,
  [TCP_CLOSE_WAIT]	= TCP_LAST_ACK  | TCP_ACTION_FIN,
  [TCP_LAST_ACK]	= TCP_LAST_ACK,
  [TCP_LISTEN]		= TCP_CLOSE,
  [TCP_CLOSING]		= TCP_CLOSING,
  [TCP_NEW_SYN_RECV]	= TCP_CLOSE,	/* should not happen ! */
};

/* 进行状态转移，并且判断是否可以发送 FIN。 */
static int tcp_close_state(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state];

	/* 除去可能的FIN_ACTION */
	int ns = next & TCP_STATE_MASK;

	/* 根据状态图进行状态转移 */
	tcp_set_state(sk, ns);

	/* 如果需要执行发送FIN的动作，则返回true */
	return next & TCP_ACTION_FIN;
}

/*
 *	Shutdown the sending side of a connection. Much like close except
 *	that we don't receive shut down or sock_set_flag(sk, SOCK_DEAD).
 */
/* 通过 shutdown 系统调用，主动关闭 TCP 连接。该系统调用最终由tcp_shutdown实现。
 * 如果是发送方向的关闭，并且 TCP 状态为 ESTABLISHED、 SYN_SENT、 SYN_RECV
 * 或 CLOSE_WAIT 时，根据 TC 状态迁移图和当前的状态设置新的状态，并在需要发
 * 送 FIN 时，调用 FIN 时，调用tcp_send_fin时向对方发送 FIN。
 * 而对于接收方向的关闭，则无需向对方发送 FIN，因为可能还需要向对方发送数据。
 * 至于接收方向的关闭的实现，在 recvmsg 系统调用中发现设置了 RCV_SHUTDOWN
 * 标志会立即返回。
 */
void tcp_shutdown(struct sock *sk, int how)
{
	/*	We need to grab some memory, and put together a FIN,
	 *	and then put it into the queue to be sent.
	 *		Tim MacKenzie(tym@dibbler.cs.monash.edu.au) 4 Dec '92.
	 */
	if (!(how & SEND_SHUTDOWN))
		return;

	/* 发送方向的关闭，并且 TCP状态为ESTABLISHED, SYN_SENT, SYN_RECV, CLOSE_WAIT状态的一个 */
	/* If we've already sent a FIN, or it's a closed state, skip this. */
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_SYN_SENT |
	     TCPF_SYN_RECV | TCPF_CLOSE_WAIT)) {
		/* Clear out any half completed packets.  FIN if needed. */
	     	/* 如果此时已经发送了一个FIN了，就跳过。
	     	 * 该函数会在需要发送 FIN 时，调用tcp_close_state()来设置 TCP 的状态。
	     	 */
		if (tcp_close_state(sk))
			tcp_send_fin(sk);
	}
}
EXPORT_SYMBOL(tcp_shutdown);

bool tcp_check_oom(struct sock *sk, int shift)
{
	bool too_many_orphans, out_of_socket_memory;

	too_many_orphans = tcp_too_many_orphans(sk, shift);
	out_of_socket_memory = tcp_out_of_memory(sk);

	if (too_many_orphans)
		net_info_ratelimited("too many orphaned sockets\n");
	if (out_of_socket_memory)
		net_info_ratelimited("out of memory -- consider tuning tcp_mem\n");
	return too_many_orphans || out_of_socket_memory;
}

/* 主动关闭 - 第一次握手：发送FIN
 * 当一段完成数据发送任务之后，应用层即可调用 close 发送一个 FIN 来终止该方向
 * 上的连接，当另一端收到这个 FIN 后，必须通知应用层，另一端已经终止了数据传送。
 * 而 close 系统调用在传输层接收的实现就是 tcp_close,
 */
void tcp_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	/*
	 * 首先，对传输控制块加锁。然后设置关闭标志为 SHUTDOWN_MASK, 表示进行双向的关闭。
	 * 如果套接口处于侦听状态，这种情况处理相对比较简单，因为没有建立起连接，因
	 * 此无需发送 FIN 等操作。设置 TCP 的状态为 CLOSE，然后终止侦听。最后跳转到
	 * adjudge_to_death 处进行相关处理。
	 */
	lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	if (sk->sk_state == TCP_LISTEN) {
		tcp_set_state(sk, TCP_CLOSE);

		/* Special case. */
		inet_csk_listen_stop(sk);

		goto adjudge_to_death;
	}

	/*
	 * 因为要关闭连接，故需要释放已接收队列上的段，同时, 统计释放了多少数据，然后回收缓存。
	 */
	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;

		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			len--;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	/* 如果 socket 本身就是 close 状态的话，直接跳到 adjudge_to_death 就好。
	 */
	/* If socket has been already reset (e.g. in tcp_reset()) - kill it. */
	if (sk->sk_state == TCP_CLOSE)
		goto adjudge_to_death;

	/* As outlined in RFC 2525, section 2.17, we send a RST here because
	 * data was lost. To witness the awful effects of the old behavior of
	 * always doing a FIN, run an older 2.1.x kernel or 2.0.x, start a bulk
	 * GET in an FTP client, suspend the process, wait for the client to
	 * advertise a zero window, then kill -9 the FTP client, wheee...
	 * Note: timeout is always zero in such a case.
	 */
	 /* 开启 repair 选项 */
	if (unlikely(tcp_sk(sk)->repair)) {
		sk->sk_prot->disconnect(sk, 0);
	} else if (data_was_unread) {
		/*
		 * 
		 * 在存在数据未读的情况下断开连接。这时应该直接置状态
		 * CLOSE，并主动向对方发送 RST，因为这是不正常的情况，
		 * 而发送 FIN 表示一切正常。
		 */
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		tcp_send_active_reset(sk, sk->sk_allocation);
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/*
		 * 如果设置了 SO_LINGER，并且，延时时间为 0, 则直接调用 disconnect 断开。
		 * 删除并释放已建立连接但未被 accept 的传输控制块。同时删除并释放
		 * 已收到在接收队列、失序队列上的段以及发送队列上的段。
		 */
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
		
	} else if (tcp_close_state(sk)) { //判断是否可以发送 FIN
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		/* RED-PEN. Formally speaking, we have broken TCP state
		 * machine. State transitions:
		 *
		 * TCP_ESTABLISHED -> TCP_FIN_WAIT1
		 * TCP_SYN_RECV	-> TCP_FIN_WAIT1 (forget it, it's impossible)
		 * TCP_CLOSE_WAIT -> TCP_LAST_ACK
		 *
		 * are legal only when FIN has been sent (i.e. in window),
		 * rather than queued out of window. Purists blame.
		 *
		 * F.e. "RFC state" is ESTABLISHED,
		 * if Linux state is FIN-WAIT-1, but FIN is still not sent.
		 *
		 * The visible declinations are that sometimes
		 * we enter time-wait state, when it is not required really
		 * (harmless), do not send active resets, when they are
		 * required by specs (TCP_ESTABLISHED, TCP_CLOSE_WAIT, when
		 * they look as CLOSING or LAST_ACK for Linux)
		 * Probably, I missed some more holelets.
		 * 						--ANK
		 * XXX (TFO) - To start off we don't support SYN+ACK+FIN
		 * in a single packet! (May consider it later but will
		 * probably need API support or TCP_CORK SYN-ACK until
		 * data is written and socket is closed.)
		 */
		tcp_send_fin(sk);
	}

	sk_stream_wait_close(sk, timeout);

	/*
	 * 在给对端发送 RST 或 FIN 段后，等待套接口的关闭，直到 TCP 的状态为 FIN_WAIT_1、
	 * CLOSING、 LAST_ACK 或等待超时。
	 */
adjudge_to_death:
	/* 置套接口为 DEAD 状态，成为孤儿套接口，同时更新系统中的孤儿套接口数。 */
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);

	local_bh_disable();
	bh_lock_sock(sk);
	/* remove backlog if any, without releasing ownership. */
	__release_sock(sk);

	percpu_counter_inc(sk->sk_prot->orphan_count);

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 1 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */
	/* 处理 FIN_WAIT2 到 CLOSE 状态的转换。 */
	if (sk->sk_state == TCP_FIN_WAIT2) {
		struct tcp_sock *tp = tcp_sk(sk);
		/*
		 * 如果 linger2 小于 0，则表示无需从 TCP_FIN_WAIT2hangtag 等待转移到
		 * CLOSE 状态，而是立即设置 CLOSE 状态，然后给对端发送 RST 段。
		 */
		if (tp->linger2 < 0) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			__NET_INC_STATS(sock_net(sk),
					LINUX_MIB_TCPABORTONLINGER);
		} else {
			/* 计算需要保持 TCP_FIN_WAIT2 状态的时长     */
			const int tmo = tcp_fin_time(sk);

			if (tmo > TCP_TIMEWAIT_LEN) {
				/* 小于 1min，调用 TCP_FIN_WAIT2 定时器 */
				inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
			} else {
				/* 否则调用 timewait 控制块取代 tcp_sock 传出控制块。 */
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}

	/* 继续处理不是CLOSE状态 */
	if (sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(sk);
		if (tcp_check_oom(sk, 0)) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			__NET_INC_STATS(sock_net(sk),
					LINUX_MIB_TCPABORTONMEMORY);
		} else if (!check_net(sock_net(sk))) {
			/* Not possible to send reset; just close */
			tcp_set_state(sk, TCP_CLOSE);
		}
	}

	/* 处理是CLOSE状态 */
	if (sk->sk_state == TCP_CLOSE) {
		struct request_sock *req = tcp_sk(sk)->fastopen_rsk;
		/* We could get here with a non-NULL req if the socket is
		 * aborted (e.g., closed with unread data) before 3WHS
		 * finishes.
		 */
		if (req)
			reqsk_fastopen_remove(sk, req, false);
		inet_csk_destroy_sock(sk);
	}
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	release_sock(sk);
	sock_put(sk);
}
EXPORT_SYMBOL(tcp_close);

/* These states need RST on ABORT according to RFC793 */

static inline bool tcp_need_reset(int state)
{
	return (1 << state) &
	       (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_FIN_WAIT1 |
		TCPF_FIN_WAIT2 | TCPF_SYN_RECV);
}

static void tcp_rtx_queue_purge(struct sock *sk)
{
	struct rb_node *p = rb_first(&sk->tcp_rtx_queue);

	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		tcp_rtx_queue_unlink(skb, sk);
		sk_wmem_free_skb(sk, skb);
	}
}

void tcp_write_queue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	tcp_chrono_stop(sk, TCP_CHRONO_BUSY);
	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) {
		tcp_skb_tsorted_anchor_cleanup(skb);
		sk_wmem_free_skb(sk, skb);
	}
	tcp_rtx_queue_purge(sk);
	INIT_LIST_HEAD(&tcp_sk(sk)->tsorted_sent_queue);
	sk_mem_reclaim(sk);
	tcp_clear_all_retrans_hints(tcp_sk(sk));
	tcp_sk(sk)->packets_out = 0;
	inet_csk(sk)->icsk_backoff = 0;
}

int tcp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int old_state = sk->sk_state;

	if (old_state != TCP_CLOSE)
		tcp_set_state(sk, TCP_CLOSE);

	/* ABORT function of RFC793 */
	if (old_state == TCP_LISTEN) {
		inet_csk_listen_stop(sk);
	} else if (unlikely(tp->repair)) {
		sk->sk_err = ECONNABORTED;
	} else if (tcp_need_reset(old_state) ||
		   (tp->snd_nxt != tp->write_seq &&
		    (1 << old_state) & (TCPF_CLOSING | TCPF_LAST_ACK))) {
		/* The last check adjusts for discrepancy of Linux wrt. RFC
		 * states
		 */
		tcp_send_active_reset(sk, gfp_any());
		sk->sk_err = ECONNRESET;
	} else if (old_state == TCP_SYN_SENT)
		sk->sk_err = ECONNRESET;

	tcp_clear_xmit_timers(sk);
	__skb_queue_purge(&sk->sk_receive_queue);
	tp->copied_seq = tp->rcv_nxt;
	tp->urg_data = 0;
	tcp_write_queue_purge(sk);
	tcp_fastopen_active_disable_ofo_check(sk);
	skb_rbtree_purge(&tp->out_of_order_queue);

	inet->inet_dport = 0;

	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	sk->sk_shutdown = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->srtt_us = 0;
	tp->rcv_rtt_last_tsecr = 0;
	tp->write_seq += tp->max_window + 2;
	if (tp->write_seq == 0)
		tp->write_seq = 1;
	tp->snd_cwnd = 2;
	icsk->icsk_probes_out = 0;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_cnt = 0;
	tp->window_clamp = 0;
	tp->delivered_ce = 0;
	tcp_set_ca_state(sk, TCP_CA_Open);
	tp->is_sack_reneg = 0;
	tcp_clear_retrans(tp);
	inet_csk_delack_init(sk);
	/* Initialize rcv_mss to TCP_MIN_MSS to avoid division by 0
	 * issue in __tcp_select_window()
	 */
	icsk->icsk_ack.rcv_mss = TCP_MIN_MSS;
	memset(&tp->rx_opt, 0, sizeof(tp->rx_opt));
	__sk_dst_reset(sk);
	dst_release(sk->sk_rx_dst);
	sk->sk_rx_dst = NULL;
	tcp_saved_syn_free(tp);
	tp->compressed_ack = 0;
	tp->bytes_sent = 0;
	tp->bytes_retrans = 0;
	tp->duplicate_sack[0].start_seq = 0;
	tp->duplicate_sack[0].end_seq = 0;
	tp->dsack_dups = 0;
	tp->reord_seen = 0;

	/* Clean up fastopen related fields */
	tcp_free_fastopen_req(tp);
	inet->defer_connect = 0;

	WARN_ON(inet->inet_num && !icsk->icsk_bind_hash);

	if (sk->sk_frag.page) {
		put_page(sk->sk_frag.page);
		sk->sk_frag.page = NULL;
		sk->sk_frag.offset = 0;
	}

	sk->sk_error_report(sk);
	return 0;
}
EXPORT_SYMBOL(tcp_disconnect);

static inline bool tcp_can_repair_sock(const struct sock *sk)
{
	return ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN) &&
		(sk->sk_state != TCP_LISTEN);
}

static int tcp_repair_set_window(struct tcp_sock *tp, char __user *optbuf, int len)
{
	struct tcp_repair_window opt;

	if (!tp->repair)
		return -EPERM;

	if (len != sizeof(opt))
		return -EINVAL;

	if (copy_from_user(&opt, optbuf, sizeof(opt)))
		return -EFAULT;

	if (opt.max_window < opt.snd_wnd)
		return -EINVAL;

	if (after(opt.snd_wl1, tp->rcv_nxt + opt.rcv_wnd))
		return -EINVAL;

	if (after(opt.rcv_wup, tp->rcv_nxt))
		return -EINVAL;

	tp->snd_wl1	= opt.snd_wl1;
	tp->snd_wnd	= opt.snd_wnd;
	tp->max_window	= opt.max_window;

	tp->rcv_wnd	= opt.rcv_wnd;
	tp->rcv_wup	= opt.rcv_wup;

	return 0;
}

static int tcp_repair_options_est(struct sock *sk,
		struct tcp_repair_opt __user *optbuf, unsigned int len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_repair_opt opt;

	while (len >= sizeof(opt)) {
		if (copy_from_user(&opt, optbuf, sizeof(opt)))
			return -EFAULT;

		optbuf++;
		len -= sizeof(opt);

		switch (opt.opt_code) {
		case TCPOPT_MSS:
			tp->rx_opt.mss_clamp = opt.opt_val;
			tcp_mtup_init(sk);
			break;
		case TCPOPT_WINDOW:
			{
				u16 snd_wscale = opt.opt_val & 0xFFFF;
				u16 rcv_wscale = opt.opt_val >> 16;

				if (snd_wscale > TCP_MAX_WSCALE || rcv_wscale > TCP_MAX_WSCALE)
					return -EFBIG;

				tp->rx_opt.snd_wscale = snd_wscale;
				tp->rx_opt.rcv_wscale = rcv_wscale;
				tp->rx_opt.wscale_ok = 1;
			}
			break;
		case TCPOPT_SACK_PERM:
			if (opt.opt_val != 0)
				return -EINVAL;

			tp->rx_opt.sack_ok |= TCP_SACK_SEEN;
			break;
		case TCPOPT_TIMESTAMP:
			if (opt.opt_val != 0)
				return -EINVAL;

			tp->rx_opt.tstamp_ok = 1;
			break;
		}
	}

	return 0;
}

/*
 *	Socket option code for TCP.
 */
static int do_tcp_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, unsigned int optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct net *net = sock_net(sk);
	int val;
	int err = 0;

	/* These are data/string values, all the others are ints */
	switch (optname) {
	case TCP_CONGESTION: {
		char name[TCP_CA_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;

		val = strncpy_from_user(name, optval,
					min_t(long, TCP_CA_NAME_MAX-1, optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;

		lock_sock(sk);
		err = tcp_set_congestion_control(sk, name, true, true);
		release_sock(sk);
		return err;
	}
	case TCP_ULP: {
		char name[TCP_ULP_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;

		val = strncpy_from_user(name, optval,
					min_t(long, TCP_ULP_NAME_MAX - 1,
					      optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;

		lock_sock(sk);
		err = tcp_set_ulp(sk, name);
		release_sock(sk);
		return err;
	}
	case TCP_FASTOPEN_KEY: {
		__u8 key[TCP_FASTOPEN_KEY_LENGTH];

		if (optlen != sizeof(key))
			return -EINVAL;

		if (copy_from_user(key, optval, optlen))
			return -EFAULT;

		return tcp_fastopen_reset_cipher(net, sk, key, sizeof(key));
	}
	default:
		/* fallthru */
		break;
	}

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TCP_MAXSEG:
		/* Values greater than interface MTU won't take effect. However
		 * at the point when this call is done we typically don't yet
		 * know which interface is going to be used
		 */
		if (val && (val < TCP_MIN_MSS || val > MAX_TCP_WINDOW)) {
			err = -EINVAL;
			break;
		}
		tp->rx_opt.user_mss = val;
		break;

	case TCP_NODELAY:
		if (val) {
			/* TCP_NODELAY is weaker than TCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TCP_NODELAY is set we make
			 * an explicit push, which overrides even TCP_CORK
			 * for currently queued segments.
			 */
			tp->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk);
		} else {
			tp->nonagle &= ~TCP_NAGLE_OFF;
		}
		break;

	case TCP_THIN_LINEAR_TIMEOUTS:
		if (val < 0 || val > 1)
			err = -EINVAL;
		else
			tp->thin_lto = val;
		break;

	case TCP_THIN_DUPACK:
		if (val < 0 || val > 1)
			err = -EINVAL;
		break;

	case TCP_REPAIR:
		if (!tcp_can_repair_sock(sk))
			err = -EPERM;
		else if (val == TCP_REPAIR_ON) {
			tp->repair = 1;
			sk->sk_reuse = SK_FORCE_REUSE;
			tp->repair_queue = TCP_NO_QUEUE;
		} else if (val == TCP_REPAIR_OFF) {
			tp->repair = 0;
			sk->sk_reuse = SK_NO_REUSE;
			tcp_send_window_probe(sk);
		} else if (val == TCP_REPAIR_OFF_NO_WP) {
			tp->repair = 0;
			sk->sk_reuse = SK_NO_REUSE;
		} else
			err = -EINVAL;

		break;

	case TCP_REPAIR_QUEUE:
		if (!tp->repair)
			err = -EPERM;
		else if ((unsigned int)val < TCP_QUEUES_NR)
			tp->repair_queue = val;
		else
			err = -EINVAL;
		break;

	case TCP_QUEUE_SEQ:
		if (sk->sk_state != TCP_CLOSE)
			err = -EPERM;
		else if (tp->repair_queue == TCP_SEND_QUEUE)
			tp->write_seq = val;
		else if (tp->repair_queue == TCP_RECV_QUEUE)
			tp->rcv_nxt = val;
		else
			err = -EINVAL;
		break;

	case TCP_REPAIR_OPTIONS:
		if (!tp->repair)
			err = -EINVAL;
		else if (sk->sk_state == TCP_ESTABLISHED)
			err = tcp_repair_options_est(sk,
					(struct tcp_repair_opt __user *)optval,
					optlen);
		else
			err = -EPERM;
		break;

	case TCP_CORK:
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TCP_CORK can be set together with TCP_NODELAY and it is
		 * stronger than TCP_NODELAY.
		 */
		if (val) {
			tp->nonagle |= TCP_NAGLE_CORK;
		} else {
			tp->nonagle &= ~TCP_NAGLE_CORK;
			if (tp->nonagle&TCP_NAGLE_OFF)
				tp->nonagle |= TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk);
		}
		break;

	case TCP_KEEPIDLE:
		if (val < 1 || val > MAX_TCP_KEEPIDLE)
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ;
			if (sock_flag(sk, SOCK_KEEPOPEN) &&
			    !((1 << sk->sk_state) &
			      (TCPF_CLOSE | TCPF_LISTEN))) {
				u32 elapsed = keepalive_time_elapsed(tp);
				if (tp->keepalive_time > elapsed)
					elapsed = tp->keepalive_time - elapsed;
				else
					elapsed = 0;
				inet_csk_reset_keepalive_timer(sk, elapsed);
			}
		}
		break;
	case TCP_KEEPINTVL:
		if (val < 1 || val > MAX_TCP_KEEPINTVL)
			err = -EINVAL;
		else
			tp->keepalive_intvl = val * HZ;
		break;
	case TCP_KEEPCNT:
		if (val < 1 || val > MAX_TCP_KEEPCNT)
			err = -EINVAL;
		else
			tp->keepalive_probes = val;
		break;
	case TCP_SYNCNT:
		if (val < 1 || val > MAX_TCP_SYNCNT)
			err = -EINVAL;
		else
			icsk->icsk_syn_retries = val;
		break;

	case TCP_SAVE_SYN:
		if (val < 0 || val > 1)
			err = -EINVAL;
		else
			tp->save_syn = val;
		break;

	case TCP_LINGER2:
		if (val < 0)
			tp->linger2 = -1;
		else if (val > net->ipv4.sysctl_tcp_fin_timeout / HZ)
			tp->linger2 = 0;
		else
			tp->linger2 = val * HZ;
		break;

	case TCP_DEFER_ACCEPT:
		/* Translate value in seconds to number of retransmits */
		icsk->icsk_accept_queue.rskq_defer_accept =
			secs_to_retrans(val, TCP_TIMEOUT_INIT / HZ,
					TCP_RTO_MAX / HZ);
		break;

	case TCP_WINDOW_CLAMP:
		if (!val) {
			if (sk->sk_state != TCP_CLOSE) {
				err = -EINVAL;
				break;
			}
			tp->window_clamp = 0;
		} else
			tp->window_clamp = val < SOCK_MIN_RCVBUF / 2 ?
						SOCK_MIN_RCVBUF / 2 : val;
		break;

	case TCP_QUICKACK:
		if (!val) {
			icsk->icsk_ack.pingpong = 1;
		} else {
			icsk->icsk_ack.pingpong = 0;
			if ((1 << sk->sk_state) &
			    (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
			    inet_csk_ack_scheduled(sk)) {
				icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
				tcp_cleanup_rbuf(sk, 1);
				if (!(val & 1))
					icsk->icsk_ack.pingpong = 1;
			}
		}
		break;

#ifdef CONFIG_TCP_MD5SIG
	case TCP_MD5SIG:
	case TCP_MD5SIG_EXT:
		if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
			err = tp->af_specific->md5_parse(sk, optname, optval, optlen);
		else
			err = -EINVAL;
		break;
#endif
	case TCP_USER_TIMEOUT:
		/* Cap the max time in ms TCP will retry or probe the window
		 * before giving up and aborting (ETIMEDOUT) a connection.
		 */
		if (val < 0)
			err = -EINVAL;
		else
			icsk->icsk_user_timeout = val;
		break;

	case TCP_FASTOPEN:
		if (val >= 0 && ((1 << sk->sk_state) & (TCPF_CLOSE |
		    TCPF_LISTEN))) {
			tcp_fastopen_init_key_once(net);

			fastopen_queue_tune(sk, val);
		} else {
			err = -EINVAL;
		}
		break;
	case TCP_FASTOPEN_CONNECT:
		if (val > 1 || val < 0) {
			err = -EINVAL;
		} else if (net->ipv4.sysctl_tcp_fastopen & TFO_CLIENT_ENABLE) {
			if (sk->sk_state == TCP_CLOSE)
				tp->fastopen_connect = val;
			else
				err = -EINVAL;
		} else {
			err = -EOPNOTSUPP;
		}
		break;
	case TCP_FASTOPEN_NO_COOKIE:
		if (val > 1 || val < 0)
			err = -EINVAL;
		else if (!((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
			err = -EINVAL;
		else
			tp->fastopen_no_cookie = val;
		break;
	case TCP_TIMESTAMP:
		if (!tp->repair)
			err = -EPERM;
		else
			tp->tsoffset = val - tcp_time_stamp_raw();
		break;
	case TCP_REPAIR_WINDOW:
		err = tcp_repair_set_window(tp, optval, optlen);
		break;
	case TCP_NOTSENT_LOWAT:
		tp->notsent_lowat = val;
		sk->sk_write_space(sk);
		break;
	case TCP_INQ:
		if (val > 1 || val < 0)
			err = -EINVAL;
		else
			tp->recvmsg_inq = val;
		break;
	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

int tcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   unsigned int optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	/* 例如：SOL_IP, ip_setsockopt() */
	if (level != SOL_TCP)
		return icsk->icsk_af_ops->setsockopt(sk, level, optname,
						     optval, optlen);
	return do_tcp_setsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(tcp_setsockopt);

#ifdef CONFIG_COMPAT
int compat_tcp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (level != SOL_TCP)
		return inet_csk_compat_setsockopt(sk, level, optname,
						  optval, optlen);
	return do_tcp_setsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(compat_tcp_setsockopt);
#endif

static void tcp_get_info_chrono_stats(const struct tcp_sock *tp,
				      struct tcp_info *info)
{
	u64 stats[__TCP_CHRONO_MAX], total = 0;
	enum tcp_chrono i;

	for (i = TCP_CHRONO_BUSY; i < __TCP_CHRONO_MAX; ++i) {
		stats[i] = tp->chrono_stat[i - 1];
		if (i == tp->chrono_type)
			stats[i] += tcp_jiffies32 - tp->chrono_start;
		stats[i] *= USEC_PER_SEC / HZ;
		total += stats[i];
	}

	info->tcpi_busy_time = total;
	info->tcpi_rwnd_limited = stats[TCP_CHRONO_RWND_LIMITED];
	info->tcpi_sndbuf_limited = stats[TCP_CHRONO_SNDBUF_LIMITED];
}

/* Return information about state of tcp endpoint in API format. */
void tcp_get_info(struct sock *sk, struct tcp_info *info)
{
	const struct tcp_sock *tp = tcp_sk(sk); /* iff sk_type == SOCK_STREAM */
	const struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned long rate;
	u32 now;
	u64 rate64;
	bool slow;

	memset(info, 0, sizeof(*info));
	if (sk->sk_type != SOCK_STREAM)
		return;

	info->tcpi_state = inet_sk_state_load(sk);

	/* Report meaningful fields for all TCP states, including listeners */
	rate = READ_ONCE(sk->sk_pacing_rate);
	rate64 = (rate != ~0UL) ? rate : ~0ULL;
	info->tcpi_pacing_rate = rate64;

	rate = READ_ONCE(sk->sk_max_pacing_rate);
	rate64 = (rate != ~0UL) ? rate : ~0ULL;
	info->tcpi_max_pacing_rate = rate64;

	info->tcpi_reordering = tp->reordering;
	info->tcpi_snd_cwnd = tp->snd_cwnd;

	if (info->tcpi_state == TCP_LISTEN) {
		/* listeners aliased fields :
		 * tcpi_unacked -> Number of children ready for accept()
		 * tcpi_sacked  -> max backlog
		 */
		info->tcpi_unacked = sk->sk_ack_backlog;
		info->tcpi_sacked = sk->sk_max_ack_backlog;
		return;
	}

	slow = lock_sock_fast(sk);

	info->tcpi_ca_state = icsk->icsk_ca_state;
	info->tcpi_retransmits = icsk->icsk_retransmits;
	info->tcpi_probes = icsk->icsk_probes_out;
	info->tcpi_backoff = icsk->icsk_backoff;

	if (tp->rx_opt.tstamp_ok)
		info->tcpi_options |= TCPI_OPT_TIMESTAMPS;
	if (tcp_is_sack(tp))
		info->tcpi_options |= TCPI_OPT_SACK;
	if (tp->rx_opt.wscale_ok) {
		info->tcpi_options |= TCPI_OPT_WSCALE;
		info->tcpi_snd_wscale = tp->rx_opt.snd_wscale;
		info->tcpi_rcv_wscale = tp->rx_opt.rcv_wscale;
	}

	if (tp->ecn_flags & TCP_ECN_OK)
		info->tcpi_options |= TCPI_OPT_ECN;
	if (tp->ecn_flags & TCP_ECN_SEEN)
		info->tcpi_options |= TCPI_OPT_ECN_SEEN;
	if (tp->syn_data_acked)
		info->tcpi_options |= TCPI_OPT_SYN_DATA;

	info->tcpi_rto = jiffies_to_usecs(icsk->icsk_rto);
	info->tcpi_ato = jiffies_to_usecs(icsk->icsk_ack.ato);
	info->tcpi_snd_mss = tp->mss_cache;
	info->tcpi_rcv_mss = icsk->icsk_ack.rcv_mss;

	info->tcpi_unacked = tp->packets_out;
	info->tcpi_sacked = tp->sacked_out;

	info->tcpi_lost = tp->lost_out;
	info->tcpi_retrans = tp->retrans_out;

	now = tcp_jiffies32;
	info->tcpi_last_data_sent = jiffies_to_msecs(now - tp->lsndtime);
	info->tcpi_last_data_recv = jiffies_to_msecs(now - icsk->icsk_ack.lrcvtime);
	info->tcpi_last_ack_recv = jiffies_to_msecs(now - tp->rcv_tstamp);

	info->tcpi_pmtu = icsk->icsk_pmtu_cookie;
	info->tcpi_rcv_ssthresh = tp->rcv_ssthresh;
	info->tcpi_rtt = tp->srtt_us >> 3;
	info->tcpi_rttvar = tp->mdev_us >> 2;
	info->tcpi_snd_ssthresh = tp->snd_ssthresh;
	info->tcpi_advmss = tp->advmss;

	info->tcpi_rcv_rtt = tp->rcv_rtt_est.rtt_us >> 3;
	info->tcpi_rcv_space = tp->rcvq_space.space;

	info->tcpi_total_retrans = tp->total_retrans;

	info->tcpi_bytes_acked = tp->bytes_acked;
	info->tcpi_bytes_received = tp->bytes_received;
	info->tcpi_notsent_bytes = max_t(int, 0, tp->write_seq - tp->snd_nxt);
	tcp_get_info_chrono_stats(tp, info);

	info->tcpi_segs_out = tp->segs_out;
	info->tcpi_segs_in = tp->segs_in;

	info->tcpi_min_rtt = tcp_min_rtt(tp);
	info->tcpi_data_segs_in = tp->data_segs_in;
	info->tcpi_data_segs_out = tp->data_segs_out;

	info->tcpi_delivery_rate_app_limited = tp->rate_app_limited ? 1 : 0;
	rate64 = tcp_compute_delivery_rate(tp);
	if (rate64)
		info->tcpi_delivery_rate = rate64;
	info->tcpi_delivered = tp->delivered;
	info->tcpi_delivered_ce = tp->delivered_ce;
	info->tcpi_bytes_sent = tp->bytes_sent;
	info->tcpi_bytes_retrans = tp->bytes_retrans;
	info->tcpi_dsack_dups = tp->dsack_dups;
	info->tcpi_reord_seen = tp->reord_seen;
	unlock_sock_fast(sk, slow);
}
EXPORT_SYMBOL_GPL(tcp_get_info);

static size_t tcp_opt_stats_get_size(void)
{
	return
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_BUSY */
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_RWND_LIMITED */
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_SNDBUF_LIMITED */
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_DATA_SEGS_OUT */
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_TOTAL_RETRANS */
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_PACING_RATE */
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_DELIVERY_RATE */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_SND_CWND */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_REORDERING */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_MIN_RTT */
		nla_total_size(sizeof(u8)) + /* TCP_NLA_RECUR_RETRANS */
		nla_total_size(sizeof(u8)) + /* TCP_NLA_DELIVERY_RATE_APP_LMT */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_SNDQ_SIZE */
		nla_total_size(sizeof(u8)) + /* TCP_NLA_CA_STATE */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_SND_SSTHRESH */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_DELIVERED */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_DELIVERED_CE */
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_BYTES_SENT */
		nla_total_size_64bit(sizeof(u64)) + /* TCP_NLA_BYTES_RETRANS */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_DSACK_DUPS */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_REORD_SEEN */
		nla_total_size(sizeof(u32)) + /* TCP_NLA_SRTT */
		0;
}

struct sk_buff *tcp_get_timestamping_opt_stats(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *stats;
	struct tcp_info info;
	unsigned long rate;
	u64 rate64;

	stats = alloc_skb(tcp_opt_stats_get_size(), GFP_ATOMIC);
	if (!stats)
		return NULL;

	tcp_get_info_chrono_stats(tp, &info);
	nla_put_u64_64bit(stats, TCP_NLA_BUSY,
			  info.tcpi_busy_time, TCP_NLA_PAD);
	nla_put_u64_64bit(stats, TCP_NLA_RWND_LIMITED,
			  info.tcpi_rwnd_limited, TCP_NLA_PAD);
	nla_put_u64_64bit(stats, TCP_NLA_SNDBUF_LIMITED,
			  info.tcpi_sndbuf_limited, TCP_NLA_PAD);
	nla_put_u64_64bit(stats, TCP_NLA_DATA_SEGS_OUT,
			  tp->data_segs_out, TCP_NLA_PAD);
	nla_put_u64_64bit(stats, TCP_NLA_TOTAL_RETRANS,
			  tp->total_retrans, TCP_NLA_PAD);

	rate = READ_ONCE(sk->sk_pacing_rate);
	rate64 = (rate != ~0UL) ? rate : ~0ULL;
	nla_put_u64_64bit(stats, TCP_NLA_PACING_RATE, rate64, TCP_NLA_PAD);

	rate64 = tcp_compute_delivery_rate(tp);
	nla_put_u64_64bit(stats, TCP_NLA_DELIVERY_RATE, rate64, TCP_NLA_PAD);

	nla_put_u32(stats, TCP_NLA_SND_CWND, tp->snd_cwnd);
	nla_put_u32(stats, TCP_NLA_REORDERING, tp->reordering);
	nla_put_u32(stats, TCP_NLA_MIN_RTT, tcp_min_rtt(tp));

	nla_put_u8(stats, TCP_NLA_RECUR_RETRANS, inet_csk(sk)->icsk_retransmits);
	nla_put_u8(stats, TCP_NLA_DELIVERY_RATE_APP_LMT, !!tp->rate_app_limited);
	nla_put_u32(stats, TCP_NLA_SND_SSTHRESH, tp->snd_ssthresh);
	nla_put_u32(stats, TCP_NLA_DELIVERED, tp->delivered);
	nla_put_u32(stats, TCP_NLA_DELIVERED_CE, tp->delivered_ce);

	nla_put_u32(stats, TCP_NLA_SNDQ_SIZE, tp->write_seq - tp->snd_una);
	nla_put_u8(stats, TCP_NLA_CA_STATE, inet_csk(sk)->icsk_ca_state);

	nla_put_u64_64bit(stats, TCP_NLA_BYTES_SENT, tp->bytes_sent,
			  TCP_NLA_PAD);
	nla_put_u64_64bit(stats, TCP_NLA_BYTES_RETRANS, tp->bytes_retrans,
			  TCP_NLA_PAD);
	nla_put_u32(stats, TCP_NLA_DSACK_DUPS, tp->dsack_dups);
	nla_put_u32(stats, TCP_NLA_REORD_SEEN, tp->reord_seen);
	nla_put_u32(stats, TCP_NLA_SRTT, tp->srtt_us >> 3);

	return stats;
}

static int do_tcp_getsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TCP_MAXSEG:
		val = tp->mss_cache;
		if (!val && ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
			val = tp->rx_opt.user_mss;
		if (tp->repair)
			val = tp->rx_opt.mss_clamp;
		break;
	case TCP_NODELAY:
		val = !!(tp->nonagle&TCP_NAGLE_OFF);
		break;
	case TCP_CORK:
		val = !!(tp->nonagle&TCP_NAGLE_CORK);
		break;
	case TCP_KEEPIDLE:
		val = keepalive_time_when(tp) / HZ;
		break;
	case TCP_KEEPINTVL:
		val = keepalive_intvl_when(tp) / HZ;
		break;
	case TCP_KEEPCNT:
		val = keepalive_probes(tp);
		break;
	case TCP_SYNCNT:
		val = icsk->icsk_syn_retries ? : net->ipv4.sysctl_tcp_syn_retries;
		break;
	case TCP_LINGER2:
		val = tp->linger2;
		if (val >= 0)
			val = (val ? : net->ipv4.sysctl_tcp_fin_timeout) / HZ;
		break;
	case TCP_DEFER_ACCEPT:
		val = retrans_to_secs(icsk->icsk_accept_queue.rskq_defer_accept,
				      TCP_TIMEOUT_INIT / HZ, TCP_RTO_MAX / HZ);
		break;
	case TCP_WINDOW_CLAMP:
		val = tp->window_clamp;
		break;
	case TCP_INFO: {
		struct tcp_info info;

		if (get_user(len, optlen))
			return -EFAULT;

		tcp_get_info(sk, &info);

		len = min_t(unsigned int, len, sizeof(info));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &info, len))
			return -EFAULT;
		return 0;
	}
	case TCP_CC_INFO: {
		const struct tcp_congestion_ops *ca_ops;
		union tcp_cc_info info;
		size_t sz = 0;
		int attr;

		if (get_user(len, optlen))
			return -EFAULT;

		ca_ops = icsk->icsk_ca_ops;
		if (ca_ops && ca_ops->get_info)
			sz = ca_ops->get_info(sk, ~0U, &attr, &info);

		len = min_t(unsigned int, len, sz);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &info, len))
			return -EFAULT;
		return 0;
	}
	case TCP_QUICKACK:
		val = !icsk->icsk_ack.pingpong;
		break;

	case TCP_CONGESTION:
		if (get_user(len, optlen))
			return -EFAULT;
		len = min_t(unsigned int, len, TCP_CA_NAME_MAX);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, icsk->icsk_ca_ops->name, len))
			return -EFAULT;
		return 0;

	case TCP_ULP:
		if (get_user(len, optlen))
			return -EFAULT;
		len = min_t(unsigned int, len, TCP_ULP_NAME_MAX);
		if (!icsk->icsk_ulp_ops) {
			if (put_user(0, optlen))
				return -EFAULT;
			return 0;
		}
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, icsk->icsk_ulp_ops->name, len))
			return -EFAULT;
		return 0;

	case TCP_FASTOPEN_KEY: {
		__u8 key[TCP_FASTOPEN_KEY_LENGTH];
		struct tcp_fastopen_context *ctx;

		if (get_user(len, optlen))
			return -EFAULT;

		rcu_read_lock();
		ctx = rcu_dereference(icsk->icsk_accept_queue.fastopenq.ctx);
		if (ctx)
			memcpy(key, ctx->key, sizeof(key));
		else
			len = 0;
		rcu_read_unlock();

		len = min_t(unsigned int, len, sizeof(key));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, key, len))
			return -EFAULT;
		return 0;
	}
	case TCP_THIN_LINEAR_TIMEOUTS:
		val = tp->thin_lto;
		break;

	case TCP_THIN_DUPACK:
		val = 0;
		break;

	case TCP_REPAIR:
		val = tp->repair;
		break;

	case TCP_REPAIR_QUEUE:
		if (tp->repair)
			val = tp->repair_queue;
		else
			return -EINVAL;
		break;

	case TCP_REPAIR_WINDOW: {
		struct tcp_repair_window opt;

		if (get_user(len, optlen))
			return -EFAULT;

		if (len != sizeof(opt))
			return -EINVAL;

		if (!tp->repair)
			return -EPERM;

		opt.snd_wl1	= tp->snd_wl1;
		opt.snd_wnd	= tp->snd_wnd;
		opt.max_window	= tp->max_window;
		opt.rcv_wnd	= tp->rcv_wnd;
		opt.rcv_wup	= tp->rcv_wup;

		if (copy_to_user(optval, &opt, len))
			return -EFAULT;
		return 0;
	}
	case TCP_QUEUE_SEQ:
		if (tp->repair_queue == TCP_SEND_QUEUE)
			val = tp->write_seq;
		else if (tp->repair_queue == TCP_RECV_QUEUE)
			val = tp->rcv_nxt;
		else
			return -EINVAL;
		break;

	case TCP_USER_TIMEOUT:
		val = icsk->icsk_user_timeout;
		break;

	case TCP_FASTOPEN:
		val = icsk->icsk_accept_queue.fastopenq.max_qlen;
		break;

	case TCP_FASTOPEN_CONNECT:
		val = tp->fastopen_connect;
		break;

	case TCP_FASTOPEN_NO_COOKIE:
		val = tp->fastopen_no_cookie;
		break;

	case TCP_TIMESTAMP:
		val = tcp_time_stamp_raw() + tp->tsoffset;
		break;
	case TCP_NOTSENT_LOWAT:
		val = tp->notsent_lowat;
		break;
	case TCP_INQ:
		val = tp->recvmsg_inq;
		break;
	case TCP_SAVE_SYN:
		val = tp->save_syn;
		break;
	case TCP_SAVED_SYN: {
		if (get_user(len, optlen))
			return -EFAULT;

		lock_sock(sk);
		if (tp->saved_syn) {
			if (len < tp->saved_syn[0]) {
				if (put_user(tp->saved_syn[0], optlen)) {
					release_sock(sk);
					return -EFAULT;
				}
				release_sock(sk);
				return -EINVAL;
			}
			len = tp->saved_syn[0];
			if (put_user(len, optlen)) {
				release_sock(sk);
				return -EFAULT;
			}
			if (copy_to_user(optval, tp->saved_syn + 1, len)) {
				release_sock(sk);
				return -EFAULT;
			}
			tcp_saved_syn_free(tp);
			release_sock(sk);
		} else {
			release_sock(sk);
			len = 0;
			if (put_user(len, optlen))
				return -EFAULT;
		}
		return 0;
	}
#ifdef CONFIG_MMU
	case TCP_ZEROCOPY_RECEIVE: {
		struct tcp_zerocopy_receive zc;
		int err;

		if (get_user(len, optlen))
			return -EFAULT;
		if (len != sizeof(zc))
			return -EINVAL;
		if (copy_from_user(&zc, optval, len))
			return -EFAULT;
		lock_sock(sk);
		err = tcp_zerocopy_receive(sk, &zc);
		release_sock(sk);
		if (!err && copy_to_user(optval, &zc, len))
			err = -EFAULT;
		return err;
	}
#endif
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

int tcp_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TCP)
		return icsk->icsk_af_ops->getsockopt(sk, level, optname,
						     optval, optlen);
	return do_tcp_getsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(tcp_getsockopt);

#ifdef CONFIG_COMPAT
int compat_tcp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (level != SOL_TCP)
		return inet_csk_compat_getsockopt(sk, level, optname,
						  optval, optlen);
	return do_tcp_getsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(compat_tcp_getsockopt);
#endif

#ifdef CONFIG_TCP_MD5SIG
static DEFINE_PER_CPU(struct tcp_md5sig_pool, tcp_md5sig_pool);
static DEFINE_MUTEX(tcp_md5sig_mutex);
static bool tcp_md5sig_pool_populated = false;

static void __tcp_alloc_md5sig_pool(void)
{
	struct crypto_ahash *hash;
	int cpu;

	hash = crypto_alloc_ahash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash))
		return;

	for_each_possible_cpu(cpu) {
		void *scratch = per_cpu(tcp_md5sig_pool, cpu).scratch;
		struct ahash_request *req;

		if (!scratch) {
			scratch = kmalloc_node(sizeof(union tcp_md5sum_block) +
					       sizeof(struct tcphdr),
					       GFP_KERNEL,
					       cpu_to_node(cpu));
			if (!scratch)
				return;
			per_cpu(tcp_md5sig_pool, cpu).scratch = scratch;
		}
		if (per_cpu(tcp_md5sig_pool, cpu).md5_req)
			continue;

		req = ahash_request_alloc(hash, GFP_KERNEL);
		if (!req)
			return;

		ahash_request_set_callback(req, 0, NULL, NULL);

		per_cpu(tcp_md5sig_pool, cpu).md5_req = req;
	}
	/* before setting tcp_md5sig_pool_populated, we must commit all writes
	 * to memory. See smp_rmb() in tcp_get_md5sig_pool()
	 */
	smp_wmb();
	tcp_md5sig_pool_populated = true;
}

bool tcp_alloc_md5sig_pool(void)
{
	if (unlikely(!tcp_md5sig_pool_populated)) {
		mutex_lock(&tcp_md5sig_mutex);

		if (!tcp_md5sig_pool_populated) {
			__tcp_alloc_md5sig_pool();
			if (tcp_md5sig_pool_populated)
				static_key_slow_inc(&tcp_md5_needed);
		}

		mutex_unlock(&tcp_md5sig_mutex);
	}
	return tcp_md5sig_pool_populated;
}
EXPORT_SYMBOL(tcp_alloc_md5sig_pool);


/**
 *	tcp_get_md5sig_pool - get md5sig_pool for this user
 *
 *	We use percpu structure, so if we succeed, we exit with preemption
 *	and BH disabled, to make sure another thread or softirq handling
 *	wont try to get same context.
 */
struct tcp_md5sig_pool *tcp_get_md5sig_pool(void)
{
	local_bh_disable();

	if (tcp_md5sig_pool_populated) {
		/* coupled with smp_wmb() in __tcp_alloc_md5sig_pool() */
		smp_rmb();
		return this_cpu_ptr(&tcp_md5sig_pool);
	}
	local_bh_enable();
	return NULL;
}
EXPORT_SYMBOL(tcp_get_md5sig_pool);

int tcp_md5_hash_skb_data(struct tcp_md5sig_pool *hp,
			  const struct sk_buff *skb, unsigned int header_len)
{
	struct scatterlist sg;
	const struct tcphdr *tp = tcp_hdr(skb);
	struct ahash_request *req = hp->md5_req;
	unsigned int i;
	const unsigned int head_data_len = skb_headlen(skb) > header_len ?
					   skb_headlen(skb) - header_len : 0;
	const struct skb_shared_info *shi = skb_shinfo(skb);
	struct sk_buff *frag_iter;

	sg_init_table(&sg, 1);

	sg_set_buf(&sg, ((u8 *) tp) + header_len, head_data_len);
	ahash_request_set_crypt(req, &sg, NULL, head_data_len);
	if (crypto_ahash_update(req))
		return 1;

	for (i = 0; i < shi->nr_frags; ++i) {
		const struct skb_frag_struct *f = &shi->frags[i];
		unsigned int offset = f->page_offset;
		struct page *page = skb_frag_page(f) + (offset >> PAGE_SHIFT);

		sg_set_page(&sg, page, skb_frag_size(f),
			    offset_in_page(offset));
		ahash_request_set_crypt(req, &sg, NULL, skb_frag_size(f));
		if (crypto_ahash_update(req))
			return 1;
	}

	skb_walk_frags(skb, frag_iter)
		if (tcp_md5_hash_skb_data(hp, frag_iter, 0))
			return 1;

	return 0;
}
EXPORT_SYMBOL(tcp_md5_hash_skb_data);

int tcp_md5_hash_key(struct tcp_md5sig_pool *hp, const struct tcp_md5sig_key *key)
{
	struct scatterlist sg;

	sg_init_one(&sg, key->key, key->keylen);
	ahash_request_set_crypt(hp->md5_req, &sg, NULL, key->keylen);
	return crypto_ahash_update(hp->md5_req);
}
EXPORT_SYMBOL(tcp_md5_hash_key);

#endif

/* 该函数用于完成关闭 TCP 连接，回收并清理相关资源。 */
void tcp_done(struct sock *sk)
{
	struct request_sock *req = tcp_sk(sk)->fastopen_rsk;

	/* 当套接字状态为 SYN_SENT 或 SYN_RECV 时，更新统计数据。 */
	if (sk->sk_state == TCP_SYN_SENT || sk->sk_state == TCP_SYN_RECV)
		TCP_INC_STATS(sock_net(sk), TCP_MIB_ATTEMPTFAILS);

	/* 将连接状态设置为关闭，并清除定时器。 */
	tcp_set_state(sk, TCP_CLOSE);
	tcp_clear_xmit_timers(sk);

	/* 当启用了 Fast Open 时，移除 fastopen 请求 */
	if (req)
		reqsk_fastopen_remove(sk, req, false);

	sk->sk_shutdown = SHUTDOWN_MASK;

	/* 如果状态不为 SOCK_DEAD，则唤醒等待着的进程。 */
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);
	else
		inet_csk_destroy_sock(sk);
}
EXPORT_SYMBOL_GPL(tcp_done);

int tcp_abort(struct sock *sk, int err)
{
	if (!sk_fullsock(sk)) {
		if (sk->sk_state == TCP_NEW_SYN_RECV) {
			struct request_sock *req = inet_reqsk(sk);

			local_bh_disable();
			inet_csk_reqsk_queue_drop(req->rsk_listener, req);
			local_bh_enable();
			return 0;
		}
		return -EOPNOTSUPP;
	}

	/* Don't race with userspace socket closes such as tcp_close. */
	lock_sock(sk);

	if (sk->sk_state == TCP_LISTEN) {
		tcp_set_state(sk, TCP_CLOSE);
		inet_csk_listen_stop(sk);
	}

	/* Don't race with BH socket closes such as inet_csk_listen_stop. */
	local_bh_disable();
	bh_lock_sock(sk);

	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_err = err;
		/* This barrier is coupled with smp_rmb() in tcp_poll() */
		smp_wmb();
		sk->sk_error_report(sk);
		if (tcp_need_reset(sk->sk_state))
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
	}

	bh_unlock_sock(sk);
	local_bh_enable();
	tcp_write_queue_purge(sk);
	release_sock(sk);
	return 0;
}
EXPORT_SYMBOL_GPL(tcp_abort);

extern struct tcp_congestion_ops tcp_reno;

static __initdata unsigned long thash_entries;
static int __init set_thash_entries(char *str)
{
	ssize_t ret;

	if (!str)
		return 0;

	ret = kstrtoul(str, 0, &thash_entries);
	if (ret)
		return 0;

	return 1;
}
__setup("thash_entries=", set_thash_entries);

static void __init tcp_init_mem(void)
{
	unsigned long limit = nr_free_buffer_pages() / 16;

	limit = max(limit, 128UL);
	sysctl_tcp_mem[0] = limit / 4 * 3;		/* 4.68 % */
	sysctl_tcp_mem[1] = limit;			/* 6.25 % */
	sysctl_tcp_mem[2] = sysctl_tcp_mem[0] * 2;	/* 9.37 % */
}

void __init tcp_init(void)
{
	int max_rshare, max_wshare, cnt;
	unsigned long limit;
	unsigned int i;

	BUILD_BUG_ON(sizeof(struct tcp_skb_cb) >
		     FIELD_SIZEOF(struct sk_buff, cb));

	percpu_counter_init(&tcp_sockets_allocated, 0, GFP_KERNEL);
	percpu_counter_init(&tcp_orphan_count, 0, GFP_KERNEL);

	/* 初始化hash信息 */
	inet_hashinfo_init(&tcp_hashinfo);
	inet_hashinfo2_init(&tcp_hashinfo, "tcp_listen_portaddr_hash",
			    thash_entries, 21,  /* one slot per 2 MB*/
			    0, 64 * 1024);
	tcp_hashinfo.bind_bucket_cachep =
		kmem_cache_create("tcp_bind_bucket",
				  sizeof(struct inet_bind_bucket), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	/* Size and allocate the main established and bind bucket
	 * hash tables.
	 *
	 * The methodology is similar to that of the buffer cache.
	 */
	tcp_hashinfo.ehash =
		alloc_large_system_hash("TCP established",
					sizeof(struct inet_ehash_bucket),
					thash_entries,
					17, /* one slot per 128 KB of memory */
					0,
					NULL,
					&tcp_hashinfo.ehash_mask,
					0,
					thash_entries ? 0 : 512 * 1024);
	for (i = 0; i <= tcp_hashinfo.ehash_mask; i++)
		INIT_HLIST_NULLS_HEAD(&tcp_hashinfo.ehash[i].chain, i);

	if (inet_ehash_locks_alloc(&tcp_hashinfo))
		panic("TCP: failed to alloc ehash_locks");
	tcp_hashinfo.bhash =
		alloc_large_system_hash("TCP bind",
					sizeof(struct inet_bind_hashbucket),
					tcp_hashinfo.ehash_mask + 1,
					17, /* one slot per 128 KB of memory */
					0,
					&tcp_hashinfo.bhash_size,
					NULL,
					0,
					64 * 1024);
	tcp_hashinfo.bhash_size = 1U << tcp_hashinfo.bhash_size;
	for (i = 0; i < tcp_hashinfo.bhash_size; i++) {
		spin_lock_init(&tcp_hashinfo.bhash[i].lock);
		INIT_HLIST_HEAD(&tcp_hashinfo.bhash[i].chain);
	}


	cnt = tcp_hashinfo.ehash_mask + 1;
	sysctl_tcp_max_orphans = cnt / 2;

	/* 初始化 sysctl_tcp_mem
		/proc/sys/net/ipv4/tcp_mem
	*/
	tcp_init_mem();
	/* Set per-socket limits to no more than 1/128 the pressure threshold */
	limit = nr_free_buffer_pages() << (PAGE_SHIFT - 7);
	max_wshare = min(4UL*1024*1024, limit);
	max_rshare = min(6UL*1024*1024, limit);

	/* /proc/sys/net/ipv4/tcp_wmem */
	init_net.ipv4.sysctl_tcp_wmem[0] = SK_MEM_QUANTUM;
	init_net.ipv4.sysctl_tcp_wmem[1] = 16*1024;
	init_net.ipv4.sysctl_tcp_wmem[2] = max(64*1024, max_wshare);

	/* /proc/sys/net/ipv4/tcp_rmem */
	init_net.ipv4.sysctl_tcp_rmem[0] = SK_MEM_QUANTUM;
	init_net.ipv4.sysctl_tcp_rmem[1] = 131072;  //128k
	init_net.ipv4.sysctl_tcp_rmem[2] = max(131072, max_rshare);

	pr_info("Hash tables configured (established %u bind %u)\n",
		tcp_hashinfo.ehash_mask + 1, tcp_hashinfo.bhash_size);

	/* ipv4 tcp 初始化 */
	tcp_v4_init();
	
	tcp_metrics_init();

	/* 拥塞算法初始化， 最终 ubunut会用到 cubic拥塞算法 */
	BUG_ON(tcp_register_congestion_control(&tcp_reno) != 0);
	tcp_tasklet_init();
}
