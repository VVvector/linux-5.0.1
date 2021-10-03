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

#include <linux/module.h>
#include <linux/gfp.h>
#include <net/tcp.h>


/*
 * TCP为每条连接建立7个定时器：连接建立定时器，重传定时器，延时ACK定时器，持续定时器，保活定时器，
 * FIN_WAIT_2定时器，TIME_WAIT定时器。
 * 但实际上，为了提高效率，内核中只使用了4个定时器来完成了7个定时器的功能，也就是说，某些定时功能
 * 合用了同一个定时器，其中FIN_WAIT_2和TIME_WAIT定时器比较特殊，当sock状态为FIN_WAIT_2或TIME_WAIT
 * 时，tcp_sock会转变为inet_timewait_sock，定时器也就由inet_timewait_sock来管理。
 */

static u32 tcp_retransmit_stamp(const struct sock *sk)
{
	u32 start_ts = tcp_sk(sk)->retrans_stamp;

	if (unlikely(!start_ts)) {
		struct sk_buff *head = tcp_rtx_queue_head(sk);

		if (!head)
			return 0;
		start_ts = tcp_skb_timestamp(head);
	}
	return start_ts;
}

static u32 tcp_clamp_rto_to_user_timeout(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 elapsed, start_ts;
	s32 remaining;

	start_ts = tcp_retransmit_stamp(sk);
	if (!icsk->icsk_user_timeout || !start_ts)
		return icsk->icsk_rto;
	elapsed = tcp_time_stamp(tcp_sk(sk)) - start_ts;
	remaining = icsk->icsk_user_timeout - elapsed;
	if (remaining <= 0)
		return 1; /* user timeout has passed; fire ASAP */

	return min_t(u32, icsk->icsk_rto, msecs_to_jiffies(remaining));
}

/**
 *  tcp_write_err() - close socket and save error info
 *  @sk:  The socket the error has appeared on.
 *
 *  Returns: Nothing (void)
 */

static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_write_queue_purge(sk);
	tcp_done(sk);
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
}

/**
 *  tcp_out_of_resources() - Close socket if out of resources
 *  @sk:        pointer to current socket
 *  @do_reset:  send a last packet with reset flag
 *
 *  Do not allow orphaned sockets to eat all our resources.
 *  This is direct violation of TCP specs, but it is required
 *  to prevent DoS attacks. It is called when a retransmission timeout
 *  or zero probe timeout occurs on orphaned socket.
 *
 *  Also close if our net namespace is exiting; in that case there is no
 *  hope of ever communicating again since all netns interfaces are already
 *  down (or about to be down), and we need to release our dst references,
 *  which have been moved to the netns loopback interface, so the namespace
 *  can finish exiting.  This condition is only possible if we are a kernel
 *  socket, as those do not hold references to the namespace.
 *
 *  Criteria is still not confirmed experimentally and may change.
 *  We kill the socket, if:
 *  1. If number of orphaned sockets exceeds an administratively configured
 *     limit.
 *  2. If we have strong memory pressure.
 *  3. If our net namespace is exiting.
 */
static int tcp_out_of_resources(struct sock *sk, bool do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int shift = 0;

	/* If peer does not open window for long time, or did not transmit
	 * anything for long time, penalize it. */
	if ((s32)(tcp_jiffies32 - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		shift++;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		shift++;

	if (tcp_check_oom(sk, shift)) {
		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_jiffies32 - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = true;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}

	if (!check_net(sock_net(sk))) {
		/* Not possible to send reset; just close */
		tcp_done(sk);
		return 1;
	}

	return 0;
}

/**
 *  tcp_orphan_retries() - Returns maximal number of retries on an orphaned socket
 *  @sk:    Pointer to the current socket.
 *  @alive: bool, socket alive state
 */
static int tcp_orphan_retries(struct sock *sk, bool alive)
{
	int retries = sock_net(sk)->ipv4.sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

/*
 * https://cloud.tencent.com/developer/article/1411873
 * 因为PMTU可能随着不同的路径而变化，为了避免PMTU变小而导致发送失败，就需要探测MTU。
 *
 * MTU探测的工作函数tcp_mtu_probing是在tcp_write_timeout中调用的：
 * 当TCP重传超过设置的sysctl_tcp_retries1值（/proc/sys/net/ipv4/tcp_retries1）时，
 * 就会调用tcp_mtu_probing()。当PMTU小于MSS时，TCP报文就会传输失败。
 * 因为默认情况下，系统都会设置禁止IP分片，这时就需要进行tcp_mtu_probing。
 *
 * MTU的下线探测还是比较激进的。首先，取探测下限search_low计算的MSS的一半值，
 * 然后与系统配置的tcp_base_mss相比，取较小值。这个较小值，不能低于可能的最小值68-tcp_header_len，
 * 并根据结果重新设置了探测下限。通过这样的方法，内核会探测到真实的PMTU，从而保证TCP报文可以顺利发送。
 */
static void tcp_mtu_probing(struct inet_connection_sock *icsk, struct sock *sk)
{
	const struct net *net = sock_net(sk);
	int mss;

	/* Black hole detection */
	if (!net->ipv4.sysctl_tcp_mtu_probing)
		return;

	if (!icsk->icsk_mtup.enabled) {
		icsk->icsk_mtup.enabled = 1;
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
	} else {
		mss = tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low) >> 1;
		mss = min(net->ipv4.sysctl_tcp_base_mss, mss);
		mss = max(mss, 68 - tcp_sk(sk)->tcp_header_len);
		icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);
	}
	tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
}


/**
 *  retransmits_timed_out() - returns true if this connection has timed out
 *  @sk:       The current socket
 *  @boundary: max number of retransmissions
 *  @timeout:  A custom timeout value.
 *             If set to 0 the default timeout is calculated and used.
 *             Using TCP_RTO_MIN and the number of unsuccessful retransmits.
 *
 * The default "timeout" value this function can calculate and use
 * is equivalent to the timeout of a TCP Connection
 * after "boundary" unsuccessful, exponentially backed-off
 * retransmissions with an initial RTO of TCP_RTO_MIN.
 */
static bool retransmits_timed_out(struct sock *sk,
				  unsigned int boundary,
				  unsigned int timeout)
{
	const unsigned int rto_base = TCP_RTO_MIN;
	unsigned int linear_backoff_thresh, start_ts;

	if (!inet_csk(sk)->icsk_retransmits)
		return false;

	start_ts = tcp_retransmit_stamp(sk);
	if (!start_ts)
		return false;

	if (likely(timeout == 0)) {
		linear_backoff_thresh = ilog2(TCP_RTO_MAX/rto_base);

		if (boundary <= linear_backoff_thresh)
			timeout = ((2 << boundary) - 1) * rto_base;
		else
			timeout = ((2 << linear_backoff_thresh) - 1) * rto_base +
				(boundary - linear_backoff_thresh) * TCP_RTO_MAX;
		timeout = jiffies_to_msecs(timeout);
	}

	/* tp->tcp_mstamp： tcp_output.c -- tcp_connect()中设置重传最开始时间。*/
	return (s32)(tcp_time_stamp(tcp_sk(sk)) - start_ts - timeout) >= 0;
}

/* A write timeout has occurred. Process the after effects. */
static int tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	bool expired, do_reset;

	/* 表示我们需要重传的最大次数 */
	int retry_until;

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		if (icsk->icsk_retransmits) {
			dst_negative_advice(sk);
		} else {
			sk_rethink_txhash(sk);
		}

		/* icsk_syn_retries表示syn失败时，能够重传的最大次数  tcp_syn_retries 5次。 */
		retry_until = icsk->icsk_syn_retries ? : net->ipv4.sysctl_tcp_syn_retries;
		expired = icsk->icsk_retransmits >= retry_until;
	} else {

		/* sysctl_tcp_retries1 表示最大的重传次数，当超过了这个值，就需要检查路由表了。 */
		if (retransmits_timed_out(sk, net->ipv4.sysctl_tcp_retries1, 0)) {
			/* Black hole detection */
			tcp_mtu_probing(icsk, sk);

			dst_negative_advice(sk);
		} else {
			sk_rethink_txhash(sk);
		}

		/* 设置重传最大次数为sysctl_tcp_retries2，一般这个值比 sysctl_tcp_retries1 大
			和上面 sysctl_tcp_retries1 不同，当重传次数超过了这个值，就必须放弃重试了。
		*/
		retry_until = net->ipv4.sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {
			const bool alive = icsk->icsk_rto < TCP_RTO_MAX;

			/* sysctl_tcp_orphan_retries 主要针对孤立的socket(即已经从进程上下文中删除了，
			可是，还有一些清理工作没有完成)； 对于这种socket，我们重试的最大次数就是它。 */
			retry_until = tcp_orphan_retries(sk, alive);

			/* 最终判断 重传次数是否达到 retry_until， 则断开连接，且该函数返回.
				==> 通过retry_until重传次数转换成对于的最大超时时间。
			*/
			do_reset = alive ||
				!retransmits_timed_out(sk, retry_until, 0);

			if (tcp_out_of_resources(sk, do_reset))
				return 1;
		}
		expired = retransmits_timed_out(sk, retry_until,
						icsk->icsk_user_timeout);
	}
	tcp_fastopen_active_detect_blackhole(sk, expired);

	if (BPF_SOCK_OPS_TEST_FLAG(tp, BPF_SOCK_OPS_RTO_CB_FLAG))
		tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_RTO_CB,
				  icsk->icsk_retransmits,
				  icsk->icsk_rto, (int)expired);

	if (expired) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}

	return 0;
}

/* Called with BH disabled */
void tcp_delack_timer_handler(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	sk_mem_reclaim_partial(sk);

	if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)) ||
	    !(icsk->icsk_ack.pending & ICSK_ACK_TIMER))
		goto out;

	if (time_after(icsk->icsk_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
		goto out;
	}
	icsk->icsk_ack.pending &= ~ICSK_ACK_TIMER;

	if (inet_csk_ack_scheduled(sk)) {
		if (!icsk->icsk_ack.pingpong) {
			/* Delayed ACK missed: inflate ATO. */
			icsk->icsk_ack.ato = min(icsk->icsk_ack.ato << 1, icsk->icsk_rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			icsk->icsk_ack.pingpong = 0;
			icsk->icsk_ack.ato      = TCP_ATO_MIN;
		}
		tcp_mstamp_refresh(tcp_sk(sk));
		tcp_send_ack(sk);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_DELAYEDACKS);
	}

out:
	if (tcp_under_memory_pressure(sk))
		sk_mem_reclaim(sk);
}


/**
 *  tcp_delack_timer() - The TCP delayed ACK timeout handler
 *  @data:  Pointer to the current socket. (gets casted to struct sock *)
 *
 *  This function gets (indirectly) called when the kernel timer for a TCP packet
 *  of this socket expires. Calls tcp_delack_timer_handler() to do the actual work.
 *
 *  Returns: Nothing (void)
 */
/* 延时确认定时器的处理函数：
 * “延时 ACK”定时器在tcp收到必须被确认但无需马上发出确认的段时设定，tcp在200ms后发送确认响应，
 * 如果在这200ms内，有数据要在该连接发送，延时ACK响应就可随数据一起发送回对端，称为捎带确认。
 *
 * 延时确认定时器的激活：
 * 1. 在建立连接时，客户端的第三次握手可能会被延时确认，如有数据需要输出，设置了TCP_DEFER_ACCEPT
 * 选项或者不在快速确认模式。
 * 2. 在确定立即发送ACK时，如果内存分配失败，则会进行延时确认。
 */
static void tcp_delack_timer(struct timer_list *t)
{
	struct inet_connection_sock *icsk =
			from_timer(icsk, t, icsk_delack_timer);
	struct sock *sk = &icsk->icsk_inet.sk;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		tcp_delack_timer_handler(sk);
	} else {
		icsk->icsk_ack.blocked = 1;
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
		/* deleguate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_DELACK_TIMER_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

/* 持续(0窗口)定时器的处理函数 */
static void tcp_probe_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb = tcp_send_head(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;
	u32 start_ts;

	if (tp->packets_out || !skb) {
		icsk->icsk_probes_out = 0;
		return;
	}

	/* RFC 1122 4.2.2.17 requires the sender to stay open indefinitely as
	 * long as the receiver continues to respond probes. We support this by
	 * default and reset icsk_probes_out with incoming ACKs. But if the
	 * socket is orphaned or the user specifies TCP_USER_TIMEOUT, we
	 * kill the socket when the retry count and the time exceeds the
	 * corresponding system limit. We also implement similar policy when
	 * we use RTO to probe window in tcp_retransmit_timer().
	 */
	start_ts = tcp_skb_timestamp(skb);
	if (!start_ts)
		skb->skb_mstamp_ns = tp->tcp_clock_cache;
	else if (icsk->icsk_user_timeout &&
		 (s32)(tcp_time_stamp(tp) - start_ts) > icsk->icsk_user_timeout)
		goto abort;

	max_probes = sock_net(sk)->ipv4.sysctl_tcp_retries2;
	if (sock_flag(sk, SOCK_DEAD)) {
		const bool alive = inet_csk_rto_backoff(icsk, TCP_RTO_MAX) < TCP_RTO_MAX;

		max_probes = tcp_orphan_retries(sk, alive);
		if (!alive && icsk->icsk_backoff >= max_probes)
			goto abort;
		if (tcp_out_of_resources(sk, true))
			return;
	}

	if (icsk->icsk_probes_out >= max_probes) {
abort:		tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
		tcp_send_probe0(sk);
	}
}

/*
 *	Timer for Fast Open socket to retransmit SYNACK. Note that the
 *	sk here is the child socket, not the parent (listener) socket.
 */
static void tcp_fastopen_synack_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int max_retries = icsk->icsk_syn_retries ? :
	    sock_net(sk)->ipv4.sysctl_tcp_synack_retries + 1; /* add one more retry for fastopen */
	struct request_sock *req;

	req = tcp_sk(sk)->fastopen_rsk;
	req->rsk_ops->syn_ack_timeout(req);

	if (req->num_timeout >= max_retries) {
		tcp_write_err(sk);
		return;
	}
	/* XXX (TFO) - Unlike regular SYN-ACK retransmit, we ignore error
	 * returned from rtx_syn_ack() to make it more persistent like
	 * regular retransmit because if the child socket has been accepted
	 * it's not good to give up too easily.
	 */
	inet_rtx_syn_ack(sk, req);
	req->num_timeout++;
	icsk->icsk_retransmits++;
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
			  TCP_TIMEOUT_INIT << req->num_timeout, TCP_RTO_MAX);
}


/**
 *  tcp_retransmit_timer() - The TCP retransmit timeout handler
 *  @sk:  Pointer to the current socket.
 *
 *  This function gets called when the kernel timer for a TCP packet
 *  of this socket expires.
 *
 *  It handles retransmission, timer adjustment and other necesarry measures.
 *
 *  Returns: Nothing (void)
 */
void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (tp->fastopen_rsk) {
		WARN_ON_ONCE(sk->sk_state != TCP_SYN_RECV &&
			     sk->sk_state != TCP_FIN_WAIT1);

		/* syn ack timer， 检查syn后的ack timeout处理。 */
		tcp_fastopen_synack_timer(sk);
		/* Before we receive ACK to our SYN-ACK don't retransmit
		 * anything else (e.g., data or FIN segments).
		 */
		return;
	}

	/* 如果没有需要确认的ack包，则什么都不做。 */
	if (!tp->packets_out)
		goto out;

	WARN_ON(tcp_rtx_queue_empty(sk));

	tp->tlp_high_seq = 0;


	/*
	 * snd_wnd为窗口大小。sock_flag用来判断sock的状态，最后一个判断是
	 * 当前的连接状态不能处于sync_sent和syn_recv状态，即连接还未建立状态。
	 */
	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
		struct inet_sock *inet = inet_sk(sk);
		if (sk->sk_family == AF_INET) {
			net_dbg_ratelimited("Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
					    &inet->inet_daddr,
					    ntohs(inet->inet_dport),
					    inet->inet_num,
					    tp->snd_una, tp->snd_nxt);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (sk->sk_family == AF_INET6) {
			net_dbg_ratelimited("Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
					    &sk->sk_v6_daddr,
					    ntohs(inet->inet_dport),
					    inet->inet_num,
					    tp->snd_una, tp->snd_nxt);
		}
#endif

		/*
		 * tcp_jiffies32也就是jiffes，而rcv_tstamp表示最后一个ack接收的时间，也就是
		 * 最后一次对端确认的时间。因此，这两个时间之差不能大于tcp_rto_max，因为
		 * tcp_rto_max为我们重传定时器的间隔时间的最大值。
		 * tp->rcv_tstamp会在 tcp_input.c的 tcp_ack()函数中被更新
		 */
		if (tcp_jiffies32 - tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(sk);
			goto out;
		}

		/* 这个函数用来进入loss状态，也就是进行一些拥塞以及流量的控制。 */
		tcp_enter_loss(sk);

		/* 现在开始重传skb */
		tcp_retransmit_skb(sk, tcp_rtx_queue_head(sk), 1);
		__sk_dst_reset(sk);

		/* 然后，重启定时器，继续等待ack的到来。 */
		goto out_reset_timer;
	}


	/* 判断重传次数是否已经到了，如果超过了系统设定的重传次数，直接退出到out */
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTIMEOUTS);
	if (tcp_write_timeout(sk)) //重要api
		goto out;

	/* 到达这里，说明我们重传的次数还没到，icsk->icsk_retransmits表示重传的次数，下面进行了统计信息的收集。 */
	if (icsk->icsk_retransmits == 0) {
		int mib_idx = 0;

		if (icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else if ((icsk->icsk_ca_state == TCP_CA_Disorder) ||
			   tp->sacked_out) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		}
		if (mib_idx)
			__NET_INC_STATS(sock_net(sk), mib_idx);
	}

	tcp_enter_loss(sk);

	/* 再一次尝试重传失败了。。。 */
	if (tcp_retransmit_skb(sk, tcp_rtx_queue_head(sk), 1) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  min(icsk->icsk_rto, TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	icsk->icsk_backoff++;  //主要用于零窗口定时器
	icsk->icsk_retransmits++; //重传次数自加

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	 /* 如果是小数据(thin stream)包，则设置rto的值。 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || net->ipv4.sysctl_tcp_thin_linear_timeouts) &&
	    tcp_stream_is_thin(tp) &&
	    icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		icsk->icsk_backoff = 0;
		icsk->icsk_rto = min(__tcp_set_rto(tp), TCP_RTO_MAX);

	/* block thream，计算rto，并重启定时器，这里使用kam算法，也就是下次超时时间增加一倍。*/
	} else {  
		/* Use normal (exponential) backoff */
		icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	}
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  tcp_clamp_rto_to_user_timeout(sk), TCP_RTO_MAX);

	if (retransmits_timed_out(sk, net->ipv4.sysctl_tcp_retries1 + 1, 0))
		__sk_dst_reset(sk);

out:;
}

/* Called with bottom-half processing disabled.
   Called by tcp_write_timer() */
void tcp_write_timer_handler(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int event;

	if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)) ||
	    !icsk->icsk_pending)
		goto out;

	if (time_after(icsk->icsk_timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
		goto out;
	}

	tcp_mstamp_refresh(tcp_sk(sk));
	event = icsk->icsk_pending;

	switch (event) {
	case ICSK_TIME_REO_TIMEOUT:
		tcp_rack_reo_timeout(sk);
		break;
	case ICSK_TIME_LOSS_PROBE:
		tcp_send_loss_probe(sk);
		break;
	/* 重传处理定时器 */
	case ICSK_TIME_RETRANS:
		icsk->icsk_pending = 0;
		tcp_retransmit_timer(sk);
		break;

	/* 持续定时器 */
	case ICSK_TIME_PROBE0:
		icsk->icsk_pending = 0;
		tcp_probe_timer(sk);
		break;
	}

out:
	sk_mem_reclaim(sk);
}

/* 重传定时器和持续(0窗口)定时器
 * 重传定时器：
 * 在tcp发送数据时设定，如果定时器已超时而对端确认还未到达，则tcp将重传数据。
 * 重传定时器的超时时间值是动态计算的，取决于tcp为该连接测量的往返时间以及该
 * 段已被重传的次数。
 *
 * 持续(0窗口)定时器：
 * 在对端通告接收窗为0，阻止TCP继续发送数据时设定。由于连接对端发送的窗口通告不可靠
 *（只有数据才会确认，ACK不会被确认），允许TCP继续发送数据的后续窗口更新有可能丢失，
 * 因此，如果TCP有数据要发送，而对端通告接收窗为0，则持续定时器启动，超时后，向对端
 * 发送1字节的数据，以判断对端接收窗是否已打开。与重传定时器类似，持续定时器的超时
 * 也是动态计算的，取决于连接的往返时间，在5-60s之间取值。
 *
 * 重传定时器的激活：
 * 1. 如果发送在一个正常段之前不存在为未确认的段，在发送出该段之后。
 * 2. 客户端连续发送SYN段后
 * 3. 路径MTU探测失败后
 * 4. 接收方丢弃SACK部分接收的段
 *
 * 持续定时器的激活：
 * 1. 接收到ACK时：通常情况下，tcp在接收到ack后会检测对方的接收窗口大小。此时，如果本端还有
 * 段需要发送，则会调用tcp_ack_probe()根据情况确认是否进行零窗口的探测。
 * 2. 发送tcp段失败：在发送tcp段时，如果发送失败，则会调用tcp_check_probe_timer()检测是否需要
 * 激活持续定时器，如有必要，则其激活。
 */
static void tcp_write_timer(struct timer_list *t)
{
	struct inet_connection_sock *icsk =
			from_timer(icsk, t, icsk_retransmit_timer);
	struct sock *sk = &icsk->icsk_inet.sk;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		tcp_write_timer_handler(sk);
	} else {
		/* delegate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_WRITE_TIMER_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

void tcp_syn_ack_timeout(const struct request_sock *req)
{
	struct net *net = read_pnet(&inet_rsk(req)->ireq_net);

	__NET_INC_STATS(net, LINUX_MIB_TCPTIMEOUTS);
}
EXPORT_SYMBOL(tcp_syn_ack_timeout);

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		inet_csk_delete_keepalive_timer(sk);
}
EXPORT_SYMBOL_GPL(tcp_set_keepalive);

/* 
 * 该timer实现了tcp的2个定时器：保活定时器，FIN_WAIT_2定时器。
 * 这是由于这三个定时器分别处于ESTANBLISHED和FIN_WAIT_2三种状态，因此，
 * 不必区分它们，只需要简单地通过当前tcp状态就能判断当前执行的是何种定时器。
 */
static void tcp_keepalive_timer(struct timer_list *t)
{
	struct sock *sk = from_timer(sk, t, sk_timer);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		inet_csk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}

	if (sk->sk_state == TCP_LISTEN) {
		pr_err("Hmm... keepalive on a LISTEN ???\n");
		goto out;
	}

	/* 连接释放期间，用作FIN_WAIT_2定时器：
	 * 当某个连接从FIN_WAIT_1状态变迁到FIN_WAIT_2状态，且不能再接收任何新数据时，则意味着应用
	 * 进程调用了close()而非shutdown()，没有利用tcp的半关闭功能，FIN_WAIT_2定时器启动，超时时间
	 * 为10min，在定时器第一次超时后，重新设置超时时间为75s，第二次超时后关闭连接。
	 * 加入这个定时器的目的是为了避免对端一直部分FIN, 某个连接会用于滞留在FIN_WAIT_2状态。
	 *
	 * TIME_WAIT定时器：
	 * 一般称为2MSL定时器，2MSL指两倍的MSL(最大段生存时间)。当连接转换到TIME_WAIT状态，即连接
	 * 主动关闭时，TIME_WAIT定时器启动，超时时间设定为1min，超时后，TCP控制块被删除，端口号可重新使用。
	 */
	tcp_mstamp_refresh(tp);
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) {
		if (tp->linger2 >= 0) {
			const int tmo = tcp_fin_time(sk) - TCP_TIMEWAIT_LEN;
			if (tmo > 0) {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}

		/* 发送 TCP HDR_RST package */
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

	/* 其余期间，用作保活定时器：
	 * 超时时间：7200秒，即2小时， 即超时后，会执行该timer函数。
	 * 最大次数：9次
	 * 每次发送packet间隔：75秒
	 * 
	 * 注：
	 * 只有在socket设置了SO_KEEPALIVE套接字选项后，才会发送保活探测消息。
	 */
	if (!sock_flag(sk, SOCK_KEEPOPEN) ||
	    ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)))
		goto out;

	/* 连接的空闲时间超过此值，就发送保活探测报文。 */
	elapsed = keepalive_time_when(tp);

	/* It is alive without keepalive 8) */
	/* 如果网络中有发送且未确认的数据包，或者，发送队列不为空，说明该连接不是idle的。
	 * 既然连接不是idle的，就没有必要探测对端是否正常，重新开始计时即可。
	 * 
	 * 而实际上当网络中有发送且未确认的数据包时，对端也可能会发生异常而没有响应。 
	 * 这个时候会导致数据包的不断重传，只能依靠重传超过了允许的最大时间，来判断连接超时。 
	 * 为了解决这一问题，引入了TCP_USER_TIMEOUT，允许用户指定超时时间，可见下文。
	 */
	if (tp->packets_out || !tcp_write_queue_empty(sk))
		goto resched;

	/* 连接经历的空闲时间，即上次收到报文至今的时间。 */
	/* elapsed time of last received data packet */
	elapsed = keepalive_time_elapsed(tp);

	/* 如果连接空闲的时间超过了设置的时间（最大是 7200s, 两个小时。） */
	if (elapsed >= keepalive_time_when(tp)) {
		/* If the TCP_USER_TIMEOUT option is enabled, use that
		 * to determine when to timeout instead.
		 */
		/*
		 * 两种情况下关闭连接：
		 * 1. 使用了TCP_USER_TIMEOUT选项，且有发送过探测报文，但是连接空闲时间超过了用户设置的时间。
		 * 2. 没有使用TCP_USER_TIMETOUT选项，当发送的保活探测包个数达到了最大次数。
		 */
		if ((icsk->icsk_user_timeout != 0 &&
		    elapsed >= msecs_to_jiffies(icsk->icsk_user_timeout) &&
		    icsk->icsk_probes_out > 0) ||
		    (icsk->icsk_user_timeout == 0 &&
		    icsk->icsk_probes_out >= keepalive_probes(tp))) {
			/* 发送一个RST数据包 */
			tcp_send_active_reset(sk, GFP_ATOMIC);

			/* 报告错误，关闭连接。 */
			tcp_write_err(sk);
			goto out;
		}

		/* 如果还不到关闭连接的时候，就继续发送保活探测包 */
		if (tcp_write_wakeup(sk, LINUX_MIB_TCPKEEPALIVE) <= 0) {
			icsk->icsk_probes_out++;
			/* 获取tcp_keepalive_intvl。keepalive探测包的发送间隔，tcp_keepalive_intvl为75s。*/
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		/* 如果连接的空闲时间还没有超过设定值，就继续等待。 */
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	sk_mem_reclaim(sk);

resched:
	inet_csk_reset_keepalive_timer (sk, elapsed);
	goto out;

death:
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static enum hrtimer_restart tcp_compressed_ack_kick(struct hrtimer *timer)
{
	struct tcp_sock *tp = container_of(timer, struct tcp_sock, compressed_ack_timer);
	struct sock *sk = (struct sock *)tp;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		if (tp->compressed_ack > TCP_FASTRETRANS_THRESH)
			tcp_send_ack(sk);
	} else {
		if (!test_and_set_bit(TCP_DELACK_TIMER_DEFERRED,
				      &sk->sk_tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);

	sock_put(sk);

	return HRTIMER_NORESTART;
}

/* tcp socket定时器的初始化函数。初始化三个定时器： 重传定时器，延时ack定时器，保活定时器 */
void tcp_init_xmit_timers(struct sock *sk)
{
	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer,
				  &tcp_keepalive_timer);


	hrtimer_init(&tcp_sk(sk)->pacing_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED_SOFT);
	tcp_sk(sk)->pacing_timer.function = tcp_pace_kick;

	hrtimer_init(&tcp_sk(sk)->compressed_ack_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL_PINNED_SOFT);
	tcp_sk(sk)->compressed_ack_timer.function = tcp_compressed_ack_kick;
}
