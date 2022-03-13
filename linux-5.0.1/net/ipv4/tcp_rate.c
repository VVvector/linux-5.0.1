#include <net/tcp.h>

/* The bandwidth estimator estimates the rate at which the network
 * can currently deliver outbound data packets for this flow. At a high
 * level, it operates by taking a delivery rate sample for each ACK.
 *
 * A rate sample records the rate at which the network delivered packets
 * for this flow, calculated over the time interval between the transmission
 * of a data packet and the acknowledgment of that packet.
 *
 * Specifically, over the interval between each transmit and corresponding ACK,
 * the estimator generates a delivery rate sample. Typically it uses the rate
 * at which packets were acknowledged. However, the approach of using only the
 * acknowledgment rate faces a challenge under the prevalent ACK decimation or
 * compression: packets can temporarily appear to be delivered much quicker
 * than the bottleneck rate. Since it is physically impossible to do that in a
 * sustained fashion, when the estimator notices that the ACK rate is faster
 * than the transmit rate, it uses the latter:
 *
 *    send_rate = #pkts_delivered/(last_snd_time - first_snd_time)
 *    ack_rate  = #pkts_delivered/(last_ack_time - first_ack_time)
 *    bw = min(send_rate, ack_rate)
 *
 * Notice the estimator essentially estimates the goodput, not always the
 * network bottleneck link rate when the sending or receiving is limited by
 * other factors like applications or receiver window limits.  The estimator
 * deliberately avoids using the inter-packet spacing approach because that
 * approach requires a large number of samples and sophisticated filtering.
 *
 * TCP flows can often be application-limited in request/response workloads.
 * The estimator marks a bandwidth sample as application-limited if there
 * was some moment during the sampled window of packets when there was no data
 * ready to send in the write queue.
 */

/*
 * https://blog.csdn.net/sinat_20184565/article/details/106109415
 * 如上面的公式：
 * 带宽取值为计算得出的数据传输速率和接收ACK速率两者之间的较小值。通常情况下，传输速率(send_rate--发送
 * 并得到确认的数据速率)将大于ACK接收的速率(ack rate)，但是，当面对ACK压缩等情况下，将导致ACK接收速率
 * 意外地增大，此时，带宽应选取传输速率(send_rate)
 */


/* Snapshot the current delivery information in the skb, to generate
 * a rate sample later when the skb is (s)acked in tcp_rate_skb_delivered().
 */
/*
 * tcp_rate_skb_sent()记录下发送的skb相关信息，之后，当接收到ACK/SACK确认报文时，根据这些信息生成速率采样。
 * 首先，看一下采样周期，当packets_out为0时，表明网络中没有报文，所有发送的报文都已经被确认，从这一刻起，
 * 是合适的时间点，记录之后报文的发送时间，在接收到相应的ack报文后，计算报文在网络中的传播时间，即要采样的间隔。
 * 反之，当packets_out不为空，将套接字之前的记录值赋予发送报文结构中，函数tcp_rate_check_app_limited用于检测是
 * 否由于应用发送的数据不足，导致的发送受限，稍后介绍。注意这里的变量first_tx_mstamp和delivered_mstamp，
 * 二者记录了本次速率采用的起点，在同一个采样窗口内的后续发送报文中，保存相同的起点时间戳值。
 * 
 * tcp控制块中的tp->first_tx_mstamp保存发送速率采样周期的开始时间戳，用于后续计算发送速率。
 * TCP控制块中的tx.delivered保存当前套接口在发送此报文时，已经成功传输的报文数量。
 * TCP控制块中的tx.delivered_mstamp记录了成功发送tx.delivered报文时的时间戳，
 * 也即初始的确认tx.delivered数据的ACK报文到达的时间戳，随后用于计算ACK速率。
 * 
 *
 * 这里使用packets_out而不是tcp_packets_in_flight函数的结果，因为后者时基于RTO和丢失检测而得出的网络中的报文数量，
 * 过早的RTO的发生，以及激进的丢失检测，将导致采样间隔缩短，进而导致带宽估算过高。
 *
 * 1. 以上函数 tcp_rate_skb_sent() 在内核中有两处调用，分别是报文发送和重传函数。如下发送函数 __tcp_transmit_skb() 中，
 * 	报文成功发送之后，调用tcp_rate_skb_sent函数，更新速率信息。但是，对于ACK报文等，这里oskb为空，不处理。
 * 2. 多数情况下，报文重传函数调用 tcp_retransmit_skb() 进行报文发送，其内部封装了以上的发送函数。
 *	但是，如果skb的数据缓存出现对其问题，或者校验的起始位置太靠后的话，虽然也是使用tcp_transmit_skb() 发送报文，
 *	但是，不在其内部更新报文速率信息，而是在这里进行更新，调用 tcp_rate_skb_sent() 函数。
 */
void tcp_rate_skb_sent(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	 /* In general we need to start delivery rate samples from the
	  * time we received the most recent ACK, to ensure we include
	  * the full time the network needs to deliver all in-flight
	  * packets. If there are no packets in flight yet, then we
	  * know that any ACKs after now indicate that the network was
	  * able to deliver those packets completely in the sampling
	  * interval between now and the next ACK.
	  *
	  * Note that we use packets_out instead of tcp_packets_in_flight(tp)
	  * because the latter is a guess based on RTO and loss-marking
	  * heuristics. We don't want spurious RTOs or loss markings to cause
	  * a spuriously small time interval, causing a spuriously high
	  * bandwidth estimate.
	  */
	if (!tp->packets_out) {
		u64 tstamp_us = tcp_skb_timestamp_us(skb);

		tp->first_tx_mstamp  = tstamp_us;
		tp->delivered_mstamp = tstamp_us;
	}

	TCP_SKB_CB(skb)->tx.first_tx_mstamp	= tp->first_tx_mstamp;
	TCP_SKB_CB(skb)->tx.delivered_mstamp	= tp->delivered_mstamp;
	TCP_SKB_CB(skb)->tx.delivered		= tp->delivered;
	TCP_SKB_CB(skb)->tx.is_app_limited	= tp->app_limited ? 1 : 0;
}

/* When an skb is sacked or acked, we fill in the rate sample with the (prior)
 * delivery information when the skb was last transmitted.
 *
 * If an ACK (s)acks multiple skbs (e.g., stretched-acks), this function is
 * called multiple times. We favor the information from the most recently
 * sent skb, i.e., the skb with the highest prior_delivered count.
 */
/*
 * 报文传输时长
 * 函数 tcp_rate_skb_delivered() 用于计算报文的传输时间，当接收到ACK报文时，调用此函数进行处理。
 * 如果delivered_mstamp为空，表明此报文发送时没有记录时间戳，不进行处理。
 *
 * 函数 tcp_rate_skb_delivered() 在SACK的处理和ACK确认报文的处理中都由调用，首先看一下在SACK处理过程中的使用。
 * 函数 tcp_sacktag_walk() 遍历skb开始的重传队列，如果判断队列中的某个skb的数据位于SACK序号块之内（tcp_match_skb_to_sack），
 * 即SACK确认了此报文，调用以上函数tcp_rate_skb_delivered() 进行处理。
 * 另外，如果in_sack小于等于零，表明SACK没有完全包含当前SKB的数据，由函数tcp_shift_skb_data() 处理部分交叉的情况。
 *
 * 对于部分数据被确认的skb，使用函数 tcp_shifted_skb() 将此部分数据分离出来，尝试与之前已经被SACK确认的报文进行合并。
 * 虽然只有部分数据被确认，也表明此报文完成了传输，使用其更新速率信息（见函数tcp_rate_skb_delivered）。
 *
 * 最后，看一下ACK报文相关的速率处理，参见以下函数 tcp_clean_rtx_queue()，无论报文是完全被确认，还是部分确认，
 * 都使用函数 tcp_rate_skb_delivered() 更新速率信息。fully_acked在之后进行。
 */
void tcp_rate_skb_delivered(struct sock *sk, struct sk_buff *skb,
			    struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

	if (!scb->tx.delivered_mstamp)
		return;

	/*
	 * 对于确认多个skb的ACK报文（Stretched-Acks），此函数将被调用多次（每个确认报文调用一次），
	 * 这里使用这些确认报文中最近发送的报文的时间信息，即tx.delivered时间较大的报文，
	 * 使用其信息生成速率采样rate_sample。
	 * 并且，使用此报文的时间戳，更新套接口first_tx_mstamp时间戳变量，开始新的发送速率采样窗口。
	 * 随后，计算此时结束的上一个发送速率采样阶段的长度，即最近确认的报文的发送时间戳，
	 * 减去最早发送的报文的时间戳（采样周期的开始时间），得到发送阶段的时长。
	 */
	if (!rs->prior_delivered ||
	    after(scb->tx.delivered, rs->prior_delivered)) {
		rs->prior_delivered  = scb->tx.delivered;
		rs->prior_mstamp     = scb->tx.delivered_mstamp;
		rs->is_app_limited   = scb->tx.is_app_limited;
		rs->is_retrans	     = scb->sacked & TCPCB_RETRANS;

		/* Record send time of most recently ACKed packet: */
		tp->first_tx_mstamp  = tcp_skb_timestamp_us(skb);
		/* Find the duration of the "send phase" of this window: */
		rs->interval_us = tcp_stamp_us_delta(tp->first_tx_mstamp,
						     scb->tx.first_tx_mstamp);

	}

	/*
	 * 最后，如果报文被SACK所确认，清空其tx.delivered_mstamp时间戳。反之，在之后接收到ACK确认时，
	 * 再次使用此报文信息计算速率。参见本函数tcp_rate_skb_delivered开头，delivered_mstamp为零的报文，不参与处理。
	 */
	/* Mark off the skb delivered once it's sacked to avoid being
	 * used again when it's cumulatively acked. For acked packets
	 * we don't need to reset since it'll be freed soon.
	 */
	if (scb->sacked & TCPCB_SACKED_ACKED)
		scb->tx.delivered_mstamp = 0;
}

/* 生成速率样本
 * 以上的函数SACK和ACK报文处理函数都是在 tcp_ack() 函数中调用，在tcp_ack函数最后，
 * 调用 tcp_rate_gen() 生成速率样本。在此之前，由函数 tcp_newly_delivered() 计算ACK报文确认的报文数量。
 * 函数 tcp_rate_gen() 的第三个参数lost表示新推倒出来的丢失报文数量（进行了标记）。
 * 
 * 函数tcp_ack的最后，调用拥塞控制函数tcp_cong_control()，目前只有BBR拥塞算法在使用速率样本。
 *
 * 如下速率样本生成函数 tcp_rate_gen() ，在发送报文数量超过应用程序限制点时，清零app_limited。
 * 之后，保存本次确认（ACK & SACK）报文数量到速率样本结构rate_sample中，保存新评估的丢失报文数量。
 * 如果delivered有值，表明ACK报文确认了新的数据，更新确认数据的时间戳为当前时间。
 *
/* Update the connection delivery information and generate a rate sample. */
void tcp_rate_gen(struct sock *sk, u32 delivered, u32 lost,
		  bool is_sack_reneg, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 snd_us, ack_us;

	/*
	 * 在以上tcp_rate_gen函数中，如果delivered的值已经超过记录的app_limited值，将其清零。
	 */
	/* Clear app limited if bubble is acked and gone. */
	if (tp->app_limited && after(tp->delivered, tp->app_limited))
		tp->app_limited = 0;

	/* TODO: there are multiple places throughout tcp_ack() to get
	 * current time. Refactor the code using a new "tcp_acktag_state"
	 * to carry current time, flags, stats like "tcp_sacktag_state".
	 */
	if (delivered)
		tp->delivered_mstamp = tp->tcp_mstamp;

	rs->acked_sacked = delivered;	/* freshly ACKed or SACKed */
	rs->losses = lost;		/* freshly marked lost */

	/*
	 * 如果没有记录报文确认时的时间戳，或者接收端删除了接收到的乱序报文，返回一个无效的速率样本。
	 * 对于后一种情况，计算带宽时，会包含进了接收端删除的乱序报文，将导致对带宽的高估，这里选择返回无效速率样本。
	 * 需要注意的是，速率样本rate_sample结构的acked_sacked变量保存了本次接收的ACK报文新确认（S/ACK）的报文；
	 * 而另一个变量rs->delivered保存的本次采样周期内确认的报文数量。
	 */
	/* Return an invalid sample if no timing information is available or
	 * in recovery from loss with SACK reneging. Rate samples taken during
	 * a SACK reneging event may overestimate bw by including packets that
	 * were SACKed before the reneg.
	 */
	if (!rs->prior_mstamp || is_sack_reneg) {
		rs->delivered = -1;
		rs->interval_us = -1;
		return;
	}
	rs->delivered   = tp->delivered - rs->prior_delivered;

	/*
	 * 通常情况，对于一个发送窗口期，ACK接收的时长大于数据发送的时长，正如开始所述，
	 * 这导致计算的ACK接收速率小于数据发送速率。但是考虑到ACK压缩的情况，
	 * 安全的选择是将interval_us设置为两个时间段之间的较大值。
	 */
	/* Model sending data and receiving ACKs as separate pipeline phases
	 * for a window. Usually the ACK phase is longer, but with ACK
	 * compression the send phase can be longer. To be safe we use the
	 * longer phase.
	 */
	snd_us = rs->interval_us;				/* send phase */
	ack_us = tcp_stamp_us_delta(tp->tcp_mstamp,
				    rs->prior_mstamp); /* ack phase */
	rs->interval_us = max(snd_us, ack_us);

	/* Record both segment send and ack receive intervals */
	rs->snd_interval_us = snd_us;
	rs->rcv_interval_us = ack_us;

	/*
	 * 如果interval_us小于RTT的最小值，很有可能带宽会估算过高，将其设置为无效值。
	 */
	/* Normally we expect interval_us >= min-rtt.
	 * Note that rate may still be over-estimated when a spuriously
	 * retransmistted skb was first (s)acked because "interval_us"
	 * is under-estimated (up to an RTT). However continuously
	 * measuring the delivery rate during loss recovery is crucial
	 * for connections suffer heavy or prolonged losses.
	 */
	if (unlikely(rs->interval_us < tcp_min_rtt(tp))) {
		if (!rs->is_retrans)
			pr_debug("tcp rate: %ld %d %u %u %u\n",
				 rs->interval_us, rs->delivered,
				 inet_csk(sk)->icsk_ca_state,
				 tp->rx_opt.sack_ok, tcp_min_rtt(tp));
		rs->interval_us = -1;
		return;
	}

	/*
	 * 如果app_limited为空，记录的速率为应用程序不限制的速率。否则，app_limited有值，
	 * 如果当前的速率大于记录的速率（rate_delivered/rate_interval_us），进行速率更新。
	 */
	/* Record the last non-app-limited or the highest app-limited bw */
	if (!rs->is_app_limited ||
	    ((u64)rs->delivered * tp->rate_interval_us >=
	     (u64)tp->rate_delivered * rs->interval_us)) {
		tp->rate_delivered = rs->delivered;
		tp->rate_interval_us = rs->interval_us;
		tp->rate_app_limited = rs->is_app_limited;
	}
}

/*
 * 应用层限制：
 * 如下函数 tcp_rate_check_app_limited() ，如果套接口发送缓存中的数据长度小于MSS值； 并且，
 * 本机Qdisc队列/网卡发送队列中没有数据（小于数据长度为1的SKB所占用的空间）； 并且，
 * 发送到网络中的报文数量小于拥塞窗口（并非拥塞窗口限制了报文发送）； 并且，所有丢失报文都已经被重传，
 * 当满足以上的所有条件时，认为套接口的发送受限于应用程序。
 * 
 * 如果确认报文数量与网络中报文数量之和大于零，将结果赋予变量app_limited，否则app_limited赋值为一。
 * 可见，app_limited一方面表示数据发送是否收到了应用层的限制，另一方面，其表示受限发生时的发送的报文数量。
 *
 * 检查函数的调用发生在TCP与应用层接口的报文发送函数中，如下 tcp_sendpage_locked() 和 tcp_sendmsg_locked() 函数。
 */
 */
/* If a gap is detected between sends, mark the socket application-limited. */
void tcp_rate_check_app_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (/* We have less than one packet to send. */
	    tp->write_seq - tp->snd_nxt < tp->mss_cache &&
	    /* Nothing in sending host's qdisc queues or NIC tx queue. */
	    sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) &&
	    /* We are not limited by CWND. */
	    tcp_packets_in_flight(tp) < tp->snd_cwnd &&
	    /* All lost packets have been retransmitted. */
	    tp->lost_out <= tp->retrans_out)
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
}
EXPORT_SYMBOL_GPL(tcp_rate_check_app_limited);
