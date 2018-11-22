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
 * 具体地，在每个发送和相应的ACK之间的间隔中，估计器生成传送速率样本。通常，
 * 它使用确认数据包的速率。然而，仅使用确认率的方法在普遍的ACK抽取或压缩下面临挑战：
 * 分组可以暂时看起来比瓶颈率更快地传递。由于在物理上不可能以持续的方式做到这一点，
 * 当估计器注意到ACK速率快于传输速率时，它使用后者：
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
 * 
 * 请注意，当发送或接收受到应用程序或接收器窗口限制等其他因素的限制时，
 * 估计器基本上估计了良好输出，而不是网络瓶颈链路速率。估计器故意避免使用分组间间隔方法，
 * 因为该方法需要大量样本和复杂的滤波。 
 * 
 * TCP流通常在请求/响应工作负载中受应用程序限制。如果当写入队列没有准备好发送的数据，
 * 而在数据包的采样窗口期间仍有有一些间隙，估计器将带宽样本标记为应用程序限制。
 */

/* Snapshot the current delivery information in the skb, to generate
 * a rate sample later when the skb is (s)acked in tcp_rate_skb_delivered().
 */
// 每次发送一个tcp seg只要成功了，都会调用该函数，来记录发包时间
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

	// 一般而言，我们需要从收到最新ACK的时间开始交付率样本，以确保我们包含网络传输所有正在进行的数据包所需的全部时间。
	// 如果还没有正在传输的数据包，那么我们知道现在之后的任何ACK都表明网络能够在现在和下一个ACK之间的采样间隔内完全传送这些数据包。
	// 请注意，我们使用packets_out而不是tcp_packets_in_flight（tp），因为后者是基于RTO和丢失标记启发式的猜测。
	// 我们不希望虚假的RTO或丢失标记导致虚假的小时间间隔，从而导致虚假的高带宽估计。
	 
	if (!tp->packets_out) {
		// 第一个包，我们更新tp上的记录，
		// 后面会在收到ack后再次更新，不然就不更新
		tp->first_tx_mstamp  = skb->skb_mstamp;
		tp->delivered_mstamp = skb->skb_mstamp;
	}

	TCP_SKB_CB(skb)->tx.first_tx_mstamp	= tp->first_tx_mstamp;
	// tp->delivered_mstamp 是每次收到ack后，记录的交付时间戳，
	// 所以 tx.delivered_mstamp 也是记录的交付的时间戳
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
// 当传入的参数skb被ack时，会调用 tcp_clean_rtx_queue 调用 tcp_rate_skb_delivered，
// 我们在最后一次传输skb时用（先前）传递信息填写速率样本。
// 如果ACK确认多个skbs（例如，拉伸的ack），则多次调用该函数。
// 我们赞成来自最近发送的skb的信息，即具有最高previous_delivered计数的skb。
// https://blog.csdn.net/qq_40894952/article/details/80626423
void tcp_rate_skb_delivered(struct sock *sk, struct sk_buff *skb,
			    struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

	if (!scb->tx.delivered_mstamp)
		return;

	if (!rs->prior_delivered ||
	    after(scb->tx.delivered, rs->prior_delivered)) {
		rs->prior_delivered  = scb->tx.delivered;
		rs->prior_mstamp     = scb->tx.delivered_mstamp;
		rs->is_app_limited   = scb->tx.is_app_limited;
		rs->is_retrans	     = scb->sacked & TCPCB_RETRANS;

		/* Find the duration of the "send phase" of this window: */
		// 计算在这个窗口內发送阶段的时间段
		rs->interval_us      = tcp_stamp_us_delta(
						skb->skb_mstamp, 			// 当前ack报文接收的时间
						scb->tx.first_tx_mstamp);   // 第一个报文发送的时间

		/* Record send time of most recently ACKed packet: */
		tp->first_tx_mstamp  = skb->skb_mstamp;
	}
	/* Mark off the skb delivered once it's sacked to avoid being
	 * used again when it's cumulatively acked. For acked packets
	 * we don't need to reset since it'll be freed soon.
	 */
	// 一旦它被sacked就标记skb的delivered_mstamp=0，以避免在acked的时候再次使用它。
	// 对于acked数据包，我们不需要重置，因为它很快就会被释放。
	if (scb->sacked & TCPCB_SACKED_ACKED)
		scb->tx.delivered_mstamp = 0;
}

/* Update the connection delivery information and generate a rate sample. */
void tcp_rate_gen(struct sock *sk, u32 delivered, u32 lost,
		  bool is_sack_reneg, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 snd_us, ack_us;

	/* Clear app limited if bubble is acked and gone. */
	/* 清除应用程序有限，如果间隙已经消失了 */
	if (tp->app_limited && after(tp->delivered, tp->app_limited))
		tp->app_limited = 0;

	/* TODO: there are multiple places throughout tcp_ack() to get
	 * current time. Refactor the code using a new "tcp_acktag_state"
	 * to carry current time, flags, stats like "tcp_sacktag_state".
	 */
	/* TODO：整个 tcp_ack() 有多个位置来获取当前时间。
	使用新的“tcp_acktag_state”重构代码以携带当前时间，
	标志，统计信息，如“tcp_sacktag_state”。
    */
	if (delivered)
		tp->delivered_mstamp = tp->tcp_mstamp;

	rs->acked_sacked = delivered;	/* freshly ACKed or SACKed */
	rs->losses = lost;		/* freshly marked lost */
	/* Return an invalid sample if no timing information is available or
	 * in recovery from loss with SACK reneging. Rate samples taken during
	 * a SACK reneging event may overestimate bw by including packets that
	 * were SACKed before the reneg.
	 */
	/* 如果没有可用的时间信息，则返回无效样本，或者在SACK reneging中从丢失中恢复。
	在SACK再现事件期间采集的速率样本可能通过包括在重新发生之前被SACK的数据包来高估bw。
	*/
	if (!rs->prior_mstamp || is_sack_reneg) {
		rs->delivered = -1;
		rs->interval_us = -1;
		return;
	}
	rs->delivered   = tp->delivered - rs->prior_delivered;

	/* Model sending data and receiving ACKs as separate pipeline phases
	 * for a window. Usually the ACK phase is longer, but with ACK
	 * compression the send phase can be longer. To be safe we use the
	 * longer phase.
	 */
	/* 模型发送数据和接收ACK作为窗口的单独管道阶段。通常ACK阶段较长，
	但通过ACK压缩，发送阶段可以更长。为了安全起见，我们使用较长的阶段。*/
	snd_us = rs->interval_us;				/* send phase */
	ack_us = tcp_stamp_us_delta(tp->tcp_mstamp, // 数据报最近发送或接收的时间
				    rs->prior_mstamp); /* ack phase */ // 上次交付的时间
	rs->interval_us = max(snd_us, ack_us);

	// 后面会根据这两个参数来计算bw
	// bw = (u64)rs->delivered * BW_UNIT;
	// do_div(bw, rs->interval_us);

	/* Normally we expect interval_us >= min-rtt.
	 * Note that rate may still be over-estimated when a spuriously
	 * retransmistted skb was first (s)acked because "interval_us"
	 * is under-estimated (up to an RTT). However continuously
	 * measuring the delivery rate during loss recovery is crucial
	 * for connections suffer heavy or prolonged losses.
	 */
	// 如果此示例受应用程序限制，则可能具有非常低的传递计数，表示应用程序行为而不是可用的网络速率。
	// 这样的样本可以拖累估计的bw，导致不必要的减速。因此，为了继续以最后测量的网络速率发送，
	// 我们过滤掉app限制的样本，除非他们描述路径bw至少和我们的bw模型一样。
	// 因此，在app限制阶段的目标是无论多长时间都以最佳网络速率进行。
	// 当应用写入速度超过网络提供的速度时，我们会自动退出此阶段:)
	if (unlikely(rs->interval_us < tcp_min_rtt(tp))) {
		if (!rs->is_retrans)
			pr_debug("tcp rate: %ld %d %u %u %u\n",
				 rs->interval_us, rs->delivered,
				 inet_csk(sk)->icsk_ca_state,
				 tp->rx_opt.sack_ok, tcp_min_rtt(tp));
		rs->interval_us = -1;
		return;
	}

	/* Record the last non-app-limited or the highest app-limited bw */
	if (!rs->is_app_limited ||
	    ((u64)rs->delivered * tp->rate_interval_us >=
	     (u64)tp->rate_delivered * rs->interval_us)) {
		tp->rate_delivered = rs->delivered;
		tp->rate_interval_us = rs->interval_us;
		tp->rate_app_limited = rs->is_app_limited;
	}
}

/* If a gap is detected between sends, mark the socket application-limited. */
// 如果在发送之间检测到间隙，请标记套接字应用程序限制。
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
