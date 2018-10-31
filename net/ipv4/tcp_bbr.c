/* Bottleneck Bandwidth and RTT (BBR) congestion control
 *
 * BBR congestion control computes the sending rate based on the delivery
 * rate (throughput) estimated from ACKs. In a nutshell:
 *
 *   On each ACK, update our model of the network path:
 *      bottleneck_bandwidth = windowed_max(delivered / elapsed, 10 round trips)
 *      min_rtt = windowed_min(rtt, 10 seconds)
 *   pacing_rate = pacing_gain * bottleneck_bandwidth
 *   cwnd = max(cwnd_gain * bottleneck_bandwidth * min_rtt, 4)
 *
 * The core algorithm does not react directly to packet losses or delays,
 * although BBR may adjust the size of next send per ACK when loss is
 * observed, or adjust the sending rate if it estimates there is a
 * traffic policer, in order to keep the drop rate reasonable.
 *
 * Here is a state transition diagram for BBR:
 *
 *             |
 *             V
 *    +---> STARTUP  ----+
 *    |        |         |
 *    |        V         |
 *    |      DRAIN   ----+
 *    |        |         |
 *    |        V         |
 *    +---> PROBE_BW ----+
 *    |      ^    |      |
 *    |      |    |      |
 *    |      +----+      |
 *    |                  |
 *    +---- PROBE_RTT <--+
 *
 * A BBR flow starts in STARTUP, and ramps up its sending rate quickly.
 * When it estimates the pipe is full, it enters DRAIN to drain the queue.
 * In steady state a BBR flow only uses PROBE_BW and PROBE_RTT.
 * A long-lived BBR flow spends the vast majority of its time remaining
 * (repeatedly) in PROBE_BW, fully probing and utilizing the pipe's bandwidth
 * in a fair manner, with a small, bounded queue. *If* a flow has been
 * continuously sending for the entire min_rtt window, and hasn't seen an RTT
 * sample that matches or decreases its min_rtt estimate for 10 seconds, then
 * it briefly enters PROBE_RTT to cut inflight to a minimum value to re-probe
 * the path's two-way propagation delay (min_rtt). When exiting PROBE_RTT, if
 * we estimated that we reached the full bw of the pipe then we enter PROBE_BW;
 * otherwise we enter STARTUP to try to fill the pipe.
 *
 * BBR is described in detail in:
 *   "BBR: Congestion-Based Congestion Control",
 *   Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh,
 *   Van Jacobson. ACM Queue, Vol. 14 No. 5, September-October 2016.
 *
 * There is a public e-mail list for discussing BBR development and testing:
 *   https://groups.google.com/forum/#!forum/bbr-dev
 *
 * NOTE: BBR might be used with the fq qdisc ("man tc-fq") with pacing enabled,
 * otherwise TCP stack falls back to an internal pacing using one high
 * resolution timer per TCP socket and may use more resources.
 */
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
// 发送速度的最小精度 (1500 bytes / 1 usec / 2^24) ~= 715 bps = 1500*8*1000*1000/2^24
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	BBR_DRAIN,	/* drain any queue created during startup */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
};

/* BBR congestion control block */
struct bbr {
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	u64	cycle_mstamp;	     /* time of this cycle phase start */
	u32     mode:3,		     /* current bbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		packet_conservation:1,  /* use packet conservation? */
		restore_cwnd:1,	     /* decided to revert cwnd to old value */
		round_start:1,	     /* start of packet-timed tx->ack round? */
		idle_restart:1,	     /* restarting after idle? */
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
		unused:12,
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
	u32	pacing_gain:10,	/* current gain for setting pacing rate */
		cwnd_gain:10,	/* current gain for setting cwnd */
		full_bw_reached:1,   /* reached full bw in Startup? */
		full_bw_cnt:2,	/* number of rounds without large bw gains */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
		has_seen_rtt:1, /* have we seen an RTT sample yet? */
		unused_b:5;
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */
};

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2;
/* Window length of min_rtt filter (in sec): */
static const u32 bbr_min_rtt_win_sec = 10;
/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
static const u32 bbr_probe_rtt_mode_ms = 200;
/* Skip TSO below the following bandwidth (bits/sec): */
static const int bbr_min_tso_rate = 1200000;

/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;
/* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round:
 */
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
static const int bbr_cwnd_gain  = BBR_UNIT * 2;
/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
static const int bbr_pacing_gain[] = {
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};
/* Randomize the starting gain cycling phase over N phases: */
static const u32 bbr_cycle_rand = 7;

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 bbr_cwnd_min_target = 4;

/* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
/* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
static const u32 bbr_full_bw_cnt = 3;

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
static const u32 bbr_lt_intvl_min_rtts = 4;
/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
static const u32 bbr_lt_loss_thresh = 50;
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
static const u32 bbr_lt_bw_diff = 4000 / 8;
/* If we estimate we're policed, use lt_bw for this many round trips: */
static const u32 bbr_lt_bw_max_rtts = 48;

/* Do we estimate that STARTUP filled the pipe? */
// 是否评估过管道的最大bw
static bool bbr_full_bw_reached(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return bbr->full_bw_reached;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
// 获取最近的bw
static u32 bbr_max_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return minmax_get(&bbr->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
static u32 bbr_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	// 如果有lt_use_bw标志位，则使用lt_bw， 没有则从bbr bw
	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
// 根据gain增益来计算rate
static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	// tcp_mss_to_mtu 拿到mtu
	// rate = bw * mtu * gain * 1<<8 * 1000000L / 1<<24
	rate *= tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);
	rate *= gain;
	rate >>= BBR_SCALE;
	// #define USEC_PER_SEC	1000000L
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}

/* Convert a BBR bw and gain factor to a pacing rate in bytes per second. */
// 根据bw和gain来计算数据的速率，bytes/sec
static u32 bbr_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	u64 rate = bw;

	rate = bbr_rate_bytes_per_sec(sk, rate, gain);
	// 比较rate和sk_max_pacing_rate，取其中小的
	// 也就是最大的rate不能超过sk_max_pacing_rate
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}

/* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
// 初始化pacing_rate
static void bbr_init_pacing_rate_from_rtt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;
	u32 rtt_us;

	// srtt /* smoothed round trip time << 3 in usecs */
	if (tp->srtt_us) {		/* any RTT sample yet? */ 
		// 如果有srtt，取rtt_us/8。并且标志has_seen_rtt
		rtt_us = max(tp->srtt_us >> 3, 1U);
		bbr->has_seen_rtt = 1;
	} else {			 /* no RTT sample yet */
		// 如果没有srtt，使用默认的rtt
		// #define USEC_PER_MSEC	1000L
		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT */
	}
	// 计算bw，而且直接用snd_cwnd来计算
	bw = (u64)tp->snd_cwnd * BW_UNIT;
	do_div(bw, rtt_us);
	// 根据bw计算pacing_rate
	sk->sk_pacing_rate = bbr_bw_to_pacing_rate(sk, bw, bbr_high_gain);
}

/* Pace using current bw estimate and a gain factor. In order to help drive the
 * network toward lower queues while maintaining high utilization and low
 * latency, the average pacing rate aims to be slightly (~1%) lower than the
 * estimated bandwidth. This is an important aspect of the design. In this
 * implementation this slightly lower pacing rate is achieved implicitly by not
 * including link-layer headers in the packet size used for the pacing rate.
 */
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 rate = bbr_bw_to_pacing_rate(sk, bw, gain);
// likely(x)等价于x，即if(likely(x))等价于if(x)，但是它告诉gcc，x取1的可能性比较大。
// unlikely(x)等价于x，即if(unlikely(x))等价于if(x)，但是它告诉gcc，x取0的可能性比较大。

	// 如果没有rtt而且有srtt_us，初始化pacing_rate
	if (unlikely(!bbr->has_seen_rtt && tp->srtt_us))
		bbr_init_pacing_rate_from_rtt(sk);
	// 如果评估过最大bw 或者 rate比sk的rate大，那么将sk的rate设置为rate
	if (bbr_full_bw_reached(sk) || rate > sk->sk_pacing_rate)
		sk->sk_pacing_rate = rate;
}

/* override sysctl_tcp_min_tso_segs */
static u32 bbr_min_tso_segs(struct sock *sk)
{
	return sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
}

static u32 bbr_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 segs, bytes;

	/* Sort of tcp_tso_autosize() but ignoring
	 * driver provided sk_gso_max_size.
	 */
	bytes = min_t(u32, sk->sk_pacing_rate >> sk->sk_pacing_shift,
		      GSO_MAX_SIZE - 1 - MAX_TCP_HEADER);
	segs = max_t(u32, bytes / tp->mss_cache, bbr_min_tso_segs(sk));

	return min(segs, 0x7FU);
}

/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
static void bbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = tp->snd_cwnd;  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		bbr->prior_cwnd = max(bbr->prior_cwnd, tp->snd_cwnd);
}

// 由Linux tcp_ca_event 调用
static void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (event == CA_EVENT_TX_START && tp->app_limited) {
		bbr->idle_restart = 1;
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		if (bbr->mode == BBR_PROBE_BW)
			bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
	}
}

/* Find target cwnd. Right-size the cwnd based on min RTT and the
 * estimated bottleneck bandwidth:
 *
 * cwnd = bw * min_rtt * gain = BDP * gain
 *
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause BBR to under-estimate the rate.
 *
 * To achieve full performance in high-speed paths, we budget enough cwnd to
 * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
 *   - one skb in sending host Qdisc,
 *   - one skb in sending host TSO/GSO engine
 *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
 * Don't worry, at low rates (bbr_min_tso_rate) this won't bloat cwnd because
 * in such cases tso_segs_goal is 1. The minimum cwnd is 4 packets,
 * which allows 2 outstanding 2-packet sequences, to try to keep pipe
 * full even with ACK-every-other-packet delayed ACKs.
 */

//根据 cwnd = bw * min_rtt * gain = BDP * gain来计算cwnd
static u32 bbr_target_cwnd(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd;
	u64 w;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
	 */
	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return TCP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

	w = (u64)bw * bbr->min_rtt_us;

	/* Apply a gain to the given value, then remove the BW_SCALE shift. */
	cwnd = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	cwnd += 3 * bbr_tso_segs_goal(sk);

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	// TODO: 没明白什么意思
	cwnd = (cwnd + 1) & ~1U;

	return cwnd;
}

/* An optimization in BBR to reduce losses: On the first round of recovery, we
 * follow the packet conservation principle: send P packets per P packets acked.
 * After that, we slow-start and send at most 2*P packets per P packets acked.
 * After recovery finishes, or upon undo, we restore the cwnd we had when
 * recovery started (capped by the target cwnd based on estimated BDP).
 *
 * TODO(ycheng/ncardwell): implement a rate-based approach.
 */
static bool bbr_set_cwnd_to_recover_or_restore(
	struct sock *sk, const struct rate_sample *rs, u32 acked, u32 *new_cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u8 prev_state = bbr->prev_ca_state;
	u8 state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tp->snd_cwnd;

	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
	 */
	// 如果有丢包，cwnd减去丢报数
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	// 如果cwnd减少而且上一次的状态不是TCP_CA_Recovery
	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		// 第一次进行recovery
		bbr->packet_conservation = 1;
		bbr->next_rtt_delivered = tp->delivered;  /* start round now */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		// 设置cwnd= in_flight + acked
		cwnd = tcp_packets_in_flight(tp) + acked;
	// 如果上一次的状态是TCP_CA_Recovery状态 而且 tcp的状态小于TCP_CA_Recovery
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		// 当前已经退出拥塞状态，告诉bbr
		bbr->restore_cwnd = 1;
		bbr->packet_conservation = 0;
	}

	// prev_ca_state 表示上一次的状态，在这里记录tcp上次的拥塞状态
	bbr->prev_ca_state = state;

	// 如果退出了拥塞状态，将恢复cwnd为上次保存的cwnd
	if (bbr->restore_cwnd) {
		/* Restore cwnd after exiting loss recovery or PROBE_RTT. */
		cwnd = max(cwnd, bbr->prior_cwnd);
		bbr->restore_cwnd = 0;
	}
	// 如果进入了拥塞状态，重新根据in_flight来计算cwnd
	if (bbr->packet_conservation) {
		*new_cwnd = max(cwnd, tcp_packets_in_flight(tp) + acked);
		return true;	/* yes, using packet conservation */
	}
	*new_cwnd = cwnd;
	return false;
}

/* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
 * has drawn us down below target), or snap down to target if we're above it.
 */
// 根据参数设置最终的cwnd
static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd = 0, target_cwnd = 0;

	// 如果没有任何一个ack回来，直接返回
	if (!acked)
		return;

	// 根据tcp拥塞状态，且设置cwnd
	// 如果是刚好进入拥塞状态，直接到done
	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;

	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
	// 如果这时候的cwnd还没有进入拥塞，那么说明cwnd还不够大，我们慢慢增大cwnd
	target_cwnd = bbr_target_cwnd(sk, bw, gain);
	// 如果我们已经拿到了最大bw，需要减少cwnd
	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
		cwnd = min(cwnd + acked, target_cwnd);
	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND)
		cwnd = cwnd + acked;
	cwnd = max(cwnd, bbr_cwnd_min_target);

done:
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);	/* apply global cap */
	// 如果是探测RTT模式，则直接将sndwnd设置为4，也就是最小窗口
	if (bbr->mode == BBR_PROBE_RTT)  /* drain queue, refresh min_rtt */
		tp->snd_cwnd = min(tp->snd_cwnd, bbr_cwnd_min_target);
}

/* End cycle phase if it's time and/or we hit the phase's in-flight target. */
// 判断一个循环是否结束
static bool bbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	// 已经经过了一个轮回时间
	bool is_full_length =
		tcp_stamp_us_delta(tp->delivered_mstamp, bbr->cycle_mstamp) >
		bbr->min_rtt_us;
	u32 inflight, bw;

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	if (bbr->pacing_gain == BBR_UNIT)
		return is_full_length;		/* just use wall clock time */

	inflight = rs->prior_in_flight;  /* what was in-flight before ACK? */
	bw = bbr_max_bw(sk);

	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
	 * small (e.g. on a LAN). We do not persist if packets are lost, since
	 * a path with small buffers may not hold that much.
	 */
	if (bbr->pacing_gain > BBR_UNIT)
		return is_full_length &&
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
			 inflight >= bbr_target_cwnd(sk, bw, bbr->pacing_gain));

	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	return is_full_length ||
		inflight <= bbr_target_cwnd(sk, bw, BBR_UNIT);
}

// 总共CYCLE_LEN=8，8个阶段
// bbr_advance_cycle_phase执行一次，cycle_idx+1
// 将 cycle_mstamp 的时间赋值为tcp发送数据包的时间
// pacing_gain，如果有lt_use_bw，则使用lt_use_bw，没有的话用bbr_pacing_gain
static void bbr_advance_cycle_phase(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1);
	bbr->cycle_mstamp = tp->delivered_mstamp;
	bbr->pacing_gain = bbr->lt_use_bw ? BBR_UNIT :
					    bbr_pacing_gain[bbr->cycle_idx];
}

/* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
static void bbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	// 如果mode是BBR_PROBE_BW， 且确实到了下个阶段
	if (bbr->mode == BBR_PROBE_BW && bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk);
}

// 设置bbr为startup模式，增益都用最高
static void bbr_reset_startup_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = bbr_high_gain;
	bbr->cwnd_gain	 = bbr_high_gain;
}

// 设置bbr为探测模式
static void bbr_reset_probe_bw_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_PROBE_BW;
	bbr->pacing_gain = BBR_UNIT;
	bbr->cwnd_gain = bbr_cwnd_gain;
	bbr->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(bbr_cycle_rand);
	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle */
}

// 如果没有拿到bw， 则启动startup 模式
// 如果已经拿到bw， 启动探测BW模式
static void bbr_reset_mode(struct sock *sk)
{
	if (!bbr_full_bw_reached(sk))
		bbr_reset_startup_mode(sk);
	else
		bbr_reset_probe_bw_mode(sk);
}

/* Start a new long-term sampling interval. */
// 重置长期的interval采样
static void bbr_reset_lt_bw_sampling_interval(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_last_stamp = div_u64(tp->delivered_mstamp, USEC_PER_MSEC);
	bbr->lt_last_delivered = tp->delivered;
	bbr->lt_last_lost = tp->lost;
	bbr->lt_rtt_cnt = 0;
}

/* Completely reset long-term bandwidth sampling. */
// lt是long-term的缩写，重置lt的标识位
static void bbr_reset_lt_bw_sampling(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_bw = 0;
	bbr->lt_use_bw = 0;
	bbr->lt_is_sampling = false;
	bbr_reset_lt_bw_sampling_interval(sk);
}

/* Long-term bw sampling interval is done. Estimate whether we're policed. */
static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 diff;

	// 如果上次的采样间隔有bw
	if (bbr->lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - bbr->lt_bw);
		// 如果上一次和当前的bw相差 1/8 之内
		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) ||
		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <=
		     bbr_lt_bw_diff)) {
			/* All criteria are met; estimate we're policed. */
			// 将当前和上次的bw平均
			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  /* avg 2 intvls */
			// 标记已经使用bw
			bbr->lt_use_bw = 1;
			// 不让发送速率增大了
			bbr->pacing_gain = BBR_UNIT;  /* try to avoid drops */
			// 重置rtt cnt
			bbr->lt_rtt_cnt = 0;
			return;
		}
	}
	// 第一次得到bw 或者 两次bw相差大于1/8
	bbr->lt_bw = bw;
	bbr_reset_lt_bw_sampling_interval(sk);
}

/* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
 * Traffic Policing", SIGCOMM 2016). BBR detects token-bucket policers and
 * explicitly models their policed rate, to reduce unnecessary losses. We
 * estimate that we're policed if we see 2 consecutive sampling intervals with
 * consistent throughput and high packet loss. If we think we're being policed,
 * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
 */
// 检测令牌桶策略，和评估bw
static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 lost, delivered;
	u64 bw;
	u32 t;

	// 第一次肯定没有使用，如果已经计算过bw了
	if (bbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		if (bbr->mode == BBR_PROBE_BW && bbr->round_start &&
		    ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
			bbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
		}
		return;
	}

	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */

	// lt_is_sampling表示正在进行长期采样
	if (!bbr->lt_is_sampling) {
		// 如果没有丢包了直接返回
		if (!rs->losses)
			return;
		bbr_reset_lt_bw_sampling_interval(sk);
		// 标志已采样
		bbr->lt_is_sampling = true;
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	if (rs->is_app_limited) {
		bbr_reset_lt_bw_sampling(sk);
		return;
	}

	if (bbr->round_start)
		bbr->lt_rtt_cnt++;	/* count round trips in this interval */
	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
		return;		/* sampling interval needs to be longer */
	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		bbr_reset_lt_bw_sampling(sk);  /* interval is too long */
		return;
	}

	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	// 如果没有丢包，直接返回，因为下面的计算都是需要丢包的
	if (!rs->losses)
		return;


	/* Calculate packets lost and delivered in sampling interval. */
	lost = tp->lost - bbr->lt_last_lost;
	delivered = tp->delivered - bbr->lt_last_delivered;
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	// 如果没有发送任何一个包 或者 loss rate超过bbr_lt_loss_thresh 直接返回
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/* Find average delivery rate in this sampling interval. */
	t = div_u64(tp->delivered_mstamp, USEC_PER_MSEC) - bbr->lt_last_stamp;
	// 如果采样的间隔不到1ms，也直接返回
	if ((s32)t < 1)
		return;		/* interval is less than one ms, so wait */
	/* Check if can multiply without overflow */
	// 如果采样间隔溢出了，重置采样标志
	if (t >= ~0U / USEC_PER_MSEC) {
		bbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
		return;
	}
	// 计算bw
	t *= USEC_PER_MSEC;
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	// 
	bbr_lt_bw_interval_done(sk, bw);
}

/* Estimate the bandwidth based on how fast packets are delivered */
// 评估带宽有多大
static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;

	bbr->round_start = 0;
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	// 已经发送的数据，并且有rtt
	if (!before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		bbr->next_rtt_delivered = tp->delivered;
		bbr->rtt_cnt++;
		bbr->round_start = 1;
		bbr->packet_conservation = 0;
	}

	bbr_lt_bw_sampling(sk, rs);

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 */
	// bw=delivered/interval 计算出bw
	// 比如 delivered = 100， interval_us = 10， bw=100 * (1<<24) / 10 = 167772160 
	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);

	/* If this sample is application-limited, it is likely to have a very
	 * low delivered count that represents application behavior rather than
	 * the available network rate. Such a sample could drag down estimated
	 * bw, causing needless slow-down. Thus, to continue to send at the
	 * last measured network rate, we filter out app-limited samples unless
	 * they describe the path bw at least as well as our bw model.
	 *
	 * So the goal during app-limited phase is to proceed with the best
	 * network rate no matter how long. We automatically leave this
	 * phase when app writes faster than the network can deliver :)
	 */
	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
		/* Incorporate new sample into our max bw filter. */
		minmax_running_max(&bbr->bw, bbr_bw_rtts, bbr->rtt_cnt, bw);
	}
}

/* Estimate when the pipe is full, using the change in delivery rate: BBR
 * estimates that STARTUP filled the pipe if the estimated bw hasn't changed by
 * at least bbr_full_bw_thresh (25%) after bbr_full_bw_cnt (3) non-app-limited
 * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
 * higher rwin, 3: we get higher delivery rate samples. Or transient
 * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
 * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
 */
static void bbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw_thresh;

	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
		return;

	bw_thresh = (u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) {
		bbr->full_bw = bbr_max_bw(sk);
		bbr->full_bw_cnt = 0;
		return;
	}
	++bbr->full_bw_cnt;
	bbr->full_bw_reached = bbr->full_bw_cnt >= bbr_full_bw_cnt;
}

/* If pipe is probably full, drain the queue and then enter steady-state. */
// 如果管道可能满了，那么清空发送队列
static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	// 如果当前的模式是start up 而且 已经达到最大bw，就切换模式为drain
	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		bbr->mode = BBR_DRAIN;	/* drain queue we created */
		bbr->pacing_gain = bbr_drain_gain;	/* pace slow to drain */
		bbr->cwnd_gain = bbr_high_gain;	/* maintain cwnd */
		tcp_sk(sk)->snd_ssthresh =
				bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT);
	}	/* fall through to check if in-flight is already small: */

	// 如果in_flight 小于 cwnd， 启动探测bw模式
	if (bbr->mode == BBR_DRAIN &&
	    tcp_packets_in_flight(tcp_sk(sk)) <=
	    bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT))
		bbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */
}

/* The goal of PROBE_RTT mode is to have BBR flows cooperatively and
 * periodically drain the bottleneck queue, to converge to measure the true
 * min_rtt (unloaded propagation delay). This allows the flows to keep queues
 * small (reducing queuing delay and packet loss) and achieve fairness among
 * BBR flows.
 *
 * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
 * we enter PROBE_RTT mode and cap the cwnd at bbr_cwnd_min_target=4 packets.
 * After at least bbr_probe_rtt_mode_ms=200ms and at least one packet-timed
 * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
 * re-enter the previous mode. BBR uses 200ms to approximately bound the
 * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
 *
 * Note that flows need only pay 2% if they are busy sending over the last 10
 * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
 * natural silences or low-rate periods within 10 seconds where the rate is low
 * enough for long enough to drain its queue in the bottleneck. We pick up
 * these min RTT measurements opportunistically with our min_rtt filter. :-)
 */

// PROBE_RTT模式的目标是使BBR流协同并周期性地排出瓶颈队列，以收敛以测量真实的min_rtt（空载传播延迟）。
// 这可以使流量保持较小的队列（减少排队延迟和数据包丢失）并实现BBR流程之间的公平性。
// min_rtt过滤器窗口是10秒。当min_rtt估计到期时，我们输入PROBE_RTT模式，
// 并将cwnd限制在bbr_cwnd_min_target = 4个数据包。
// 在至少bbr_probe_rtt_mode_ms = 200ms并且在该航程大小<= 4的情况下至少进行了一次数据包定时往返行程后，
// 我们离开PROBE_RTT模式并重新进入之前的模式。 BBR使用200ms来将PROBE_RTT的cwnd capping的性能损失约为2％（200ms / 10s）。
// *请注意，如果流量在过去的10秒内忙于发送，流量只需支付2％。
// 交互式应用程序（例如Web，RPC，视频块）在10秒内通常会有自然的沉默或低速率时段，
// 这些时段的速率足够低，足以将其队列排入瓶颈。我们用我们的min_rtt过滤器机会性地挑选这些最小RTT测量值。 :-)
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool filter_expired;

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	// 比较当前时间是不是超过了10s
	filter_expired = after(tcp_jiffies32,
			       bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);
	// 如果rtt大于0 而且 rtt小于min rtt，记录min rtt
	// 或者 时间已经超过了10s 而且 不是delayed的ack ， 记录min rtt
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us <= bbr->min_rtt_us ||
	     (filter_expired && !rs->is_ack_delayed))) {
		bbr->min_rtt_us = rs->rtt_us;
		bbr->min_rtt_stamp = tcp_jiffies32; // min_rtt_stamp 来存储上次记录min rtt的时间
	}

	// 如果时间超过了10s， 而且不是探测RTT模式，那么启动探测RTT模式
	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */
		bbr->pacing_gain = BBR_UNIT;
		bbr->cwnd_gain = BBR_UNIT;
		// 将当前的cwnd存在prior_cwnd
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		// 标志probe_rtt_done_stamp=0
		bbr->probe_rtt_done_stamp = 0;
	}

	// 如果开启了BBR_PROBE_RTT模式
	if (bbr->mode == BBR_PROBE_RTT) {
		/* Ignore low rate samples during this mode. */
		// 如果没delivered或inflight，则置app_limited=1
		// 没有发送数据包，就置app_limited=1
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;

		/* Maintain min packets in flight for max(200 ms, 1 round). */
		// 如果未设置probe_rtt_done_stamp 而且 inflight <= 4，
		// 说明启动了BBR_PROBE_RTT模式
		if (!bbr->probe_rtt_done_stamp && 
		    tcp_packets_in_flight(tp) <= bbr_cwnd_min_target) {
			bbr->probe_rtt_done_stamp = tcp_jiffies32 +
				msecs_to_jiffies(bbr_probe_rtt_mode_ms);
			bbr->probe_rtt_round_done = 0;
			bbr->next_rtt_delivered = tp->delivered;
		} else if (bbr->probe_rtt_done_stamp) {
			if (bbr->round_start)
				bbr->probe_rtt_round_done = 1; // 探测RTT一轮结束
			if (bbr->probe_rtt_round_done &&  
			    after(tcp_jiffies32, bbr->probe_rtt_done_stamp)) {
				// 如果探测RTT结束了
				bbr->min_rtt_stamp = tcp_jiffies32;
				bbr->restore_cwnd = 1;  /* snap to prior_cwnd */
				// 重置模式
				bbr_reset_mode(sk);
			}
		}
	}
	/* Restart after idle ends only once we process a new S/ACK for data */
	if (rs->delivered > 0)
		bbr->idle_restart = 0;
}

// /*全状态更新函数如下所列*/
static void bbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	// 评估带宽
	bbr_update_bw(sk, rs);
	// bbr循环分析
	bbr_update_cycle_phase(sk, rs);
	// 判断最大bw
	bbr_check_full_bw_reached(sk, rs);
	// 检查drain，是否需要发送queue中的数据
	bbr_check_drain(sk, rs);
	// 评估最小rtt
	bbr_update_min_rtt(sk, rs);
}

// linux/net/ipv4/tcp_input.c 中 tcp_cong_control 调用，是tcp拥塞控制的入口点
static void bbr_main(struct sock *sk, const struct rate_sample *rs)
{
	// 从scok中拿到bbr结构数据
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw;

	bbr_update_model(sk, rs);

	//获取最大bw
	bw = bbr_bw(sk);
	// 根据bw和pacing_gain来得到rate
	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain);
	// 根据cwnd_gain设置cwnd
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);
}

static void bbr_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->prior_cwnd = 0;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	bbr->rtt_cnt = 0;
	bbr->next_rtt_delivered = 0;
	bbr->prev_ca_state = TCP_CA_Open;
	bbr->packet_conservation = 0;

	bbr->probe_rtt_done_stamp = 0;
	bbr->probe_rtt_round_done = 0;
	bbr->min_rtt_us = tcp_min_rtt(tp);
	bbr->min_rtt_stamp = tcp_jiffies32;

	minmax_reset(&bbr->bw, bbr->rtt_cnt, 0);  /* init max bw to 0 */

	bbr->has_seen_rtt = 0;
	// 根据sndwnd和rtt，计算bw，再计算rate
	bbr_init_pacing_rate_from_rtt(sk);

	bbr->restore_cwnd = 0;
	bbr->round_start = 0;
	bbr->idle_restart = 0;
	bbr->full_bw_reached = 0;
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->cycle_mstamp = 0;
	bbr->cycle_idx = 0;
	// 重置long-term的各种标志位
	bbr_reset_lt_bw_sampling(sk);
	// 重置startup mode
	bbr_reset_startup_mode(sk);

	// sk_pacing_status改为 SK_PACING_NEEDED
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

// 有linux tcp_sndbuf_expand 调用，sndmem = ca_ops->sndbuf_expand ? ca_ops->sndbuf_expand(sk) : 2;
static u32 bbr_sndbuf_expand(struct sock *sk)
{
	/* Provision 3 * cwnd since BBR may slow-start even during recovery. */
	return 3;
}

/* In theory BBR does not need to undo the cwnd since it does not
 * always reduce cwnd on losses (see bbr_main()). Keep it for now.
 */
// 由linux tcp_undo_cwnd_reduction调用，
// if (tp->prior_ssthresh) {
// 	const struct inet_connection_sock *icsk = inet_csk(sk);
// 	tp->snd_cwnd = icsk->icsk_ca_ops->undo_cwnd(sk);
// 	if (tp->prior_ssthresh > tp->snd_ssthresh) {
// 		tp->snd_ssthresh = tp->prior_ssthresh;
// 		tcp_ecn_withdraw_cwr(tp);
// 	}
// }
static u32 bbr_undo_cwnd(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->full_bw = 0;   /* spurious slow-down; reset full pipe detection */
	bbr->full_bw_cnt = 0;
	bbr_reset_lt_bw_sampling(sk);
	return tcp_sk(sk)->snd_cwnd;
}

/* Entering loss recovery, so save cwnd for when we exit or undo recovery. */
// linux tcp_enter_loss 调用， 丢包的时候
static u32 bbr_ssthresh(struct sock *sk)
{
	bbr_save_cwnd(sk);
	return tcp_sk(sk)->snd_ssthresh;
}

static size_t bbr_get_info(struct sock *sk, u32 ext, int *attr,
			   union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_BBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct bbr *bbr = inet_csk_ca(sk);
		u64 bw = bbr_bw(sk);

		bw = bw * tp->mss_cache * USEC_PER_SEC >> BW_SCALE;
		memset(&info->bbr, 0, sizeof(info->bbr));
		info->bbr.bbr_bw_lo		= (u32)bw;
		info->bbr.bbr_bw_hi		= (u32)(bw >> 32);
		info->bbr.bbr_min_rtt		= bbr->min_rtt_us;
		info->bbr.bbr_pacing_gain	= bbr->pacing_gain;
		info->bbr.bbr_cwnd_gain		= bbr->cwnd_gain;
		*attr = INET_DIAG_BBRINFO;
		return sizeof(info->bbr);
	}
	return 0;
}

static inline void tcp_set_ca_state(struct sock *sk, const u8 ca_state)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_ops->set_state)
		icsk->icsk_ca_ops->set_state(sk, ca_state);
	icsk->icsk_ca_state = ca_state;
}

static void bbr_set_state(struct sock *sk, u8 new_state)
{
	struct bbr *bbr = inet_csk_ca(sk);

	// 如果设置的状态为 TCP_CA_Loss 那么，直接设置bbr的上一次状态为TCP_CA_Loss
	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		bbr->prev_ca_state = TCP_CA_Loss;
		bbr->full_bw = 0;
		bbr->round_start = 1;	/* treat RTO like end of a round */
		bbr_lt_bw_sampling(sk, &rs);
	}
}

static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "bbr",
	.owner		= THIS_MODULE,
	.init		= bbr_init,
	.cong_control	= bbr_main,
	.sndbuf_expand	= bbr_sndbuf_expand,
	.undo_cwnd	= bbr_undo_cwnd,
	// linux/include/net/tcp.h tcp_ca_event 函数调用
	.cwnd_event	= bbr_cwnd_event,
	.ssthresh	= bbr_ssthresh,
	.min_tso_segs	= bbr_min_tso_segs,
	.get_info	= bbr_get_info,
	.set_state	= bbr_set_state,
};

static int __init bbr_register(void)
{
	BUILD_BUG_ON(sizeof(struct bbr) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_bbr_cong_ops);
}

static void __exit bbr_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_bbr_cong_ops);
}

module_init(bbr_register);
module_exit(bbr_unregister);

MODULE_AUTHOR("Van Jacobson <vanj@google.com>");
MODULE_AUTHOR("Neal Cardwell <ncardwell@google.com>");
MODULE_AUTHOR("Yuchung Cheng <ycheng@google.com>");
MODULE_AUTHOR("Soheil Hassas Yeganeh <soheil@google.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP BBR (Bottleneck Bandwidth and RTT)");