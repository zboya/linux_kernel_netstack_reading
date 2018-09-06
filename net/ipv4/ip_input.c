/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <net/dst_metadata.h>

/*
 *	Process Router Attention IP option (RFC 2113)
 */
bool ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);

	for (ra = rcu_dereference(net->ipv4.ra_chain); ra; ra = rcu_dereference(ra->next)) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex)) {
			if (ip_is_fragment(ip_hdr(skb))) {
				if (ip_defrag(net, skb, IP_DEFRAG_CALL_RA_CHAIN))
					return true;
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		return true;
	}
	return false;
}

//从这里进入L4传输层
/*
 * ip_local_deliver_finish()将输入数据包从网络层传递
 * 到传输层。过程如下:
 * 1)首先，在数据包传递给传输层之前，去掉IP首部
 * 2)接着，如果是RAW套接字接收数据包，则需要
 * 复制一份副本，输入到接收该数据包的套接字。
 * 3)最后，通过传输层的接收例程，将数据包传递
 * 到传输层，由传输层进行处理。
 */
static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	{
		// 获取ip头里的协议
		int protocol = ip_hdr(skb)->protocol;
		const struct net_protocol *ipprot;
		int raw;

	resubmit:
		// 分发处理原始套接字
		raw = raw_local_deliver(skb, protocol);

		// 根据协议来获取协议的handler函数，如果协议为tcp，那么为tcp_v4_rcv
		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot) {
			int ret;

			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			// 用协议的处理函数处理skb
			ret = ipprot->handler(skb);
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
		} else {
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
				kfree_skb(skb);
			} else {
				__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
				consume_skb(skb);
			}
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
/*
  * 在ip_route_input进行路由选择后，如果接收的包
  * 是发送给本机，则调用ip_local_deliver来传递给上层协议
  */
  //ip_route_input_slow->ip_local_deliver
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);

	 /* 
	* frag_off是16位，其中高3位用作标志位，
	* 低13位才是真正的偏移量.
	* 内核可通过设置的分片标识位或非0
	* 的分片偏移量识别分片的分组。偏移
	* 量字段为0，表明这是分组的最后一个分片。
	* 
	* 如果接收到的IP数据包时分片，则调用
	* ip_defrag()进行重组，其标志位IP_DEFRAG_LOCAL_DELIVER。
	*/
	if (ip_is_fragment(ip_hdr(skb))) {
		/*
        * 重新组合分片分组的各个部分。
        * 
        * 如果ip_defrag()返回非0，则表示IP数据包分片
        * 尚未到齐，重组没有完成，或者出错，直接
        * 返回。为0，则表示已完成IP数据包的重组，
        * 需要传递到传输层进行处理。
        */
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	/*
     * 经过netfilter处理后，调用ip_local_deliver_finish()，
     * 将组装完成的IP数据包传送到传输层处理
     */
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		__IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		__IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
							     &iph->saddr,
							     &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

/*
 * ip_rcv_finish()在ip_rcv()中当IP数据包经过netfilter模块
 * 处理后被调用。完成的主要功能是，如果
 * 还没有为该数据包查找输入路由缓存，则
 * 调用ip_route_input()为其查找输入路由缓存。
 * 接着处理IP数据包首部中的选项，最后
 * 根据输入路由缓存输入到本地或抓发。
 */
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	int (*edemux)(struct sk_buff *skb);
	struct net_device *dev = skb->dev;
	struct rtable *rt;
	int err;

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	if (net->ipv4.sysctl_ip_early_demux &&
	    !skb_dst(skb) &&
	    !skb->sk &&
	    !ip_is_fragment(iph)) {
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot && (edemux = READ_ONCE(ipprot->early_demux))) {
			err = edemux(skb);
			if (unlikely(err))
				goto drop_error;
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	/*
	 * 如果还没有为该数据包查找输入路由缓存，
	 * 则调用ip_route_input()为其查找输入路由缓存。
	 * 若查找失败，则将该数据包丢弃。
	 */
	if (!skb_valid_dst(skb)) {
		err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					   iph->tos, dev);
		if (unlikely(err))
			goto drop_error;
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	/*
	 * 根据长度判断IP首部中是否存在选项，如果有，
	 * 则调用ip_rcv_options()处理IP选项。
	 */
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
	} else if (skb->pkt_type == PACKET_BROADCAST ||
		   skb->pkt_type == PACKET_MULTICAST) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		/* RFC 1122 3.3.6:
		 *
		 *   When a host sends a datagram to a link-layer broadcast
		 *   address, the IP destination address MUST be a legal IP
		 *   broadcast or IP multicast address.
		 *
		 *   A host SHOULD silently discard a datagram that is received
		 *   via a link-layer broadcast (see Section 2.4) but does not
		 *   specify an IP multicast or broadcast destination address.
		 *
		 * This doesn't explicitly say L2 *broadcast*, but broadcast is
		 * in a way a form of multicast and the most common use case for
		 * this is 802.11 protecting against cross-station spoofing (the
		 * so-called "hole-196" attack) so do it for both.
		 */
		if (in_dev &&
		    IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST))
			goto drop;
	}

	/*
	 * dst_input根据输入路由缓存决定输入到本地或
	 * 转发，最终前者调用ip_local_deliver()，或者调用
	 * ip_forward()。
	 * 对于输入到本地或转发的组播报文，在经过netfilter处理
	 * 之后会调用ip_rcv_finish()正式进入输入的处理。先调用
	 * ip_route_input()进行输入路由的查询，如果发现目的地址
	 * 为组播地址，就会按照组播地址的规则查找路由，查找
	 * 到组播的输入路由后，组播报文接收处理函数为ip_mr_input()。
	 * 参见ip_route_input_mc().
	 */
	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;

drop_error:
	if (err == -EXDEV)
		__NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
	goto drop;
}

/*
 * 	Main IP Receive routine.
 */
// 由设备层调用该函数来接受ip报文
/*
* @skb: 接收到的IP数据包
 * @dev: 接收到的IP数据包当前的输入网络设备
 * @pt:输入此数据包的网络层输入接口
 * @orig_dev:接收到的IP数据包原始的输入网络设备。
*/
//  该函数主要用来处理网络层的IP报文的入口函数，它到Netfilter框架的切入点为：
//  NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, dev, NULL,ip_rcv_finish)
//  根据前面的理解，这句代码意义已经很直观明确了。那就是：如果协议栈当前收到了一个IP报文(PF_INET)，那么就把这个报文传到Netfilter
//  的NF_IP_PRE_ROUTING过滤点，去检查[R]在那个过滤点(nf_hooks[2][0])是否已经有人注册了相关的用于处理数据包的钩子函数。如果有，
//  则挨个去遍历链表nf_hooks[2][0]去寻找匹配的match和相应的target，根据返回到Netfilter框架中的值来进一步决定该如何处理该数据包
//  (由钩子模块处理还是交由ip_rcv_finish函数继续处理)。
// 
//  数据报从网卡到l3层的接收过程（非napi）: 
//  netif_rx-->net_rx_action-->process_backlog-->netif_receive_skb-- >sniffer(如果有)-->diverter(如果有)-->bridge(如果有)-->ip_rcv(或者其他的l3 层协议处理函数)
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	struct net *net;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	//数据包不是发给我们的,这里所说的“不属于”这个主机，是指在这个包目标主机的MAC地址不是本机，而不是L3层的ip地址。
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;


	net = dev_net(dev);
	__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	if (iph->ihl < 5 || iph->version != 4) // 检查ihl和ip版本
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	__IP_ADD_STATS(net,
		       IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
		       max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	if (!pskb_may_pull(skb, iph->ihl*4)) //对数据报的头长度进行检查 
		goto inhdr_error;

	iph = ip_hdr(skb);

	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		__IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	if (pskb_trim_rcsum(skb, len)) { //根据ip包总长度，重新计算skb的长度，去掉末尾的无用信息
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	skb->transport_header = skb->network_header + iph->ihl*4;

	/* Remove any debris in the socket control block */
	// 这里面后面会存ip填充信息，IP如果超过20字节，就有填充信息
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->iif = skb->skb_iif;

	/* Must drop socket now because of tproxy. */
	/*
	 * 将skb中的IP控制块清零，以便
	 * 后续对IP选项的处理
	 */
	skb_orphan(skb);

	/*
	* 最后通过netfilter模块处理后，调用ip_rcv_finish()
	* 完成IP数据包的输入。
	*/
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);

csum_error:
	__IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}
