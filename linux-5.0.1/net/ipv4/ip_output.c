/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path
 *					for decreased register pressure on x86
 *					and more readibility.
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/lwtunnel.h>
#include <linux/bpf-cgroup.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

static int
ip_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
	    unsigned int mtu,
	    int (*output)(struct net *, struct sock *, struct sk_buff *));

/* Generate a checksum for an outgoing IP datagram. */
void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}
EXPORT_SYMBOL(ip_send_check);

int __ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);

	/* 计算ip header的校验和 */
	/*Calls ip_send_check to compute the checksum to be written in the IP packet header.*/
	ip_send_check(iph);

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	/* 设置skb协议字段 */
	skb->protocol = htons(ETH_P_IP);

	/*
	 * 经过netfilter的 LOCAL_OUT钩子点进行检查过滤，如果通过，则通过dst_output()函数，
	 * 实际上调用的是IP数据包输出函数 ip_output()函数。
	 */
	/*
	 * nf_hook 只是一个 wrapper，它调用 nf_hook_thresh，首先检查是否有为这个协议族和hook 类型
	 *（这里分别为 NFPROTO_IPV4 和 NF_INET_LOCAL_OUT）安装的过滤器，然后将返回到 IP 协议层，
	 * 避免深入到 netfilter 或更下面，比如 iptables 和conntrack。
	 *
	 * 请记住：
	 * 如果你有非常多或者非常复杂的 netfilter 或 iptables 规则，那些规则将在触发sendmsg 系统调的
	 * 用户进程的上下文中执行。如果对这个用户进程设置了 CPU 亲和性，相应的 CPU 将花费系统时间（system time）
	 * 处理出站（outbound）iptables 规则。如果你在做性能回归测试，那可能要考虑根据系统的负载，
	 * 将相应的用户进程绑到到特定的 CPU，或者是减少 netfilter/iptables 规则的复杂度，以减少对性能测试的影响。
	 */
	/*the IP protocol layer will call down into netfilter by calling nf_hook. 
	The return value of the nf_hook function will be passed back up to ip_local_out.
	*/
	return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}

int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int err;

	err = __ip_local_out(net, sk, skb);

	/*Destination cache, ip_output()*/
	if (likely(err == 1))
		err = dst_output(net, sk, skb);

	return err;
}
EXPORT_SYMBOL_GPL(ip_local_out);

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = ip4_dst_hoplimit(dst);
	return ttl;
}

/*
 *		Add an ip header to a skbuff and send it out.
 *
 */
int ip_build_and_send_pkt(struct sk_buff *skb, const struct sock *sk,
			  __be32 saddr, __be32 daddr, struct ip_options_rcu *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = skb_rtable(skb);
	struct net *net = sock_net(sk);
	struct iphdr *iph;

	/* Build the IP header. */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->opt.optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	iph->ttl      = ip_select_ttl(inet, &rt->dst);
	iph->daddr    = (opt && opt->opt.srr ? opt->opt.faddr : daddr);
	iph->saddr    = saddr;
	iph->protocol = sk->sk_protocol;
	if (ip_dont_fragment(sk, &rt->dst)) {
		iph->frag_off = htons(IP_DF);
		iph->id = 0;
	} else {
		iph->frag_off = 0;
		__ip_select_ident(net, iph, 1);
	}

	if (opt && opt->opt.optlen) {
		iph->ihl += opt->opt.optlen>>2;
		ip_options_build(skb, &opt->opt, daddr, rt, 0);
	}

	skb->priority = sk->sk_priority;
	if (!skb->mark)
		skb->mark = sk->sk_mark;

	/* Send it out. */
	return ip_local_out(net, skb->sk, skb);
}
EXPORT_SYMBOL_GPL(ip_build_and_send_pkt);

/*This function handles bumping various statistics counters prior to handing the packet down to the neighbour cache.*/
static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	u32 nexthop;

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTBCAST, skb->len);

	/* skb 头部空间不能存储链路头 */
	/* Be paranoid, rather than too clever. */
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;

		/* 重新分配skb */
		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (!skb2) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		consume_skb(skb);
		skb = skb2;
	}

	if (lwtunnel_xmit_redirect(dst->lwtstate)) {
		int res = lwtunnel_xmit(skb);

		if (res < 0 || res == LWTUNNEL_XMIT_DONE)
			return res;
	}

	rcu_read_lock_bh();

	/* 获取下一跳 */
	nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);

	/* 邻居子系统表查询 */
	neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);
	if (!IS_ERR(neigh)) {
		int res;

		sock_confirm_neigh(skb, neigh);
	
		/* ##the neighbour’s state is checked and the appropriate output function is called.*/
		/* 邻居子系统的处理 ， 最终走到 dev_queue_xmit() */
		res = neigh_output(neigh, skb);

		rcu_read_unlock_bh();
		return res;
	}
	rcu_read_unlock_bh();

	net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
			    __func__);
	kfree_skb(skb);
	return -EINVAL;
}

static int ip_finish_output_gso(struct net *net, struct sock *sk,
				struct sk_buff *skb, unsigned int mtu)
{
	netdev_features_t features;
	struct sk_buff *segs;
	int ret = 0;

	/* common case: seglen is <= mtu */
	if (skb_gso_validate_network_len(skb, mtu))
		return ip_finish_output2(net, sk, skb);

	/* Slowpath -  GSO segment length exceeds the egress MTU.
	 *
	 * This can happen in several cases:
	 *  - Forwarding of a TCP GRO skb, when DF flag is not set.
	 *  - Forwarding of an skb that arrived on a virtualization interface
	 *    (virtio-net/vhost/tap) with TSO/GSO size set by other network
	 *    stack.
	 *  - Local GSO skb transmitted on an NETIF_F_TSO tunnel stacked over an
	 *    interface with a smaller MTU.
	 *  - Arriving GRO skb (or GSO skb in a virtualized environment) that is
	 *    bridged to a NETIF_F_TSO tunnel stacked over an interface with an
	 *    insufficent MTU.
	 */

	/* skb gso len大于mtu值，做gso segment处理。*/
	features = netif_skb_features(skb);
	BUILD_BUG_ON(sizeof(*IPCB(skb)) > SKB_SGO_CB_OFFSET);
	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
	if (IS_ERR_OR_NULL(segs)) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	consume_skb(skb);

	do {
		struct sk_buff *nskb = segs->next;
		int err;

		skb_mark_not_on_list(segs);
		/* IP分片 */
		err = ip_fragment(net, sk, segs, mtu, ip_finish_output2);

		if (err && ret == 0)
			ret = err;
		segs = nskb;
	} while (segs);

	return ret;
}


/* 根据网络配置确定是否需要对数据包进行重路由，是否需要对数据包分割，最后，
 * 调用ip_finish_output2()与邻居子系统接口，将数据包目标地址中的IP地址转换成
 * 目标主机的MAC地址。
 */
static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	unsigned int mtu;
	int ret;

	ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	/* 如果内核启用了 netfilter 和数据包转换（XFRM - transformer数据加密相关），
	 * 则更新 skb 的标志并通过 dst_output() 将其发回。
	 */
#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb_dst(skb)->xfrm) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(net, sk, skb);
	}
#endif

	/* 获取mtu */
	/*If packet’s length is larger than the MTU and the packet’s segmentation will not be offloaded to the device, 
	ip_fragment is called to help fragment the packet prior to transmission.*/
	mtu = ip_skb_dst_mtu(sk, skb);

	/* 如果是gso，做gso packet处理 */
	if (skb_is_gso(skb))
		return ip_finish_output_gso(net, sk, skb, mtu);

	/* 长度超过mtu或者设置了IPSKB_FRAG_PMTU, 做ip fragment动作，即ip分片。 */
	if (skb->len > mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU))
		return ip_fragment(net, sk, skb, mtu, ip_finish_output2);

	/* 其他类型的packet数据包 */
	/*the packet is passed straight through to ip_finish_output2.*/
	/*This function handles bumping various statistics counters prior to handing the packet down to the neighbour cache.*/
	return ip_finish_output2(net, sk, skb);
}

static int ip_mc_finish_output(struct net *net, struct sock *sk,
			       struct sk_buff *skb)
{
	int ret;

	ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	return dev_loopback_xmit(net, sk, skb);
}

int ip_mc_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct rtable *rt = skb_rtable(skb);
	struct net_device *dev = rt->dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if (sk_mc_loop(sk)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    &&
		    ((rt->rt_flags & RTCF_LOCAL) ||
		     !(IPCB(skb)->flags & IPSKB_FORWARDED))
#endif
		   ) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING,
					net, sk, newskb, NULL, newskb->dev,
					ip_mc_finish_output);
		}

		/* Multicasts with ttl 0 must not go beyond the host */

		if (ip_hdr(skb)->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING,
				net, sk, newskb, NULL, newskb->dev,
				ip_mc_finish_output);
	}

	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			    net, sk, skb, NULL, skb->dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/* 在tcp/udp ipv4情况下，dst_output()实际会调用到该接口。*/
int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

	/* 设置发送数据包输出网络设备，数据包协议，调用网络过滤子系统回调函数过滤数据包，
	 * 如果通过安全检查，调用ip_finish_output()发送数据包。*/
	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 * 通过调用NF_HOOK_COND将控制权交给netfilter。
	 * NF_HOOK_COND 通过检查传入的条件来工作。在这里条件是!(IPCB(skb)->flags & IPSKB_REROUTED。
	 * 如果此条件为真，则 skb 将发送给 netfilter。如果 netfilter 允许包通过，okfn 回调函数将被调用。
	 * 在这里，okfn 是 ip_finish_output。
	 */
	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			    net, sk, skb, NULL, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/*
 * copy saddr and daddr, possibly using 64bit load/stores
 * Equivalent to :
 *   iph->saddr = fl4->saddr;
 *   iph->daddr = fl4->daddr;
 */
static void ip_copy_addrs(struct iphdr *iph, const struct flowi4 *fl4)
{
	BUILD_BUG_ON(offsetof(typeof(*fl4), daddr) !=
		     offsetof(typeof(*fl4), saddr) + sizeof(fl4->saddr));
	memcpy(&iph->saddr, &fl4->saddr,
	       sizeof(fl4->saddr) + sizeof(fl4->daddr));
}

/* Note: skb->sk can be different from sk, in case of tunnels */
/*
 * ip层的发送函数，会被传输层作为callback function调用。
 * 该函数提供：
 * 1. 路由查找校验
 * 2. 封装IP头和IP选项
 * 最后调用 ip_local_out() 发送数据包。
 *
 * 注：
 * 在TCP中，将TCP段打包成IP数据报的方法根据TCP段类型的不同而有多种接口，
 * 最常用的就是ip_queue_xmit()，而ip_build_and_send_pkt()和ip_send_unicast_reply()只有在发送特定段时才会调用。
 * 
 * 在UDP中使用的输出接口有 ip_append_data() 和 ip_push_pending_frames()
 */
int __ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl,
		    __u8 tos)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options_rcu *inet_opt;
	struct flowi4 *fl4;
	struct rtable *rt;
	struct iphdr *iph;
	int res;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	fl4 = &fl->u.ip4;

	/* 路由判断，是否需要路由出去。即查看skb中是否有缓存路由 */
	rt = skb_rtable(skb);
	if (rt)
		goto packet_routed;

	/* 如果skb中缓存了输出路由缓存项，则需要检查该路由缓存是否过期。
	 * 如果路由缓存项过期了，则需要重新通过输出网络设备dev，ip目的，源地址等信息
	 * 查找输出路由缓存项。如果查找到对应的路由缓存项，则将其输出到sock中，否则，将try，最后drop该数据包。
	 */
	/* Make sure we can route this packet. */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (!rt) {
		__be32 daddr;

		/* Use correct destination address if we have options. */
		daddr = inet->inet_daddr;
		if (inet_opt && inet_opt->opt.srr)
			daddr = inet_opt->opt.faddr;

		/* 查找路由 */
		/* If this fails, retransmit mechanism of transport layer will
		 * keep trying until route appears or the connection times
		 * itself out.
		 */
		rt = ip_route_output_ports(net, fl4, sk,
					   daddr, inet->inet_saddr,
					   inet->inet_dport,
					   inet->inet_sport,
					   sk->sk_protocol,
					   RT_CONN_FLAGS_TOS(sk, tos),
					   sk->sk_bound_dev_if);
		if (IS_ERR(rt))
			goto no_route;
		sk_setup_caps(sk, &rt->dst);
	}
	
	/* 如果没有过期，则使用缓存。 */
	skb_dst_set_noref(skb, &rt->dst);

	/* 查找到路由后的处理 */
packet_routed:
	/*  */
	if (inet_opt && inet_opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto no_route;

	/* 预留和填充ip header，包括ip option部分空间。 */
	/* OK, we know where to send it, allocate and build IP header. */
	skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (tos & 0xff));

	/* 检查是否不需要分片，并设置相应bit */
	if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->dst);
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);

	/* 如果有ip option，则需要给IP header构建option域。 */
	/* Transport layer set skb->h.foo itself. */
	if (inet_opt && inet_opt->opt.optlen) {
		iph->ihl += inet_opt->opt.optlen >> 2;
		ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt, 0);
	}

	/* 设置ip id */
	ip_select_ident_segs(net, skb, sk,
			     skb_shinfo(skb)->gso_segs ?: 1);

	/* priority, mark带外信息的设置，即可通过sock进行设置。 */
	/* TODO : should we use skb->sk here instead of sk ? */
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	/* 最后处理：
	 * 1. 计算校验和
	 * 2. 调用网络过滤子系统的回调函数，来查看数据包是否有权限调到下一个步骤（dst_output）继续发送 
	 */
	res = ip_local_out(net, sk, skb);

	rcu_read_unlock();
	return res;

no_route:
	rcu_read_unlock();
	IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}
EXPORT_SYMBOL(__ip_queue_xmit);

static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	skb_dst_drop(to);
	skb_dst_copy(to, from);
	to->dev = from->dev;
	to->mark = from->mark;

	skb_copy_hash(to, from);

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
	skb_ext_copy(to, from);
#if IS_ENABLED(CONFIG_IP_VS)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
}

static int ip_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		       unsigned int mtu,
		       int (*output)(struct net *, struct sock *, struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);

	if ((iph->frag_off & htons(IP_DF)) == 0)
		return ip_do_fragment(net, sk, skb, output);

	if (unlikely(!skb->ignore_df ||
		     (IPCB(skb)->frag_max_size &&
		      IPCB(skb)->frag_max_size > mtu))) {
		IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	return ip_do_fragment(net, sk, skb, output);
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 */

int ip_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		   int (*output)(struct net *, struct sock *, struct sk_buff *))
{
	struct iphdr *iph;
	int ptr;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs;
	int offset;
	__be16 not_last_frag;
	struct rtable *rt = skb_rtable(skb);
	int err = 0;

	/* for offloaded checksums cleanup checksum before fragmentation */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_checksum_help(skb)))
		goto fail;

	/*
	 *	Point into the IP datagram header.
	 */

	iph = ip_hdr(skb);

	mtu = ip_skb_dst_mtu(sk, skb);
	if (IPCB(skb)->frag_max_size && IPCB(skb)->frag_max_size < mtu)
		mtu = IPCB(skb)->frag_max_size;

	/*
	 *	Setup starting values.
	 */

	hlen = iph->ihl * 4;
	mtu = mtu - hlen;	/* Size of data space */
	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;
	ll_rs = LL_RESERVED_SPACE(rt->dst.dev);

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	if (skb_has_frag_list(skb)) {
		struct sk_buff *frag, *frag2;
		unsigned int first_len = skb_pagelen(skb);

		if (first_len - hlen > mtu ||
		    ((first_len - hlen) & 7) ||
		    ip_is_fragment(iph) ||
		    skb_cloned(skb) ||
		    skb_headroom(skb) < ll_rs)
			goto slow_path;

		skb_walk_frags(skb, frag) {
			/* Correct geometry. */
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen + ll_rs)
				goto slow_path_clean;

			/* Partially cloned skb? */
			if (skb_shared(frag))
				goto slow_path_clean;

			BUG_ON(frag->sk);
			if (skb->sk) {
				frag->sk = skb->sk;
				frag->destructor = sock_wfree;
			}
			skb->truesize -= frag->truesize;
		}

		/* Everything is OK. Generate! */

		err = 0;
		offset = 0;
		frag = skb_shinfo(skb)->frag_list;
		skb_frag_list_init(skb);
		skb->data_len = first_len - skb_headlen(skb);
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		iph->frag_off = htons(IP_MF);
		ip_send_check(iph);

		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				frag->ip_summed = CHECKSUM_NONE;
				skb_reset_transport_header(frag);
				__skb_push(frag, hlen);
				skb_reset_network_header(frag);
				memcpy(skb_network_header(frag), iph, hlen);
				iph = ip_hdr(frag);
				iph->tot_len = htons(frag->len);
				ip_copy_metadata(frag, skb);
				if (offset == 0)
					ip_options_fragment(frag);
				offset += skb->len - hlen;
				iph->frag_off = htons(offset>>3);
				if (frag->next)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				ip_send_check(iph);
			}

			err = output(net, sk, skb);

			if (!err)
				IP_INC_STATS(net, IPSTATS_MIB_FRAGCREATES);
			if (err || !frag)
				break;

			skb = frag;
			frag = skb->next;
			skb_mark_not_on_list(skb);
		}

		if (err == 0) {
			IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
		return err;

slow_path_clean:
		skb_walk_frags(skb, frag2) {
			if (frag2 == frag)
				break;
			frag2->sk = NULL;
			frag2->destructor = NULL;
			skb->truesize += frag2->truesize;
		}
	}

slow_path:
	iph = ip_hdr(skb);

	left = skb->len - hlen;		/* Space per frame */
	ptr = hlen;		/* Where to start from */

	/*
	 *	Fragment the datagram.
	 */

	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */

	while (left > 0) {
		len = left;

		/* 如果len大于mtu，设置当前的将要分片的数据大小为MTU */
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		if (len > mtu)
			len = mtu;

		/* 长度对齐 */
		/* IF: we are not sending up to and including the packet end
		   then align the next start on an eight byte boundary */
		if (len < left)	{
			len &= ~7;
		}

		/* malloc一个新的buffer，大小包括 ip payload, ip head 和l2 head */
		/* Allocate buffer */
		skb2 = alloc_skb(len + hlen + ll_rs, GFP_ATOMIC);
		if (!skb2) {
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */
		/* 复制一些相同的值的域 */
		ip_copy_metadata(skb2, skb);

		/* 保留l2 header空间 */
		skb_reserve(skb2, ll_rs);

		/* 设置ip header & ddos header & ip payload空间 */
		skb_put(skb2, len + hlen);
		skb_reset_network_header(skb2);

		/* l4 header指针为ip header + ddos header数据偏移位置，用于复制原始payload */
		skb2->transport_header = skb2->network_header + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */
		/* 将每一个分片的ip包都关联到源包的socket */
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 */
		/* 拷贝 ip header */
		skb_copy_from_linear_data(skb, skb_network_header(skb2), hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		 /* 拷贝ip payload数据 */
		if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
			BUG();
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		 /* 填充相应的ip头 */
		iph = ip_hdr(skb2);
		iph->frag_off = htons((offset >> 3));

		if (IPCB(skb)->flags & IPSKB_FRAG_PMTU)
			iph->frag_off |= htons(IP_DF);

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		 /* 第一个包，因此，进行ip_option处理 */
		if (offset == 0)
			ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		 /* 不是最后一个包，因此，设置mf位 */
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);

		/* 移动数据指针以及更改数据偏移 */
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */
		 /* 更新包头的数据长度 */
		iph->tot_len = htons(len + hlen);

		/* 重新计算校验 */
		ip_send_check(iph);

		/* 调用   ip_finish_output2() 函数*/
		err = output(net, sk, skb2);
		if (err)
			goto fail;

		IP_INC_STATS(net, IPSTATS_MIB_FRAGCREATES);
	}
	consume_skb(skb);
	IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb);
	IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
	return err;
}
EXPORT_SYMBOL(ip_do_fragment);

int
ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	struct msghdr *msg = from;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (!copy_from_iter_full(to, len, &msg->msg_iter))
			return -EFAULT;
	} else {
		__wsum csum = 0;
		if (!csum_and_copy_from_iter_full(to, len, &csum, &msg->msg_iter))
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}
EXPORT_SYMBOL(ip_generic_getfrag);

static inline __wsum
csum_page(struct page *page, int offset, int copy)
{
	char *kaddr;
	__wsum csum;
	kaddr = kmap(page);
	csum = csum_partial(kaddr + offset, copy, 0);
	kunmap(page);
	return csum;
}


/*
 * 对上层下来的数据进行整形，如果是大数据包进行切割，变成多个小于或等于MTU的SKB。
 * (CORK flag设置的情况下)如果是小数据包，并且开启了聚合，就会将若干个数据包整合。
 *
 * https://blog.csdn.net/minghe_uestc/article/details/7836920?utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromMachineLearnPai2%7Edefault-1.control&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromMachineLearnPai2%7Edefault-1.control
 *
 * 1. 如果 socket 是 corked，则从 ip_append_data() 调用此函数；
 * 2. 如果 socket 未被 cork，则从ip_make_skb() 调用此函数。
 * 在任何一种情况下，函数都将分配一个新缓冲区来存储传入的数据，或者将数据附加到现有数据中。
 * 这种工作的方式围绕 socket 的发送队列，等待发送的现有数据（例如，如果 socket 被 cork）将在队列中有一个对应条目，
 * 可以被追加数据。
 *
 * 1. 在 cork 的情况下，__ip_append_data 的返回值向上传递。数据位于发送队列中，
 * 直到 udp_sendmsg() 确定是时候调用 udp_push_pending_frames() 来完成 skb，后者会进一步调用 udp_send_skb() 。
 * 2. 在 unorked 情况下，持有 skb 的 queue 被作为参数传递给上面描述的 __ip_make_skb() ，
 * 在那里它被出队并通过 udp_send_skb() 发送到更底层。
 *
 * 参数：
 * getfrag(): 将L4指定的数据拷贝到一个一个的skb中，因为该函数会由多个L4协议公用，执行拷贝时，
 *		它们的动作有所差异（主要是校验和计算），所以，这里用函数指针。
 * from：待拷贝数据的用户态起始地址。
 * length： 待拷贝数据长度
 * transhdrlen：传输层报文长度，例如：对应udp就是sizeof(struct udphdr)
 */
static int __ip_append_data(struct sock *sk,
			    struct flowi4 *fl4,
			    struct sk_buff_head *queue,
			    struct inet_cork *cork,
			    struct page_frag *pfrag,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ubuf_info *uarg = NULL;
	struct sk_buff *skb;

	struct ip_options *opt = cork->opt;
	int hh_len;
	int exthdrlen;
	int mtu;
	int copy;
	int err;
	int offset = 0;
	unsigned int maxfraglen, fragheaderlen, maxnonfragsize;
	int csummode = CHECKSUM_NONE;
	struct rtable *rt = (struct rtable *)cork->dst;
	unsigned int wmem_alloc_delta = 0;
	bool paged, extra_uref;
	u32 tskey = 0;

	skb = skb_peek_tail(queue);

	exthdrlen = !skb ? rt->dst.header_len : 0;
	mtu = cork->gso_size ? IP_MAX_MTU : cork->fragsize;
	paged = !!cork->gso_size;

	if (cork->tx_flags & SKBTX_ANY_SW_TSTAMP &&
	    sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
		tskey = sk->sk_tskey++;

	/* hh_len是L2的首部长度，分配内存时会为L2/L3首部预留空间，这样底层协议在处理时就
	 * 不用重新分配内存并移动数据了。
	 */
	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	/* 每个IP片段都需要有IP首部，fragheaderlen就是IP层首部长度，包括选项部分 */
	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);

	/* 为了计算方便，这里IP分片要求载荷部分是8字节对齐，所以，maxfraglen就是
	 * 最大的IP分片长度（包括IP首部）。
	 */
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	/* 长度判断，由于IPv4数据报首部的total字段是16bit，所以，一个IP报文
	 * 的总长度(包括IP首部)最大就是0xffff，如果多次调用ip_append_data()，
	 * 使得总长度超过了该限定值，那么就发送失败。
	 * 一个IP数据包最大大小不能超过64K
	 */
	maxnonfragsize = ip_sk_ignore_df(sk) ? 0xFFFF : mtu;
	if (cork->length + length > maxnonfragsize - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
			       mtu - (opt ? opt->optlen : 0));
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->dst.dev->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM) &&
	    (!(flags & MSG_MORE) || cork->gso_size) &&
	    (!exthdrlen || (rt->dst.dev->features & NETIF_F_HW_ESP_TX_CSUM)))
	    	/*由硬件执行校验和计算 */
		csummode = CHECKSUM_PARTIAL;

	if (flags & MSG_ZEROCOPY && length && sock_flag(sk, SOCK_ZEROCOPY)) {
		uarg = sock_zerocopy_realloc(sk, length, skb_zcopy(skb));
		if (!uarg)
			return -ENOBUFS;
		extra_uref = true;

		/* device支持SG, 且支持tx checksum offload */
		if (rt->dst.dev->features & NETIF_F_SG &&
		    csummode == CHECKSUM_PARTIAL) {
			paged = true;
		} else {
			uarg->zerocopy = 0;
			skb_zcopy_set(skb, uarg, &extra_uref);
		}
	}

	cork->length += length;

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */
	/* 判断输出队列是否为空，如果为空，就申请新的skb，
	 * 不为空，就直接使用追加到上传的skb中。
	 */
	if (!skb)
		goto alloc_new_skb;

	/* 开始循环拷贝用户数据到skb中。 */
	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
		/* copy表示本轮循环要拷贝的数据量，初始化为当前skb还可用容纳的数据量。*/
		copy = mtu - skb->len;

		/* 当前skb不能容纳全部的剩余数据，说明当前skb不是最后一个IP分片，
		 * 所以，需要按照8字节对齐方式安排skb，故重新计算copy。 
		 */
		if (copy < length)
			copy = maxfraglen - skb->len;

		/* 表示当前skb无剩余空间可以拷贝数据，那么需要重新分配一个新的skb */
		if (copy <= 0) {
			char *data;
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen;
			unsigned int pagedlen;
			struct sk_buff *skb_prev;

		/* 这里需要分配skb，说明上一个skb肯定无法容纳更多的数据，所以，skb_prev->len
		 * 一定是大于maxfrglen的，而且二者的差值一定在[0, 8)区间内
		 */
alloc_new_skb:
			skb_prev = skb;
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			 /* datalen记录了该新的skb能够保存多少字节的L4数据。*/
			datalen = length + fraggap;
			if (datalen > mtu - fragheaderlen)
				datalen = maxfraglen - fragheaderlen;

			/* fraglen记录了该新的skb的实际片段长度(datalen + IP首部长度) */
			fraglen = datalen + fragheaderlen;
			pagedlen = 0;

			/* 1.如果后续很快有数据到达，并且设备不支持S/G IO：那么最优的分配策略就是直接分配一个
			 * mtu大小的skb，这样后续的ip_append_data()调用可以直接使用，无需再次分配（当然，如果该skb
			 * 剩余空间不足还是会继续分配的）。

			 * 2. 其他情况，只需要分配能够容纳当前数据的大小就好。
			 */
			if ((flags & MSG_MORE) &&
			    !(rt->dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else if (!paged)
				alloclen = fraglen;
			else {
				alloclen = min_t(int, fraglen, MAX_HEADER);
				pagedlen = fraglen - alloclen;
			}

			alloclen += exthdrlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */

			/* 如果是最后一个片段，将可能存在的额外尾部加上，IPsec才需要。 */
			if (datalen == length + fraggap)
				alloclen += rt->dst.trailer_len;

			/* 分配缓冲区，transhdrlen不为0，表示第一次调用ip_append_data(),即
			 * IP报文的第一个IP片段。
			 * 第一次调用需要拷贝L4报文的首部，这是需要考虑更多的情况，所以分配函数不同。
			 */
			if (transhdrlen) {
				skb = sock_alloc_send_skb(sk,
						alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} else {
				skb = NULL;
				if (refcount_read(&sk->sk_wmem_alloc) + wmem_alloc_delta <=
				    2 * sk->sk_sndbuf)
					skb = alloc_skb(alloclen + hh_len + 15,
							sk->sk_allocation);
				if (unlikely(!skb))
					err = -ENOBUFS;
			}

			/* 分配失败，那么本次调用失败结束。 */
			if (!skb)
				goto error;


			/* 初始化好skb的一些字段 */
			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = csummode;
			skb->csum = 0;

			/* 为L2预留头部空间 */
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fraglen + exthdrlen - pagedlen);
			skb_set_network_header(skb, exthdrlen);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			data += fragheaderlen + exthdrlen;

			/* fraggap不为0，需要将上一个skb末尾的几个字节数据拷贝到新的skb中，需要以增量方式
			 * 重新计算校验和。
			 */
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			copy = datalen - transhdrlen - fraggap - pagedlen;
			/* 这里的getfrag()函数是 udplite_getfrag或之前ip_generic_getfrag，
			 * 会做用户数据到内核buffer skb的拷贝。
			 */
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			/* 本次拷贝结束，更新偏移量，因为下一次拷贝有可能需要从offset出开始。 */
			offset += copy;

			/* 递减总的带拷贝数据量 */
			length -= copy + transhdrlen;
			transhdrlen = 0;
			exthdrlen = 0;
			csummode = CHECKSUM_NONE;

			/* only the initial fragment is time stamped */
			skb_shinfo(skb)->tx_flags = cork->tx_flags;
			cork->tx_flags = 0;
			skb_shinfo(skb)->tskey = tskey;
			tskey = 0;
			skb_zcopy_set(skb, uarg, &extra_uref);

			if ((flags & MSG_CONFIRM) && !skb_prev)
				skb_set_dst_pending_confirm(skb, 1);

			/*
			 * Put the packet on the pending queue.
			 */
			if (!skb->destructor) {
				skb->destructor = sock_wfree;
				skb->sk = sk;
				wmem_alloc_delta += skb->truesize;
			}

			/* 将新分配的skb放入发送队列中 */
			__skb_queue_tail(queue, skb);
			continue;
		}

		/* copy > 0的情况：表示最后一个skb还有一些空余空间。 */
		/* 重新调整待拷贝的数据量 */
		if (copy > length)
			copy = length;

		/*
		 * 处理支持分散/收集（scatter/gather）IO 的网卡。许多卡都支持此功能，
		 * 并使用 NETIF_F_SG 标志进行通告。支持该特性的网卡可以处理数据被分散到多个 buffer 的数据包;
		 * 内核不需要花时间将多个缓冲区合并成一个缓冲区中。避免这种额外的复制会提升性能，
		 * 大多数网卡都支持此功能
		 */
		if (!(rt->dst.dev->features&NETIF_F_SG) &&
		    skb_tailroom(skb) >= copy) {
			unsigned int off;

			/* 只能拷贝到线性区 */
			off = skb->len;
			if (getfrag(from, skb_put(skb, copy),
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}

		/* 设备支持S/G IO 时，将数据拷贝到skb的frags page数组中。 */
		} else if (!uarg || !uarg->zerocopy) {
			int i = skb_shinfo(skb)->nr_frags;

			err = -ENOMEM;

			/* 申请skb frag buffer */
			if (!sk_page_frag_refill(sk, pfrag))
				goto error;

			/* 检查页面是否可以合并 */
			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				err = -EMSGSIZE;
				if (i == MAX_SKB_FRAGS)
					goto error;

				__skb_fill_page_desc(skb, i, pfrag->page,
						     pfrag->offset, 0);
				skb_shinfo(skb)->nr_frags = ++i;
				get_page(pfrag->page);
			}

			/* 将数据拷贝到skb的frags[]数组中 */
			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			if (getfrag(from,
				    page_address(pfrag->page) + pfrag->offset,
				    offset, copy, skb->len, skb) < 0)
				goto error_efault;

			pfrag->offset += copy;
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			wmem_alloc_delta += copy;
		} else {
			err = skb_zerocopy_iter_dgram(skb, from, copy);
			if (err < 0)
				goto error;
		}

		/* 更新偏移和剩余要拷贝的数据量 */
		offset += copy;
		length -= copy;
	}

	if (wmem_alloc_delta)
		refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
	return 0;

error_efault:
	err = -EFAULT;

	/* 出错处理，将length从cork中减去。 */
error:
	if (uarg)
		sock_zerocopy_put_abort(uarg, extra_uref);
	cork->length -= length;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
	return err;
}

static int ip_setup_cork(struct sock *sk, struct inet_cork *cork,
			 struct ipcm_cookie *ipc, struct rtable **rtp)
{
	struct ip_options_rcu *opt;
	struct rtable *rt;

	rt = *rtp;
	if (unlikely(!rt))
		return -EFAULT;

	/*
	 * setup for corking.
	 */
	opt = ipc->opt;
	if (opt) {
		if (!cork->opt) {
			cork->opt = kmalloc(sizeof(struct ip_options) + 40,
					    sk->sk_allocation);
			if (unlikely(!cork->opt))
				return -ENOBUFS;
		}
		memcpy(cork->opt, &opt->opt, sizeof(struct ip_options) + opt->opt.optlen);
		cork->flags |= IPCORK_OPT;
		cork->addr = ipc->addr;
	}

	/*
	 * We steal reference to this route, caller should not release it
	 */
	*rtp = NULL;
	cork->fragsize = ip_sk_use_pmtu(sk) ?
			 dst_mtu(&rt->dst) : rt->dst.dev->mtu;

	/* 设置udp的gso size，通过cork设置 */
	cork->gso_size = ipc->gso_size;
	cork->dst = &rt->dst;
	cork->length = 0;
	cork->ttl = ipc->ttl;
	cork->tos = ipc->tos;
	cork->priority = ipc->priority;
	cork->transmit_time = ipc->sockc.transmit_time;
	cork->tx_flags = 0;
	sock_tx_timestamp(sk, ipc->sockc.tsflags, &cork->tx_flags);

	return 0;
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 */
/*
 * 设计目标：将要发送的数据按照便于ip分片的方式组织成一个一个的skb，它并不负责实际的发送，
 * 调用者需要主动调用 ip_push_pending_frames() 接口进行实际的发送。
 * 调用者可以通过连续多次调用该函数将多个数据片段合并成一个大的ip报文，这里要注意ip报文和ip片段的不同。
 * 传输层可以通过该函数组织一个很大的ip报文，但是，该函数会负责根据MTU将其分割成一个一个的skb，所以，
 * skb是和ip片段一一对应的，即一个skb的载荷部分当然不能超过MTU。
 * 
 */
int ip_append_data(struct sock *sk, struct flowi4 *fl4,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable **rtp,
		   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	int err;

	/* 检查是否从用户传入了 MSG_PROBE 标志。该标志表示用户查询当前是否有数据可读。
	 * 只是做路径探测（例如，确定PMTU） 
	 */
	if (flags & MSG_PROBE)
		return 0;

	/* 检查 socket 的发送队列是否为空。如果为空，意味着没有 cork 数据等待处理，
	 * 因此调用ip_setup_cork 来设置 corking 
	 */
	if (skb_queue_empty(&sk->sk_write_queue)) {
		err = ip_setup_cork(sk, &inet->cork.base, ipc, rtp);
		if (err)
			return err;
	} else {
		transhdrlen = 0;
	}

	/* 用于将数据处理成数据包的大量逻辑 */
	return __ip_append_data(sk, fl4, &sk->sk_write_queue, &inet->cork.base,
				sk_page_frag(sk), getfrag,
				from, length, transhdrlen, flags);
}

ssize_t	ip_append_page(struct sock *sk, struct flowi4 *fl4, struct page *page,
		       int offset, size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct rtable *rt;
	struct ip_options *opt = NULL;
	struct inet_cork *cork;
	int hh_len;
	int mtu;
	int len;
	int err;
	unsigned int maxfraglen, fragheaderlen, fraggap, maxnonfragsize;

	if (inet->hdrincl)
		return -EPERM;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue))
		return -EINVAL;

	cork = &inet->cork.base;
	rt = (struct rtable *)cork->dst;
	if (cork->flags & IPCORK_OPT)
		opt = cork->opt;

	if (!(rt->dst.dev->features&NETIF_F_SG))
		return -EOPNOTSUPP;

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);
	mtu = cork->gso_size ? IP_MAX_MTU : cork->fragsize;

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;
	maxnonfragsize = ip_sk_ignore_df(sk) ? 0xFFFF : mtu;

	if (cork->length + size > maxnonfragsize - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
			       mtu - (opt ? opt->optlen : 0));
		return -EMSGSIZE;
	}

	skb = skb_peek_tail(&sk->sk_write_queue);
	if (!skb)
		return -EINVAL;

	cork->length += size;

	while (size > 0) {
		/* Check if the remaining data fits into current packet. */
		len = mtu - skb->len;
		if (len < size)
			len = maxfraglen - skb->len;

		if (len <= 0) {
			struct sk_buff *skb_prev;
			int alloclen;

			skb_prev = skb;
			fraggap = skb_prev->len - maxfraglen;

			alloclen = fragheaderlen + hh_len + fraggap + 15;
			skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
			if (unlikely(!skb)) {
				err = -ENOBUFS;
				goto error;
			}

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			skb_put(skb, fragheaderlen + fraggap);
			skb_reset_network_header(skb);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(skb_prev,
								   maxfraglen,
						    skb_transport_header(skb),
								   fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		if (len > size)
			len = size;

		if (skb_append_pagefrags(skb, page, offset, len)) {
			err = -EMSGSIZE;
			goto error;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			__wsum csum;
			csum = csum_page(page, offset, len);
			skb->csum = csum_block_add(skb->csum, csum, skb->len);
		}

		skb->len += len;
		skb->data_len += len;
		skb->truesize += len;
		refcount_add(len, &sk->sk_wmem_alloc);
		offset += len;
		size -= len;
	}
	return 0;

error:
	cork->length -= size;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

static void ip_cork_release(struct inet_cork *cork)
{
	/* 主要是路由和IP选项 */
	cork->flags &= ~IPCORK_OPT;
	kfree(cork->opt);
	cork->opt = NULL;
	dst_release(cork->dst);
	cork->dst = NULL;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
struct sk_buff *__ip_make_skb(struct sock *sk,
			      struct flowi4 *fl4,
			      struct sk_buff_head *queue,
			      struct inet_cork *cork)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = (struct rtable *)cork->dst;
	struct iphdr *iph;
	__be16 df = 0;
	__u8 ttl;

	skb = __skb_dequeue(queue);
	if (!skb)
		goto out;

	/* 下面是将多个skb，采用frag_list的方式来合成一个大的skb。
	 * 该skb只有一个udp header和ip header。
	 * 所以，要将其余的skb的header部分去掉。
	 */
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));

	while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
		__skb_pull(tmp_skb, skb_network_header_len(skb));
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	skb->ignore_df = ip_sk_ignore_df(sk);


	/* 下面是构造IP报文首部 */
	/* DF bit is set when we want to see DF on outgoing frames.
	 * If ignore_df is set too, we still allow to fragment this frame
	 * locally. */
	 /* PMTU相关 */
	if (inet->pmtudisc == IP_PMTUDISC_DO ||
	    inet->pmtudisc == IP_PMTUDISC_PROBE ||
	    (skb->len <= dst_mtu(&rt->dst) &&
	     ip_dont_fragment(sk, &rt->dst)))
		df = htons(IP_DF);

	if (cork->flags & IPCORK_OPT)
		opt = cork->opt;

	if (cork->ttl != 0)
		ttl = cork->ttl;
	else if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->dst);

	/* 填充ip header部分。 */
	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = (cork->tos != -1) ? cork->tos : inet->tos;
	iph->frag_off = df;
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);
	ip_select_ident(net, skb, sk);

	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, cork->addr, rt, 0);
	}

	/* 设定skb带外信息，如priority, mark, tstamp等。*/
	skb->priority = (cork->tos != -1) ? cork->priority: sk->sk_priority;
	skb->mark = sk->sk_mark;
	skb->tstamp = cork->transmit_time;
	/*
	 * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
	 * on dst refcount
	 */
	cork->dst = NULL;
	skb_dst_set(skb, &rt->dst);

	if (iph->protocol == IPPROTO_ICMP)
		icmp_out_count(net, ((struct icmphdr *)
			skb_transport_header(skb))->type);

	ip_cork_release(cork);
out:
	return skb;
}

/*The UDP protocol layer hands skbs down to the IP protocol by simply calling ip_send_skb,
so let’s start there and map out the IP protocol layer!*/
int ip_send_skb(struct net *net, struct sk_buff *skb)
{
	int err;

	err = ip_local_out(net, skb->sk, skb);
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	return err;
}

/* RAW_SOCKET, ICMP等 都是用该接口，将用户数据发送到IP layer中。 */
int ip_push_pending_frames(struct sock *sk, struct flowi4 *fl4)
{
	struct sk_buff *skb;

	skb = ip_finish_skb(sk, fl4);
	if (!skb)
		return 0;

	/* Netfilter gets whole the not fragmented skb. */
	return ip_send_skb(sock_net(sk), skb);
}

/*
 *	Throw away all pending data on the socket.
 */
static void __ip_flush_pending_frames(struct sock *sk,
				      struct sk_buff_head *queue,
				      struct inet_cork *cork)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(queue)) != NULL)
		kfree_skb(skb);

	ip_cork_release(cork);
}

void ip_flush_pending_frames(struct sock *sk)
{
	__ip_flush_pending_frames(sk, &sk->sk_write_queue, &inet_sk(sk)->cork.base);
}

struct sk_buff *ip_make_skb(struct sock *sk,
			    struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags)
{
	struct sk_buff_head queue;
	int err;

	if (flags & MSG_PROBE)
		return NULL;

	/* 栈变量，初始化一个新的 tx            skb list，用于后续管理用户拷贝的skb。 */
	__skb_queue_head_init(&queue);

	/* 这里的cork变量也是上层传入的一个栈变量，里面会承载一些ipc，rtable等信息，给到下层api使用。 */
	cork->flags = 0;
	cork->addr = 0;
	cork->opt = NULL;
	err = ip_setup_cork(sk, cork, ipc, rtp);
	if (err)
		return ERR_PTR(err);

	/* 会申请新的skb buffer，并拷贝user data，并把该skb添加到传入的queue中。
	 * 如果追加数据失败，则调用__ip_flush_pending_frames()丢弃数据并向上返回错误。
	 */
	err = __ip_append_data(sk, fl4, &queue, cork,
			       &current->task_frag, getfrag,
			       from, length, transhdrlen, flags);
	if (err) {
		/* 清除发送队列
		 * 如果__ip_append_data()遇到异常，那么需要将之前已经构造成功且放入发送队列的skb全部清除。 
		 */
		__ip_flush_pending_frames(sk, &queue, cork);
		return ERR_PTR(err);
	}

	/* 如果追加数据成功，则将skb出队，并添加IP选项，并返回一个准备好传递给更底层发送的skb。 */
	return __ip_make_skb(sk, fl4, &queue, cork);
}

/*
 *	Fetch data from kernel space and fill in checksum if needed.
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset,
			      int len, int odd, struct sk_buff *skb)
{
	__wsum csum;

	csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
	skb->csum = csum_block_add(skb->csum, csum, odd);
	return 0;
}

/*
 *	Generic function to send a packet as reply to another packet.
 *	Used to send some TCP resets/acks so far.
 */
void ip_send_unicast_reply(struct sock *sk, struct sk_buff *skb,
			   const struct ip_options *sopt,
			   __be32 daddr, __be32 saddr,
			   const struct ip_reply_arg *arg,
			   unsigned int len)
{
	struct ip_options_data replyopts;
	struct ipcm_cookie ipc;
	struct flowi4 fl4;
	struct rtable *rt = skb_rtable(skb);
	struct net *net = sock_net(sk);
	struct sk_buff *nskb;
	int err;
	int oif;

	if (__ip_options_echo(net, &replyopts.opt.opt, skb, sopt))
		return;

	ipcm_init(&ipc);
	ipc.addr = daddr;

	if (replyopts.opt.opt.optlen) {
		ipc.opt = &replyopts.opt;

		if (replyopts.opt.opt.srr)
			daddr = replyopts.opt.opt.faddr;
	}

	oif = arg->bound_dev_if;
	if (!oif && netif_index_is_l3_master(net, skb->skb_iif))
		oif = skb->skb_iif;

	flowi4_init_output(&fl4, oif,
			   IP4_REPLY_MARK(net, skb->mark) ?: sk->sk_mark,
			   RT_TOS(arg->tos),
			   RT_SCOPE_UNIVERSE, ip_hdr(skb)->protocol,
			   ip_reply_arg_flowi_flags(arg),
			   daddr, saddr,
			   tcp_hdr(skb)->source, tcp_hdr(skb)->dest,
			   arg->uid);
	security_skb_classify_flow(skb, flowi4_to_flowi(&fl4));
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return;

	inet_sk(sk)->tos = arg->tos;

	sk->sk_priority = skb->priority;
	sk->sk_protocol = ip_hdr(skb)->protocol;
	sk->sk_bound_dev_if = arg->bound_dev_if;
	sk->sk_sndbuf = sysctl_wmem_default;
	sk->sk_mark = fl4.flowi4_mark;
	err = ip_append_data(sk, &fl4, ip_reply_glue_bits, arg->iov->iov_base,
			     len, 0, &ipc, &rt, MSG_DONTWAIT);
	if (unlikely(err)) {
		ip_flush_pending_frames(sk);
		goto out;
	}

	nskb = skb_peek(&sk->sk_write_queue);
	if (nskb) {
		if (arg->csumoffset >= 0)
			*((__sum16 *)skb_transport_header(nskb) +
			  arg->csumoffset) = csum_fold(csum_add(nskb->csum,
								arg->csum));
		nskb->ip_summed = CHECKSUM_NONE;
		ip_push_pending_frames(sk, &fl4);
	}
out:
	ip_rt_put(rt);
}

void __init ip_init(void)
{
	/* 初始化 路由子系统 route table  */
	ip_rt_init();

	/* 初始化 peer    subsystem for ip or route 
		两个ip建立连接，即这两个ip称为一个peer。
	*/
	inet_initpeers();

	/* IP 组播初始化 */
#if defined(CONFIG_IP_MULTICAST)
	igmp_mc_init();
#endif
}
