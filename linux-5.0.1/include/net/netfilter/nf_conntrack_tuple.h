/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Definitions and Declarations for tuple.
 *
 * 16 Dec 2003: Yasuyuki Kozakai @USAGI <yasuyuki.kozakai@toshiba.co.jp>
 *	- generalize L3 protocol dependent part.
 *
 * Derived from include/linux/netfiter_ipv4/ip_conntrack_tuple.h
 */

#ifndef _NF_CONNTRACK_TUPLE_H
#define _NF_CONNTRACK_TUPLE_H

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/list_nulls.h>

/* A `tuple' is a structure containing the information to uniquely
  identify a connection.  ie. if two packets have the same tuple, they
  are in the same connection; if not, they are not.

  We divide the structure along "manipulatable" and
  "non-manipulatable" lines, for the benefit of the NAT code.
*/

#define NF_CT_TUPLE_L3SIZE	ARRAY_SIZE(((union nf_inet_addr *)NULL)->all)

/* The manipulable part of the tuple. */
struct nf_conntrack_man {
	union nf_inet_addr u3;
	/* 协议相关 */
	union nf_conntrack_man_proto u;
	/* Layer 3 protocol */
	u_int16_t l3num;
};

/* This contains the information to distinguish a connection. */
/* 定义一个 tuple, 一个tuple定义一个单项flow (unidirectional) 
 * 为方便 NAT 的实现，内核将 tuple 结构体拆分为 "manipulatable" 和 "non-manipulatable" 两部分。
 * Tuple 结构体中只有两个字段 src 和 dst，分别保存源和目的信息。src 和 dst 自身也是结构体，能保存不同类型协议的数据。
 *
 * 从定义可以看出，连接跟踪模块目前只支持以下六种协议：TCP、UDP、ICMP、DCCP、SCTP、GRE。
 * 注： ICMP 使用了其头信息中的 ICMP type和 code 字段来 定义 tuple。
 */
struct nf_conntrack_tuple {
	/* 源地址信息 */
	struct nf_conntrack_man src;

	/* 目的地址信息 */
	/* These are the parts of the tuple which are fixed. */
	struct {
		union nf_inet_addr u3;
		union {
			/* Add other protocols here. */
			__be16 all;

			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				u_int8_t type, code;
			} icmp;
			struct {
				__be16 port;
			} dccp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;

		/* The protocol. */
		u_int8_t protonum;

		/* The direction (for tuplehash) */
		u_int8_t dir;
	} dst;
};

struct nf_conntrack_tuple_mask {
	struct {
		union nf_inet_addr u3;
		union nf_conntrack_man_proto u;
	} src;
};

static inline void nf_ct_dump_tuple_ip(const struct nf_conntrack_tuple *t)
{
#ifdef DEBUG
	printk("tuple %p: %u %pI4:%hu -> %pI4:%hu\n",
	       t, t->dst.protonum,
	       &t->src.u3.ip, ntohs(t->src.u.all),
	       &t->dst.u3.ip, ntohs(t->dst.u.all));
#endif
}

static inline void nf_ct_dump_tuple_ipv6(const struct nf_conntrack_tuple *t)
{
#ifdef DEBUG
	printk("tuple %p: %u %pI6 %hu -> %pI6 %hu\n",
	       t, t->dst.protonum,
	       t->src.u3.all, ntohs(t->src.u.all),
	       t->dst.u3.all, ntohs(t->dst.u.all));
#endif
}

static inline void nf_ct_dump_tuple(const struct nf_conntrack_tuple *t)
{
	switch (t->src.l3num) {
	case AF_INET:
		nf_ct_dump_tuple_ip(t);
		break;
	case AF_INET6:
		nf_ct_dump_tuple_ipv6(t);
		break;
	}
}

/* If we're the first tuple, it's the original dir. */
#define NF_CT_DIRECTION(h)						\
	((enum ip_conntrack_dir)(h)->tuple.dst.dir)

/* 哈希表(conntrack table)中的表项(entry)。
 * conntrack将活动连接的状态存储在一张哈希表中。
 * 用hash_conntrack_raw()根据tuple计算出一个32位的哈希值。
 * 每条连接在哈希表中都对应两项，分别对应两个方向（egress/ingress）
 */
/* Connections have two entries in the hash table: one for each way */
struct nf_conntrack_tuple_hash {
	/* 指向该哈希对应的连接 struct nf_conn，采用 list 形式是为了解决哈希冲突 */
	struct hlist_nulls_node hnnode;

	/* N 元组 */
	struct nf_conntrack_tuple tuple;
};

static inline bool __nf_ct_tuple_src_equal(const struct nf_conntrack_tuple *t1,
					   const struct nf_conntrack_tuple *t2)
{ 
	return (nf_inet_addr_cmp(&t1->src.u3, &t2->src.u3) &&
		t1->src.u.all == t2->src.u.all &&
		t1->src.l3num == t2->src.l3num);
}

static inline bool __nf_ct_tuple_dst_equal(const struct nf_conntrack_tuple *t1,
					   const struct nf_conntrack_tuple *t2)
{
	return (nf_inet_addr_cmp(&t1->dst.u3, &t2->dst.u3) &&
		t1->dst.u.all == t2->dst.u.all &&
		t1->dst.protonum == t2->dst.protonum);
}

static inline bool nf_ct_tuple_equal(const struct nf_conntrack_tuple *t1,
				     const struct nf_conntrack_tuple *t2)
{
	return __nf_ct_tuple_src_equal(t1, t2) &&
	       __nf_ct_tuple_dst_equal(t1, t2);
}

static inline bool
nf_ct_tuple_mask_equal(const struct nf_conntrack_tuple_mask *m1,
		       const struct nf_conntrack_tuple_mask *m2)
{
	return (nf_inet_addr_cmp(&m1->src.u3, &m2->src.u3) &&
		m1->src.u.all == m2->src.u.all);
}

static inline bool
nf_ct_tuple_src_mask_cmp(const struct nf_conntrack_tuple *t1,
			 const struct nf_conntrack_tuple *t2,
			 const struct nf_conntrack_tuple_mask *mask)
{
	int count;

	for (count = 0; count < NF_CT_TUPLE_L3SIZE; count++) {
		if ((t1->src.u3.all[count] ^ t2->src.u3.all[count]) &
		    mask->src.u3.all[count])
			return false;
	}

	if ((t1->src.u.all ^ t2->src.u.all) & mask->src.u.all)
		return false;

	if (t1->src.l3num != t2->src.l3num ||
	    t1->dst.protonum != t2->dst.protonum)
		return false;

	return true;
}

static inline bool
nf_ct_tuple_mask_cmp(const struct nf_conntrack_tuple *t,
		     const struct nf_conntrack_tuple *tuple,
		     const struct nf_conntrack_tuple_mask *mask)
{
	return nf_ct_tuple_src_mask_cmp(t, tuple, mask) &&
	       __nf_ct_tuple_dst_equal(t, tuple);
}

#endif /* _NF_CONNTRACK_TUPLE_H */
