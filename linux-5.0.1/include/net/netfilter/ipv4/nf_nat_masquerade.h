/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_NAT_MASQUERADE_IPV4_H_
#define _NF_NAT_MASQUERADE_IPV4_H_

#include <net/netfilter/nf_nat.h>

/*
 * NAT 模块
 * 一般配置方式：Change IP1 to IP2 if matching XXX。
 * 高级配置方式：Change IP1 to dev1's IP if matching XXX，这种方式称为 Masquerade。
 *
 * Masquerade 优缺点：
 * 优点：当设备（网卡）的 IP 地址发生变化时，NAT 规则无需做任何修改。
 * 缺点：性能比第一种方式要差。
 */


unsigned int
nf_nat_masquerade_ipv4(struct sk_buff *skb, unsigned int hooknum,
		       const struct nf_nat_range2 *range,
		       const struct net_device *out);

int nf_nat_masquerade_ipv4_register_notifier(void);
void nf_nat_masquerade_ipv4_unregister_notifier(void);

#endif /*_NF_NAT_MASQUERADE_IPV4_H_ */
