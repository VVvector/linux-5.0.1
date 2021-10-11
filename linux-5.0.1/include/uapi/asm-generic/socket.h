/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_GENERIC_SOCKET_H
#define __ASM_GENERIC_SOCKET_H

#include <asm/sockios.h>

/* For setsockopt(2) */
#define SOL_SOCKET	1

/* 网络模块的日志输出控制 */
#define SO_DEBUG	1

/* 默认情况下，socket不会和一个正在使用的端口绑定到一起，但是，在少数情况下需要，来实现端口复用。
 * 1. 当有一个socket1处于TIME_WAIT状态，而socket2要占用socket1的地址和端口，则进程就要用到该选项。
 * 2. SO_REUSEADDR 运行同一个端口上启动同一个服务器的多个实例（多个进程）。但是，每个实例绑定的ip
 * 地址不能相同。
 * 3. SO_REUSEADDR 允许完全相同的地址和端口的重复绑定。
 */
#define SO_REUSEADDR	2

/* 获取socket的类型，例如，SOCK_DGRAM, SOCK_STREAM */
#define SO_TYPE		3

/* 返回socket的错误代码。 */
#define SO_ERROR	4

/* 使能此选项时，则无需查询路由表 ，直接通过socket绑定的那个网络接口将数据传送出去。
 * 通常采用默认设置，即发送时会经过路由过程。SOCK_LOCALROUTE
 */
#define SO_DONTROUTE	5

/* 使能socket能收发广播消息，只对非SOCK_STREAM类型有效。 */
#define SO_BROADCAST	6

/* 配置发送和接收的缓存区大小 */
#define SO_SNDBUF	7
#define SO_RCVBUF	8
#define SO_SNDBUFFORCE	32
#define SO_RCVBUFFORCE	33

/* 运行tcp套接口在tcp连接上发送“保活”数据包 */
#define SO_KEEPALIVE	9

/* 使能此选项后，可在带外数据中加入正常数据流，或在普通数据流中接收带外数据。 */
#define SO_OOBINLINE	10
#define SO_NO_CHECK	11

/* 设置发送或者转发的QoS类别，sk_priority */
#define SO_PRIORITY	12

/* 设置或获取当前关闭套接口的延迟时间。即影响close()时，对尚未发送的数据的处理。 */
#define SO_LINGER	13
#define SO_BSDCOMPAT	14
#define SO_REUSEPORT	15
#ifndef SO_PASSCRED /* powerpc only differs in these */
#define SO_PASSCRED	16
#define SO_PEERCRED	17

/* 设置发送和接收的最小缓存值。以及timeout */
#define SO_RCVLOWAT	18
#define SO_SNDLOWAT	19
#define SO_RCVTIMEO	20
#define SO_SNDTIMEO	21
#endif

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION		22
#define SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define SO_SECURITY_ENCRYPTION_NETWORK		24

#define SO_BINDTODEVICE	25

/* Socket filtering */
#define SO_ATTACH_FILTER	26
#define SO_DETACH_FILTER	27
#define SO_GET_FILTER		SO_ATTACH_FILTER

#define SO_PEERNAME		28

/* 如果设置为true，则将数据包接收时间作为时间戳。 */
#define SO_TIMESTAMP		29
#define SCM_TIMESTAMP		SO_TIMESTAMP

#define SO_ACCEPTCONN		30

#define SO_PEERSEC		31
#define SO_PASSSEC		34
#define SO_TIMESTAMPNS		35
#define SCM_TIMESTAMPNS		SO_TIMESTAMPNS

#define SO_MARK			36

#define SO_TIMESTAMPING		37
#define SCM_TIMESTAMPING	SO_TIMESTAMPING

#define SO_PROTOCOL		38
#define SO_DOMAIN		39

#define SO_RXQ_OVFL             40

#define SO_WIFI_STATUS		41
#define SCM_WIFI_STATUS	SO_WIFI_STATUS
#define SO_PEEK_OFF		42

/* Instruct lower device to use last 4-bytes of skb data as FCS */
#define SO_NOFCS		43

#define SO_LOCK_FILTER		44

#define SO_SELECT_ERR_QUEUE	45

#define SO_BUSY_POLL		46

#define SO_MAX_PACING_RATE	47

#define SO_BPF_EXTENSIONS	48

#define SO_INCOMING_CPU		49

#define SO_ATTACH_BPF		50
#define SO_DETACH_BPF		SO_DETACH_FILTER

#define SO_ATTACH_REUSEPORT_CBPF	51
#define SO_ATTACH_REUSEPORT_EBPF	52

#define SO_CNX_ADVICE		53

#define SCM_TIMESTAMPING_OPT_STATS	54

#define SO_MEMINFO		55

#define SO_INCOMING_NAPI_ID	56

#define SO_COOKIE		57

#define SCM_TIMESTAMPING_PKTINFO	58

#define SO_PEERGROUPS		59

#define SO_ZEROCOPY		60

#define SO_TXTIME		61
#define SCM_TXTIME		SO_TXTIME

#endif /* __ASM_GENERIC_SOCKET_H */
