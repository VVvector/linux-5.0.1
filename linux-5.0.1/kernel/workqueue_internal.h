/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel/workqueue_internal.h
 *
 * Workqueue internal header file.  Only to be included by workqueue and
 * core kernel subsystems.
 */
#ifndef _KERNEL_WORKQUEUE_INTERNAL_H
#define _KERNEL_WORKQUEUE_INTERNAL_H

#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/preempt.h>

struct worker_pool;

/*
 * The poor guys doing the actual heavy lifting.  All on-duty workers are
 * either serving the manager role, on idle list or on busy hash.  For
 * details on the locking annotation (L, I, X...), refer to workqueue.c.
 *
 * Only to be used in workqueue and async.
 */

/*
 * 每个 worker 对应一个 worker_thread() 内核线程，一个 worker_pool 对应一个或者多个 worker。
 * 多个 worker 从同一个链表中 worker_pool->worklist 获取 work 进行处理。
 * 所以这其中有几个重点：
 * 	1. worker 怎么处理 work - 处理 work 的过程主要在 worker_thread() -> process_one_work() 中处理。
 *	2. worker_pool 怎么动态管理 worker 的数量；
 *	worker_pool 怎么来动态增减 worker，这部分的算法是 CMWQ 的核心。其思想如下：
 *		1. worker_pool 中的 worker 有 3 种状态：idle、running、suspend；
 *		2. 如果 worker_pool 中有 work 需要处理，保持至少一个 running worker 来处理；
 *		3. running worker 在处理 work 的过程中进入了阻塞 suspend 状态，为了保持其他 
 *		4. work 的执行，需要唤醒新的 idle worker 来处理 work；
 *		5. 如果有 work 需要执行且 running worker 大于 1 个，会让多余的 running worker 进入 idle 状态；
 *		6. 如果没有 work 需要执行，会让所有 worker 进入 idle 状态；
 *		7. 如果创建的 worker 过多，destroy_worker 在 300s(IDLE_WORKER_TIMEOUT) 时间内没有再次运行的 idle worker。
 *	
 *	1. 为了追踪 worker 的 running 和 suspend 状态，用来动态调整 worker 的数量。
 	wq 使用在进程调度中加钩子函数的技巧：
 *		1. 追踪 worker 从 suspend 进入 running 状态：ttwu_activate() -> wq_worker_waking_up()
 *		2. 追踪 worker 从 running 进入 suspend 状态：__schedule() -> wq_worker_sleeping()
 *
 *	但是这里有一个问题如果 work 是 CPU 密集型的，它虽然也没有进入 suspend 状态，
 *	但是会长时间的占用 CPU，让后续的 work 阻塞太长时间。
 *	为了解决这个问题，CMWQ 设计了 WQ_CPU_INTENSIVE，如果一个 wq 声明自己是 CPU_INTENSIVE，
 *	则让当前 worker 脱离动态调度，像是进入了 suspend 状态，那么 CMWQ 会创建新的 worker，后续的 work 会得到执行。
 */
struct worker {
	/* on idle list while idle, on busy hash table while busy */
	union {
		/* 当该worker idle时，被添加到worker_pool的空闲队列中。 */
		struct list_head	entry;	/* L: while idle */
		/* 当该worker_busy时，被添加到worker_pool的忙碌队列中。 */
		struct hlist_node	hentry;	/* L: while busy */
	};

	/* 当前正在处理的work */
	struct work_struct	*current_work;	/* L: work being processed */
	/* 当前正在执行的work回调函数 */
	work_func_t		current_func;	/* L: current_work's fn */
	/* 当前执行work所属的pool_workqueue */
	struct pool_workqueue	*current_pwq; /* L: current_work's pwq */

	/* 所有被调度执行的work都将被添加到该链表中 */
	struct list_head	scheduled;	/* L: scheduled works */

	/* 64 bytes boundary on 64bit, 32 on 32bit */

	/* 指向内核线程 */
	struct task_struct	*task;		/* I: worker task */
	/* 该worker所属的worker_pool */
	struct worker_pool	*pool;		/* A: the associated pool */
						/* L: for rescuers */

	/* 添加到worker_pool->workers链表中 */
	struct list_head	node;		/* A: anchored at pool->workers */
						/* A: runs through worker->node */

	unsigned long		last_active;	/* L: last active timestamp */
	unsigned int		flags;		/* X: flags */
	int			id;		/* I: worker id */

	/*
	 * Opaque string set with work_set_desc().  Printed out with task
	 * dump for debugging - WARN, BUG, panic or sysrq.
	 */
	char			desc[WORKER_DESC_LEN];

	/* used only by rescuers to point to the target workqueue */
	struct workqueue_struct	*rescue_wq;	/* I: the workqueue to rescue */

	/* used by the scheduler to determine a worker's last known identity */
	work_func_t		last_func;
};

/**
 * current_wq_worker - return struct worker if %current is a workqueue worker
 */
static inline struct worker *current_wq_worker(void)
{
	if (in_task() && (current->flags & PF_WQ_WORKER))
		return kthread_data(current);
	return NULL;
}

/*
 * Scheduler hooks for concurrency managed workqueue.  Only to be used from
 * sched/ and workqueue.c.
 */
void wq_worker_waking_up(struct task_struct *task, int cpu);
struct task_struct *wq_worker_sleeping(struct task_struct *task);
work_func_t wq_worker_last_func(struct task_struct *task);

#endif /* _KERNEL_WORKQUEUE_INTERNAL_H */
