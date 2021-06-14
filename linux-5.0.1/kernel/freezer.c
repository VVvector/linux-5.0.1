/*
 * kernel/freezer.c - Function to freeze a process
 *
 * Originally from kernel/power/process.c
 */

#include <linux/interrupt.h>
#include <linux/suspend.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/freezer.h>
#include <linux/kthread.h>

/* total number of freezing conditions in effect */
atomic_t system_freezing_cnt = ATOMIC_INIT(0);
EXPORT_SYMBOL(system_freezing_cnt);

/* indicate whether PM freezing is in effect, protected by
 * system_transition_mutex
 */
bool pm_freezing;
bool pm_nosig_freezing;

/*
 * Temporary export for the deadlock workaround in ata_scsi_hotplug().
 * Remove once the hack becomes unnecessary.
 */
EXPORT_SYMBOL_GPL(pm_freezing);

/* protects freezing and frozen transitions */
static DEFINE_SPINLOCK(freezer_lock);

/**
 * freezing_slow_path - slow path for testing whether a task needs to be frozen
 * @p: task to be tested
 *
 * This function is called by freezing() if system_freezing_cnt isn't zero
 * and tests whether @p needs to enter and stay in frozen state.  Can be
 * called under any context.  The freezers are responsible for ensuring the
 * target tasks see the updated state.
 */
bool freezing_slow_path(struct task_struct *p)
{
	/* (PF_NOFREEZE | PF_SUSPEND_TASK) 当前进程不能被 freeze */
	if (p->flags & (PF_NOFREEZE | PF_SUSPEND_TASK))
		return false;

	if (test_tsk_thread_flag(p, TIF_MEMDIE))
		return false;

	/* 如果 pm_nosig_freezing 为 true，内核进程 freeze 已经开始，
	 * 当前进程可以被 freeze 
	 */
	if (pm_nosig_freezing || cgroup_freezing(p))
		return true;

	/* 如果 pm_freezing 为 true，且当前进程为用户进程
	 * 当前进程可以被 freeze
	 */
	if (pm_freezing && !(p->flags & PF_KTHREAD))
		return true;

	return false;
}
EXPORT_SYMBOL(freezing_slow_path);

/* Refrigerator is place where frozen processes are stored :-). */
bool __refrigerator(bool check_kthr_stop)
{
	/* Hmm, should we be allowed to suspend when there are realtime
	   processes around? */
	bool was_frozen = false;
	long save = current->state;

	pr_debug("%s entered refrigerator\n", current->comm);

	for (;;) {
		/* 设置当前进程进入 TASK_UNINTERRUPTIBLE阻塞状态 */
		set_current_state(TASK_UNINTERRUPTIBLE);

		spin_lock_irq(&freezer_lock);
		/* 设置已freeze的标志 */
		current->flags |= PF_FROZEN;

		/* 检查是否可以对当前进程进行freeze，如果不可以，则还原。 */
		if (!freezing(current) ||
		    (check_kthr_stop && kthread_should_stop()))
			current->flags &= ~PF_FROZEN;
		spin_unlock_irq(&freezer_lock);

		if (!(current->flags & PF_FROZEN))
			break;
		was_frozen = true;

		/* 将本进程切换出去，即调度不再调度该进程，即休眠了。 */
		schedule();
	}

	pr_debug("%s left refrigerator\n", current->comm);

	/*
	 * Restore saved task state before returning.  The mb'd version
	 * needs to be used; otherwise, it might silently break
	 * synchronization which depends on ordered task state change.
	 */
	set_current_state(save);

	return was_frozen;
}
EXPORT_SYMBOL(__refrigerator);

static void fake_signal_wake_up(struct task_struct *p)
{
	unsigned long flags;

	if (lock_task_sighand(p, &flags)) {
		signal_wake_up(p, 0);
		unlock_task_sighand(p, &flags);
	}
}

/**
 * freeze_task - send a freeze request to given task
 * @p: task to send the request to
 *
 * If @p is freezing, the freeze request is sent either by sending a fake
 * signal (if it's not a kernel thread) or waking it up (if it's a kernel
 * thread).
 *
 * RETURNS:
 * %false, if @p is not freezing or already frozen; %true, otherwise
 */
bool freeze_task(struct task_struct *p)
{
	unsigned long flags;

	/*
	 * This check can race with freezer_do_not_count, but worst case that
	 * will result in an extra wakeup being sent to the task.  It does not
	 * race with freezer_count(), the barriers in freezer_count() and
	 * freezer_should_skip() ensure that either freezer_count() sees
	 * freezing == true in try_to_freeze() and freezes, or
	 * freezer_should_skip() sees !PF_FREEZE_SKIP and freezes the task
	 * normally.
	 */
	if (freezer_should_skip(p))
		return false;

	spin_lock_irqsave(&freezer_lock, flags);
	/* 检查当前进程是否可以被freeze，或者是否已经被freeze。 */
	if (!freezing(p) || frozen(p)) {
		spin_unlock_irqrestore(&freezer_lock, flags);
		return false;
	}

	/* 如果是用户进程，伪造一个signal发送给进程。 */
	if (!(p->flags & PF_KTHREAD))
		fake_signal_wake_up(p);
	else
		wake_up_state(p, TASK_INTERRUPTIBLE); //内核进程，则wake up内核进程。

	/* 注：
	 * 如果进程阻塞在信号量、mutex 等内核同步机制上，wake_up_state 并不能解除阻塞。
	 * 因为这些机制都有 while(1) 循环来判断条件，是否成立，不成立只是简单的唤醒随即又会进入阻塞睡眠状态
	 * 它只能唤醒类似下面这种简单的阻塞内核进程。
	 	while (1) {
	 		set_current_state(TASK_UNINTERRUPTIBLE);
			schedule();
	 	}
	 * 而内核进程响应freeze操作，也必须显式调用 try_to_freeze()或者kthread_freezable_should_stop()
	 * 来freeze自己。类似：
	 	void user_thread() {
			while (!kthread_should_stop()) {
				try_to_freeze();
			}	
	 	}

	 * 即 从代码逻辑上看 内核进程freeze，并不会freeze所有内核进程，只freeze了两部分：
	 * 1. 设置了WQ_FREEZABLE标志的workqueue。
	 * 2. 内核进程主动调用了try_to_freeze()并在架构上设计了可以响应freeze。
	 */

	spin_unlock_irqrestore(&freezer_lock, flags);
	return true;
}

void __thaw_task(struct task_struct *p)
{
	unsigned long flags;

	spin_lock_irqsave(&freezer_lock, flags);
	if (frozen(p))
		wake_up_process(p);
	spin_unlock_irqrestore(&freezer_lock, flags);
}

/**
 * set_freezable - make %current freezable
 *
 * Mark %current freezable and enter refrigerator if necessary.
 */
bool set_freezable(void)
{
	might_sleep();

	/*
	 * Modify flags while holding freezer_lock.  This ensures the
	 * freezer notices that we aren't frozen yet or the freezing
	 * condition is visible to try_to_freeze() below.
	 */
	spin_lock_irq(&freezer_lock);
	current->flags &= ~PF_NOFREEZE;
	spin_unlock_irq(&freezer_lock);

	return try_to_freeze();
}
EXPORT_SYMBOL(set_freezable);
