#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/cpumask.h>
#include <linux/sched/task.h>

#define GAME_UID 10302

static struct kprobe kp_cgroup_fork;
static unsigned long (*set_cpus_allowed_ptr_sym)(struct task_struct *, const struct cpumask *);

/* 复用的 kallsyms 查找（和你 file_copy.c 一样） */
static unsigned long (*kallsyms_lookup_name_sym)(const char *name);
static int dummy_pre(struct kprobe *p, struct pt_regs *regs) { return 0; }
static unsigned long get_kallsyms_addr(void) {
    struct kprobe probe = { .pre_handler = dummy_pre, .symbol_name = "kallsyms_lookup_name" };
    unsigned long addr;
    if (register_kprobe(&probe)) return 0;
    addr = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    return addr;
}
static unsigned long my_kallsyms_lookup(const char *name) {
    if (!kallsyms_lookup_name_sym) {
        kallsyms_lookup_name_sym = (void *)get_kallsyms_addr();
        if (!kallsyms_lookup_name_sym) return 0;
    }
    return kallsyms_lookup_name_sym(name);
}

/* cgroup_post_fork 的 kprobe 回调 */
static int cgroup_fork_handler(struct kprobe *p, struct pt_regs *regs) {
    struct task_struct *child = (struct task_struct *)regs->regs[0]; /* arm64: x0 */
    const struct cred *cred;
    uid_t uid;

    if (!child) return 0;

    rcu_read_lock();
    cred = __task_cred(child);
    uid = __kuid_val(cred->uid);
    rcu_read_unlock();

    if (uid == GAME_UID) {
        cpumask_t mask;
        pr_info("cpuset_hook: child pid=%d uid=%d match\n",
                child->pid, uid);
        cpumask_clear(&mask);
        cpumask_set_cpu(7, &mask);  /* 只绑到 CPU7，按需改 */
        if (set_cpus_allowed_ptr_sym)
            set_cpus_allowed_ptr_sym(child, &mask);
        else
            pr_err("cpuset_hook: set_cpus_allowed_ptr not found\n");
    }
    return 0;
}

static int __init cpuset_hook_init(void) {
    unsigned long addr;

    addr = my_kallsyms_lookup("set_cpus_allowed_ptr");
    if (!addr) {
        pr_err("cpuset_hook: set_cpus_allowed_ptr not found\n");
        return -ENXIO;
    }
    set_cpus_allowed_ptr_sym = (void *)addr;
    pr_info("cpuset_hook: set_cpus_allowed_ptr @ %px\n", (void *)addr);

    kp_cgroup_fork.symbol_name = "cgroup_post_fork";
    kp_cgroup_fork.pre_handler = cgroup_fork_handler;

    if (register_kprobe(&kp_cgroup_fork)) {
        pr_err("cpuset_hook: register_kprobe(cgroup_post_fork) failed\n");
        return -ENXIO;
    }
    pr_info("cpuset_hook: loaded, GAME_UID=%d\n", GAME_UID);
    return 0;
}

static void __exit cpuset_hook_exit(void) {
    unregister_kprobe(&kp_cgroup_fork);
    pr_info("cpuset_hook: unloaded\n");
}

module_init(cpuset_hook_init);
module_exit(cpuset_hook_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hook cgroup_post_fork to set affinity for game threads");
