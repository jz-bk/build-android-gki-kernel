#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/cpumask.h>
#include <linux/sched/task.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/uidgid.h>

#define GAME_PKG    "com.tencent.ig"

/* ---------------- kallsyms 查找 ---------------- */
static unsigned long (*kallsyms_lookup_name_sym)(const char *name);

static int dummy_pre(struct kprobe *p, struct pt_regs *regs) { return 0; }

static unsigned long get_kallsyms_addr(void)
{
    struct kprobe probe = {
        .pre_handler = dummy_pre,
        .symbol_name = "kallsyms_lookup_name",
    };
    unsigned long addr;

    if (register_kprobe(&probe))
        return 0;
    addr = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    return addr;
}

static unsigned long my_kallsyms_lookup(const char *name)
{
    if (!kallsyms_lookup_name_sym) {
        kallsyms_lookup_name_sym = (void *)get_kallsyms_addr();
        if (!kallsyms_lookup_name_sym)
            return 0;
    }
    return kallsyms_lookup_name_sym(name);
}

/* ---------------- 全局变量 ---------------- */
static struct kprobe kp_cgroup_fork;
static unsigned long (*set_cpus_allowed_ptr_sym)(struct task_struct *,
                                                 const struct cpumask *);
static uid_t g_game_uid = (uid_t)-1;

/* ---------------- 规则表 ---------------- */
struct thread_rule {
    const char *name;
    cpumask_t mask;
};

/* 4-7 -> 0xF0，0-6 -> 0x7F */
static struct thread_rule rules[] = {
    { "UEGameThread",    { .bits = { 0xF0 } } },
    { "RHIThread",       { .bits = { 0xF0 } } },
    { "RenderThread",    { .bits = { 0xF0 } } },
    { "TaskGraphNP",     { .bits = { 0xF0 } } },
    { "mali-event-hand", { .bits = { 0xF0 } } },
    { "mali-cpu-comman", { .bits = { 0xF0 } } },
    { "NativeThread",    { .bits = { 0xF0 } } },
};

static cpumask_t default_mask = { .bits = { 0x7F } };   /* 0-6 */

/* 最长前缀优先 */
static struct thread_rule *pick_rule(const char *comm)
{
    struct thread_rule *best = NULL;
    size_t best_len = 0;
    int i;

    for (i = 0; i < ARRAY_SIZE(rules); i++) {
        size_t len = strlen(rules[i].name);
        if (strncmp(comm, rules[i].name, len) == 0 && len > best_len) {
            best = &rules[i];
            best_len = len;
        }
    }
    return best;
}

/* ---------------- 包名 -> UID（init 阶段，可睡眠） ---------------- */
static uid_t resolve_pkg_uid(const char *pkg)
{
    char path[256];
    struct path p;
    uid_t uid = (uid_t)-1;

    snprintf(path, sizeof(path), "/data/data/%s", pkg);
    if (kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
        uid = __kuid_val(p.dentry->d_inode->i_uid);
        path_put(&p);
    }
    return uid;
}

/* ---------------- kprobe 回调 ---------------- */
static int cgroup_fork_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *child = (struct task_struct *)regs->regs[0];
    const struct cred *cred;
    uid_t uid;
    const struct cpumask *mask;
    struct thread_rule *r;
    int ret;

    if (!child)
        return 0;

    rcu_read_lock();
    cred = __task_cred(child);
    uid = __kuid_val(cred->uid);
    rcu_read_unlock();

    if (uid != g_game_uid)
        return 0;

    r = pick_rule(child->comm);
    mask = r ? &r->mask : &default_mask;

    ret = set_cpus_allowed_ptr_sym(child, mask);
    if (ret)
        pr_err("cpuset_hook: pid=%d comm=%s ret=%d\n",
               child->pid, child->comm, ret);
    else if (r)
        pr_info("cpuset_hook: pid=%d comm=%s -> rule\n",
                child->pid, child->comm);

    return 0;
}

/* ---------------- 模块入口 ---------------- */
static int __init cpuset_hook_init(void)
{
    unsigned long addr;

    addr = my_kallsyms_lookup("set_cpus_allowed_ptr");
    if (!addr) {
        pr_err("cpuset_hook: set_cpus_allowed_ptr not found\n");
        return -ENXIO;
    }
    set_cpus_allowed_ptr_sym = (void *)addr;
    pr_info("cpuset_hook: set_cpus_allowed_ptr @ %px\n", (void *)addr);

    g_game_uid = resolve_pkg_uid(GAME_PKG);
    if (g_game_uid == (uid_t)-1) {
        pr_err("cpuset_hook: cannot resolve UID for %s\n", GAME_PKG);
        return -ENOENT;
    }
    pr_info("cpuset_hook: %s -> uid=%d\n", GAME_PKG, g_game_uid);

    kp_cgroup_fork.symbol_name = "cgroup_post_fork";
    kp_cgroup_fork.pre_handler = cgroup_fork_handler;

    if (register_kprobe(&kp_cgroup_fork)) {
        pr_err("cpuset_hook: register_kprobe(cgroup_post_fork) failed\n");
        return -ENXIO;
    }

    pr_info("cpuset_hook: loaded\n");
    return 0;
}

static void __exit cpuset_hook_exit(void)
{
    unregister_kprobe(&kp_cgroup_fork);
    pr_info("cpuset_hook: unloaded\n");
}

module_init(cpuset_hook_init);
module_exit(cpuset_hook_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hook cgroup_post_fork to set affinity for game threads");
