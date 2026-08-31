#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/version.h>
#include <linux/kprobes.h>          // 新增：提供 struct kprobe 和 kprobe API
#include <linux/errname.h>          // 可选

/* ---------- 参数配置 ---------- */
static char *protected_paths = "/data/protected.txt";
module_param(protected_paths, charp, 0644);
MODULE_PARM_DESC(protected_paths, "Comma-separated list of absolute file paths to protect");

/* ---------- 存储保护路径的链表 ---------- */
struct protected_entry {
    char *path;
    struct list_head list;
};
static LIST_HEAD(protected_list);

/* ---------- 用于 kretprobe 的全局变量 ---------- */
static struct kretprobe krp;
static int (*original_security_file_permission)(struct file *file, int mask);

/* ---------- 路径检查函数 ---------- */
static int is_path_protected(struct file *file)
{
    char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf)
        return 0;

    char *path = d_path(&file->f_path, path_buf, PATH_MAX);
    if (IS_ERR(path)) {
        kfree(path_buf);
        return 0;
    }

    struct protected_entry *entry;
    int found = 0;
    list_for_each_entry(entry, &protected_list, list) {
        if (strcmp(path, entry->path) == 0) {
            found = 1;
            break;
        }
    }
    kfree(path_buf);
    return found;
}

/* ---------- kretprobe 处理函数 ---------- */
static int security_file_permission_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // 获取函数返回值（原本存在 regs->regs[0] 中，ARM64 为 x0）
    int ret = (int)regs->regs[0];

    // 如果返回值已经是错误（可能已有其他限制），我们不再覆盖
    if (ret < 0)
        return 0;

    // 获取第一个参数（struct file *file）
    struct file *file = (struct file *)regs->regs[0];
    // 获取第二个参数（int mask）
    int mask = (int)regs->regs[1];

    // 如果是写请求且文件在保护列表中，则拒绝
    if ((mask & MAY_WRITE) && is_path_protected(file)) {
        printk(KERN_INFO "file_protect: Blocked write to %s (pid=%d)\n",
               d_path(&file->f_path, (char *)__builtin_alloca(PATH_MAX), PATH_MAX),
               current->pid);
        regs->regs[0] = -EPERM;   // 修改返回值
        return 1;                 // 表示已修改
    }
    return 0;
}

/* ---------- 获取 kallsyms_lookup_name 函数指针 ---------- */
static unsigned long (*kallsyms_lookup_name_func)(const char *name);

static int get_kallsyms_lookup_name(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    struct kprobe kp;
    int ret;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "file_protect: Failed to register kprobe for kallsyms_lookup_name\n");
        return -EINVAL;
    }
    kallsyms_lookup_name_func = (void *)kp.addr;
    unregister_kprobe(&kp);
#else
    kallsyms_lookup_name_func = &kallsyms_lookup_name;
#endif
    if (!kallsyms_lookup_name_func) {
        printk(KERN_ERR "file_protect: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    return 0;
}

/* ---------- 注册 kretprobe ---------- */
static int install_hook(void)
{
    unsigned long addr;

    // 获取 security_file_permission 的地址
    addr = kallsyms_lookup_name_func("security_file_permission");
    if (!addr) {
        printk(KERN_ERR "file_protect: security_file_permission symbol not found\n");
        return -EINVAL;
    }
    original_security_file_permission = (void *)addr;

    // 设置 kretprobe
    krp.kp.symbol_name = "security_file_permission";
    krp.handler = security_file_permission_ret_handler;
    krp.data_size = 0;  // 不需要额外数据
    krp.maxactive = 20; // 并发调用数

    int ret = register_kretprobe(&krp);
    if (ret < 0) {
        printk(KERN_ERR "file_protect: register_kretprobe failed: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "file_protect: kretprobe registered on security_file_permission\n");
    return 0;
}

static void remove_hook(void)
{
    unregister_kretprobe(&krp);
    printk(KERN_INFO "file_protect: kretprobe unregistered\n");
}

/* ---------- 路径列表解析 ---------- */
static int parse_protected_paths(void)
{
    char *buf, *token;
    int ret = 0;

    if (!protected_paths || !*protected_paths)
        return 0;

    buf = kstrdup(protected_paths, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    while ((token = strsep(&buf, ",")) != NULL) {
        char *p = strim(token);
        if (!*p)
            continue;

        struct protected_entry *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            ret = -ENOMEM;
            break;
        }
        entry->path = kstrdup(p, GFP_KERNEL);
        if (!entry->path) {
            kfree(entry);
            ret = -ENOMEM;
            break;
        }
        list_add_tail(&entry->list, &protected_list);
        printk(KERN_INFO "file_protect: Protecting %s\n", p);
    }
    kfree(buf);
    return ret;
}

static void free_protected_list(void)
{
    struct protected_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &protected_list, list) {
        list_del(&entry->list);
        kfree(entry->path);
        kfree(entry);
    }
}

/* ---------- 模块加载/卸载 ---------- */
static int __init file_protect_init(void)
{
    int ret;

    printk(KERN_INFO "file_protect: initializing...\n");

    ret = parse_protected_paths();
    if (ret < 0) {
        printk(KERN_ERR "file_protect: failed to parse paths\n");
        goto err_free;
    }

    ret = get_kallsyms_lookup_name();
    if (ret < 0) {
        printk(KERN_ERR "file_protect: cannot locate kallsyms_lookup_name\n");
        goto err_free;
    }

    ret = install_hook();
    if (ret < 0) {
        printk(KERN_ERR "file_protect: hook installation failed\n");
        goto err_free;
    }

    printk(KERN_INFO "file_protect: loaded successfully\n");
    return 0;

err_free:
    free_protected_list();
    return ret;
}

static void __exit file_protect_exit(void)
{
    remove_hook();
    free_protected_list();
    printk(KERN_INFO "file_protect: unloaded\n");
}

module_init(file_protect_init);
module_exit(file_protect_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Protect files from any write (using kretprobe on security_file_permission)");
