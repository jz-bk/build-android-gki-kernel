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

/* ---------- 参数配置 ---------- */
static char *protected_paths = "/data/protected.txt";   // 默认保护文件
module_param(protected_paths, charp, 0644);
MODULE_PARM_DESC(protected_paths, "Comma-separated list of absolute file paths to protect");

/* ---------- 存储保护路径的链表 ---------- */
struct protected_entry {
    char *path;
    struct list_head list;
};
static LIST_HEAD(protected_list);

/* ---------- LSM 钩子拦截 ---------- */
static int (*original_file_permission)(struct file *file, int mask);

static int my_file_permission(struct file *file, int mask)
{
    // 如果请求包含写权限，检查是否在保护列表中
    if (mask & MAY_WRITE) {
        struct protected_entry *entry;
        char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!path_buf)
            goto original;  // 内存不足则放行

        char *path = d_path(&file->f_path, path_buf, PATH_MAX);
        if (IS_ERR(path)) {
            kfree(path_buf);
            goto original;
        }

        // 遍历保护列表
        list_for_each_entry(entry, &protected_list, list) {
            if (strcmp(path, entry->path) == 0) {
                printk(KERN_INFO "file_protect: Blocked write to %s (pid=%d)\n",
                       path, current->pid);
                kfree(path_buf);
                return -EPERM;  // 禁止写入
            }
        }
        kfree(path_buf);
    }

original:
    // 调用原始钩子（如果有）
    if (original_file_permission)
        return original_file_permission(file, mask);
    return 0;  // 无原始钩子则放行
}

/* ---------- 初始化保护列表 ---------- */
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
        char *p = strim(token);  // 去除前后空格
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

/* ---------- 获取 kallsyms_lookup_name 函数指针（跨版本兼容） ---------- */
static unsigned long (*kallsyms_lookup_name_func)(const char *name);

static int get_kallsyms_lookup_name(void)
{
    // 从内核中获取 kallsyms_lookup_name 地址（通过 kprobe）
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    // 内核 >= 5.7 时，kallsyms_lookup_name 未导出，需要通过 kprobe 或直接符号查找
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
    // 旧内核直接使用导出的 kallsyms_lookup_name
    kallsyms_lookup_name_func = &kallsyms_lookup_name;
#endif
    if (!kallsyms_lookup_name_func) {
        printk(KERN_ERR "file_protect: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    return 0;
}

/* ---------- 修改 security_ops ---------- */
static int hook_security_ops(void)
{
    struct security_ops **ops_ptr;
    struct security_ops *ops;

    // 1. 获取 security_ops 的地址
    unsigned long addr = kallsyms_lookup_name_func("security_ops");
    if (!addr) {
        printk(KERN_ERR "file_protect: security_ops symbol not found\n");
        return -EINVAL;
    }
    ops_ptr = (struct security_ops **)addr;
    ops = *ops_ptr;
    if (!ops) {
        printk(KERN_ERR "file_protect: security_ops is NULL\n");
        return -EINVAL;
    }

    // 2. 备份原始 file_permission
    original_file_permission = ops->file_permission;

    // 3. 替换为我们的钩子
    // 注意：安全模块通常使用 rcu 保护，但我们简单替换，不处理并发（生产环境需加锁）
    // 为简化，直接赋值（在持有 write_lock 的情况下，这里省略）
    ops->file_permission = my_file_permission;

    printk(KERN_INFO "file_protect: security_ops hooked, original=0x%px\n",
           original_file_permission);
    return 0;
}

static void unhook_security_ops(void)
{
    unsigned long addr = kallsyms_lookup_name_func("security_ops");
    if (!addr) return;
    struct security_ops **ops_ptr = (struct security_ops **)addr;
    struct security_ops *ops = *ops_ptr;
    if (ops) {
        ops->file_permission = original_file_permission;
        printk(KERN_INFO "file_protect: security_ops restored\n");
    }
}

/* ---------- 模块初始化和退出 ---------- */
static int __init file_protect_init(void)
{
    int ret;

    printk(KERN_INFO "file_protect: initializing...\n");

    // 解析保护路径列表
    ret = parse_protected_paths();
    if (ret < 0) {
        printk(KERN_ERR "file_protect: failed to parse paths\n");
        goto err_free;
    }

    // 获取 kallsyms_lookup_name
    ret = get_kallsyms_lookup_name();
    if (ret < 0) {
        printk(KERN_ERR "file_protect: cannot locate kallsyms_lookup_name\n");
        goto err_free;
    }

    // Hook security_ops
    ret = hook_security_ops();
    if (ret < 0) {
        printk(KERN_ERR "file_protect: hook failed\n");
        goto err_free;
    }

    printk(KERN_INFO "file_protect: loaded successfully, protecting files\n");
    return 0;

err_free:
    free_protected_list();
    return ret;
}

static void __exit file_protect_exit(void)
{
    // 恢复 security_ops
    unhook_security_ops();

    // 释放保护列表
    free_protected_list();

    printk(KERN_INFO "file_protect: unloaded\n");
}

module_init(file_protect_init);
module_exit(file_protect_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Protect specified files from any write operation (including root)");
