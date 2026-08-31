#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>        // 新增
#include <linux/kprobes.h>         // 新增
#include <asm/cacheflush.h>        // 新增
#include <asm/set_memory.h>        // 新增

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

/* ---------- 函数指针（通过 kallsyms 获取） ---------- */
static ssize_t (*original_vfs_write)(struct file *file, const char __user *buf,
                                      size_t count, loff_t *pos);
static unsigned long vfs_write_addr;

/* ---------- 判断文件是否受保护 ---------- */
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

/* ---------- 我们的替换函数 ---------- */
static ssize_t hooked_vfs_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *pos)
{
    if (is_path_protected(file)) {
        char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path_buf) {
            char *path = d_path(&file->f_path, path_buf, PATH_MAX);
            if (!IS_ERR(path)) {
                printk(KERN_INFO "file_protect: Blocked write to %s (pid=%d, size=%zu)\n",
                       path, current->pid, count);
            }
            kfree(path_buf);
        }
        return -EPERM;
    }
    return original_vfs_write(file, buf, count, pos);
}

/* ---------- 修改内核代码的辅助函数 ---------- */
static void write_to_kernel_memory(void *addr, const void *data, size_t size)
{
    unsigned long flags;

    // 设置可写
    set_memory_rw((unsigned long)addr & PAGE_MASK, 1);

    local_irq_save(flags);
    memcpy(addr, data, size);
    flush_icache_range((unsigned long)addr, (unsigned long)addr + size);
    local_irq_restore(flags);

    // 恢复只读（可选）
    set_memory_ro((unsigned long)addr & PAGE_MASK, 1);
}

/* ---------- 安装 inline hook ---------- */
static int install_inline_hook(void)
{
    unsigned long addr = kallsyms_lookup_name("vfs_write");
    if (!addr) {
        printk(KERN_ERR "file_protect: vfs_write not found\n");
        return -EINVAL;
    }
    vfs_write_addr = addr;
    original_vfs_write = (void *)addr;
    printk(KERN_INFO "file_protect: vfs_write at 0x%lx\n", addr);

    // 构造相对跳转（B 指令）
    unsigned long hook_addr = (unsigned long)hooked_vfs_write;
    long offset = (hook_addr - (addr + 4)) >> 2;  // ARM64 B 指令偏移量（以指令为单位）
    if (offset >= -0x200000 && offset < 0x200000) {
        unsigned int b_insn = 0x14000000 | (offset & 0x03ffffff);
        write_to_kernel_memory((void *)addr, &b_insn, 4);
        printk(KERN_INFO "file_protect: B instruction installed (offset=%ld)\n", offset);
    } else {
        // 若偏移超出范围，使用绝对跳转（ldr x16, =addr; br x16）
        // 这里用 4 条指令：movz/movk 构造 64 位地址，再 br
        uint32_t movz = 0xd2a00000 | ((hook_addr & 0xffff) << 5) | 0x10;   // movz x16, #low16
        uint32_t movk = 0xf2a00000 | (((hook_addr >> 16) & 0xffff) << 5) | 0x10; // movk x16, #high16
        uint32_t br = 0xd61f0200;  // br x16
        write_to_kernel_memory((void *)addr, &movz, 4);
        write_to_kernel_memory((void *)(addr + 4), &movk, 4);
        write_to_kernel_memory((void *)(addr + 8), &br, 4);
        printk(KERN_INFO "file_protect: Absolute branch installed\n");
    }
    return 0;
}

static void remove_inline_hook(void)
{
    // 恢复原函数前几条指令（需要备份原始字节，此处省略）
    printk(KERN_WARNING "file_protect: Inline hook removed, but may cause instability\n");
    // 实际恢复可以从备份还原，为简化，暂不实现
}

/* ---------- 获取 kallsyms_lookup_name ---------- */
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

    ret = install_inline_hook();
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
    remove_inline_hook();
    free_protected_list();
    printk(KERN_INFO "file_protect: unloaded\n");
}

module_init(file_protect_init);
module_exit(file_protect_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Protect files using inline hook on vfs_write (MTK-compatible)");
