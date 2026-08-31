// hide_procfs_dir.h
#ifndef _HIDE_PROCFS_DIR_H_
#define _HIDE_PROCFS_DIR_H_

#include "ver_control.h"
#include "arch_support.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <asm/cacheflush.h>
#include <linux/proc_fs.h>

// 隐藏的目录名称
static char g_hide_dir_name[256] = {0};
static bool g_is_hooked = false;

// 声明 proc_dir_entry 的基本结构（根据内核版本可能需要调整）
struct my_proc_dir_entry {
    unsigned int low_ino;
    unsigned short namelen;
    const char *name;
    mode_t mode;
    nlink_t nlink;
    uid_t uid;
    gid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *next;
    struct proc_dir_entry *parent;
    struct proc_dir_entry *subdir;
    void *data;
    atomic_t count;
    atomic_t in_use;
    struct completion *pde_unload_completion;
    struct list_head pde_openers;
};

// 获取 proc_root 的替代方法
static struct proc_dir_entry *get_proc_root(void)
{
    struct proc_dir_entry *proc_root = NULL;
    
    // 尝试通过 kallsyms 查找 proc_root
    proc_root = (struct proc_dir_entry *)kallsyms_lookup_name("proc_root");
    if (proc_root) {
        return proc_root;
    }
    
    // 如果找不到，尝试其他可能的符号名
    proc_root = (struct proc_dir_entry *)kallsyms_lookup_name("proc_root_dentry");
    if (proc_root) {
        return proc_root;
    }
    
    printk_debug("[hide_procfs_dir] proc_root not found\n");
    return NULL;
}

// 查找 proc 条目的简化版本
static struct proc_dir_entry *my_proc_find(const char *name, struct proc_dir_entry *parent)
{
    struct proc_dir_entry *pde;
    struct my_proc_dir_entry *mpde;
    
    if (!parent) {
        parent = get_proc_root();
        if (!parent) {
            return NULL;
        }
    }
    
    // 转换为我们的结构以访问成员
    mpde = (struct my_proc_dir_entry *)parent;
    
    // 遍历链表查找目标
    for (pde = mpde->subdir; pde != NULL; pde = ((struct my_proc_dir_entry *)pde)->next) {
        struct my_proc_dir_entry *current_entry = (struct my_proc_dir_entry *)pde;
        if (current_entry->name && strcmp(current_entry->name, name) == 0) {
            return pde;
        }
    }
    
    return NULL;
}

// 简单方法：直接遍历 proc 目录并移除目标条目
static bool start_hide_procfs_dir_simple(const char* hide_dir_name)
{
    struct proc_dir_entry *pde;
    struct my_proc_dir_entry *mpde;
    struct my_proc_dir_entry *prev_entry = NULL;
    struct my_proc_dir_entry *current_entry = NULL;
    
    if (g_is_hooked) {
        return true;
    }
    
    strlcpy(g_hide_dir_name, hide_dir_name, sizeof(g_hide_dir_name));
    
    // 查找要隐藏的 proc 条目
    pde = my_proc_find(g_hide_dir_name, NULL);
    if (pde) {
        mpde = (struct my_proc_dir_entry *)pde;
        
        // 从父目录的子节点列表中移除
        if (mpde->parent) {
            struct my_proc_dir_entry *parent_mpde = (struct my_proc_dir_entry *)mpde->parent;
            
            // 遍历链表找到并移除目标节点
            prev_entry = NULL;
            current_entry = (struct my_proc_dir_entry *)parent_mpde->subdir;
            
            while (current_entry) {
                if (current_entry == mpde) {
                    if (prev_entry) {
                        prev_entry->next = current_entry->next;
                    } else {
                        parent_mpde->subdir = current_entry->next;
                    }
                    break;
                }
                prev_entry = current_entry;
                current_entry = (struct my_proc_dir_entry *)current_entry->next;
            }
        }
        
        g_is_hooked = true;
        printk_debug("[hide_procfs_dir] Removed proc entry: %s\n", g_hide_dir_name);
        return true;
    }
    
    printk_debug("[hide_procfs_dir] Proc entry not found: %s\n", g_hide_dir_name);
    return false;
}

static void stop_hide_procfs_dir_simple(void)
{
    if (g_is_hooked) {
        printk_debug("[hide_procfs_dir] Simple hide removed\n");
        g_is_hooked = false;
    }
}

static bool start_hide_procfs_dir(const char* hide_dir_name)
{
    return start_hide_procfs_dir_simple(hide_dir_name);
}

static void stop_hide_procfs_dir(void)
{
    stop_hide_procfs_dir_simple();
}

#endif // _HIDE_PROCFS_DIR_H_
