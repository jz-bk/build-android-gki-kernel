#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>      // 用于 copy_from_user/copy_to_user
#include <linux/slab.h>         // 用于 kzalloc/kfree

#define FILE_PATH "/tmp/kernel_test.txt"
#define BUFFER_SIZE 256

// 读取文件
static void read_file_example(const char *path) {
    struct file *file;
    char *buffer;
    ssize_t bytes_read;
    loff_t pos = 0;  // 文件偏移量

    // 1. 打开文件（只读）
    file = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open file: %ld\n", PTR_ERR(file));
        return;
    }

    // 2. 分配内核缓冲区
    buffer = kzalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Memory allocation failed\n");
        filp_close(file, NULL);
        return;
    }

    // 3. 读取文件内容
    bytes_read = kernel_read(file, buffer, BUFFER_SIZE - 1, &pos);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';  // 字符串结尾
        printk(KERN_INFO "File content: %s\n", buffer);
    } else {
        printk(KERN_INFO "Read %zd bytes\n", bytes_read);
    }

    // 4. 清理资源
    kfree(buffer);
    filp_close(file, NULL);
}

// 写入文件
static void write_file_example(const char *path, const char *data) {
    struct file *file;
    ssize_t bytes_written;
    loff_t pos = 0;

    // 1. 打开文件（只写，如果不存在则创建，存在则清空）
    file = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open file for writing: %ld\n", PTR_ERR(file));
        return;
    }

    // 2. 写入数据
    bytes_written = kernel_write(file, data, strlen(data), &pos);
    if (bytes_written > 0) {
        printk(KERN_INFO "Written %zd bytes to %s\n", bytes_written, path);
    } else {
        printk(KERN_ERR "Write failed: %zd\n", bytes_written);
    }

    // 3. 关闭文件
    filp_close(file, NULL);
}

// 模块加载函数
static int __init file_ops_init(void) {
    printk(KERN_INFO "File operations module loaded\n");
    
    // 测试写入
    write_file_example(FILE_PATH, "Hello from kernel!\n");
    
    // 测试读取
    read_file_example(FILE_PATH);
    
    return 0;
}

// 模块卸载函数
static void __exit file_ops_exit(void) {
    printk(KERN_INFO "File operations module unloaded\n");
}

module_init(file_ops_init);
module_exit(file_ops_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module demonstrating file operations");
