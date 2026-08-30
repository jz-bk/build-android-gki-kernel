// code/hollo.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

// 模块初始化函数（内核启动时执行）
static int __init hollo_init(void)
{
    // 打印到内核日志，可用 dmesg 查看
    pr_info("Hollo, Android Kernel! Module loaded successfully.\n");
    return 0; // 返回 0 表示初始化成功
}

// 模块退出函数（模块卸载或关机时执行）
static void __exit hollo_exit(void)
{
    pr_info("Goodbye from Hollo! Module unloaded.\n");
}

// 注册入口和出口函数
module_init(hollo_init);
module_exit(hollo_exit);

// 模块信息（必须包含，否则编译会报 warning）
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JZ");
MODULE_DESCRIPTION("A simple hollo driver for Android kernel");
