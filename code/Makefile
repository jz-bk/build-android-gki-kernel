# code/Makefile
# 由于上游工作流使用 "obj-y += kerneldriver/" 包含此目录，
# 这里使用 obj-y 将此对象静态链接进内核镜像。
obj-m += hollo.o

# 注意：当此 Makefile 被内核顶层 Kbuild 系统解析时，
# KDIR 会自动指向内核源码根目录，无需额外指定。
# 这里的规则仅供开发者本地测试参考，在 CI 中会被内核构建系统覆盖。
all:
    @echo "This Makefile is designed to be built inside the kernel tree."

clean:
    rm -f *.o *.ko *.mod.c *.mod *.order *.symvers
