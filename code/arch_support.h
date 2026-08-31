// arch_support.h
#ifndef ARCH_SUPPORT_H_
#define ARCH_SUPPORT_H_

#include <linux/types.h>
#include <linux/cache.h>

#if defined(__aarch64__)
static inline unsigned long my_read_cr0(void) {
    unsigned long val;
    asm volatile("mrs %0, sctlr_el1" : "=r" (val));
    return val;
}

static inline void my_write_cr0(unsigned long val) {
    asm volatile("msr sctlr_el1, %0" :: "r" (val));
    asm volatile("isb");
}
#elif defined(__arm__)
static inline unsigned long my_read_cr0(void) {
    unsigned long val;
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r" (val));
    return val;
}

static inline void my_write_cr0(unsigned long val) {
    asm volatile("mcr p15, 0, %0, c1, c0, 0" :: "r" (val));
    asm volatile("isb");
}
#endif

static inline size_t my_cache_line_size(void) {
#if defined(__aarch64__)
    u64 ctr;
    asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
    return 4 << ((ctr >> 16) & 0xF);
#else
    return L1_CACHE_BYTES;
#endif
}

#endif /* ARCH_SUPPORT_H_ */
