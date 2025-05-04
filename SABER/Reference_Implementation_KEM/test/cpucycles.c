#include <stdint.h>

#if defined(__APPLE__)
#include <mach/mach_time.h>
uint64_t cpucycles(void) {
    return mach_absolute_time();
}
#else
uint64_t cpucycles(void) {
    uint64_t result;
    __asm__ __volatile__ ("rdtsc" : "=a" (result) :: "%rdx");
    return result;
}
#endif
