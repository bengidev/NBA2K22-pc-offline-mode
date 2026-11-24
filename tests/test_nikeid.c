#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int call_nikeid_guard(void* obj) {
    uint64_t rbx0, rbp0, rsi0, rdi0, r12_0, r13_0, r14_0, r15_0;
    uint64_t rbx1, rbp1, rsi1, rdi1, r12_1, r13_1, r14_1, r15_1;
    int ret;
    __asm__ volatile (
        "mov %%rbx, %0\n\t"
        "mov %%rbp, %1\n\t"
        "mov %%rsi, %2\n\t"
        "mov %%r12, %3\n\t"
        "mov %%r13, %4\n\t"
        "mov %%r14, %5\n\t"
        "mov %%r15, %6\n\t"
        : "=m"(rbx0), "=m"(rbp0), "=m"(rsi0), "=m"(r12_0), "=m"(r13_0), "=m"(r14_0), "=m"(r15_0)
    );
    rdi0 = (uint64_t)obj;
    __asm__ volatile (
        "mov %2, %%rdi\n\t"
        "call _nikeid_f8_guard_test\n\t"
        : "=a"(ret), "=D"(rdi1)
        : "r"(obj)
        : "rcx", "rdx", "r9", "r10", "cc", "memory"
    );
    __asm__ volatile (
        "mov %%rbx, %0\n\t"
        "mov %%rbp, %1\n\t"
        "mov %%rsi, %2\n\t"
        "mov %%r12, %3\n\t"
        "mov %%r13, %4\n\t"
        "mov %%r14, %5\n\t"
        "mov %%r15, %6\n\t"
        : "=m"(rbx1), "=m"(rbp1), "=m"(rsi1), "=m"(r12_1), "=m"(r13_1), "=m"(r14_1), "=m"(r15_1)
    );
    assert(rbx0 == rbx1 && rbp0 == rbp1 && rsi0 == rsi1 && rdi0 == rdi1);
    assert(r12_0 == r12_1 && r13_0 == r13_1 && r14_0 == r14_1 && r15_0 == r15_1);
    return ret;
}

int main(void) {
    uint8_t obj[0x120];
    uint8_t arr[0x100];

    // 1. cnt == 0 -> skip (0)
    memset(obj, 0, sizeof(obj));
    assert(call_nikeid_guard(obj) == 0);

    // 2. cnt == 3, arr == NULL -> clear (0)
    memset(obj, 0, sizeof(obj));
    *(int32_t*)(obj + 0xf8) = 3;
    assert(call_nikeid_guard(obj) == 0);
    assert(*(int32_t*)(obj + 0xf8) == 0);
    assert(*(uint64_t*)(obj + 0x100) == 0);

    // 3. Synthetic valid v1.0: cnt == 2, arr[0].rel == 0x29 (0x29 + 7 == 0x30 == 2 * 0x18) -> v1.0 (1)
    memset(obj, 0, sizeof(obj));
    memset(arr, 0, sizeof(arr));
    *(int32_t*)(obj + 0xf8) = 2;
    *(uint64_t*)(obj + 0x100) = (uint64_t)arr;
    *(int64_t*)(arr + 8) = 0x29;
    assert(call_nikeid_guard(obj) == 1);
    assert(*(int32_t*)(obj + 0xf8) == 2);
    assert(*(uint64_t*)(obj + 0x100) == (uint64_t)arr);

    // 4. Synthetic negative offset v1.0: cnt == 2, arr[0].rel == -0x20 -> v1.0 (1)
    *(int64_t*)(arr + 8) = -0x20;
    assert(call_nikeid_guard(obj) == 1);
    assert(*(int32_t*)(obj + 0xf8) == 2);
    assert(*(uint64_t*)(obj + 0x100) == (uint64_t)arr);

    // 5. 2029_style pattern: cnt == 8, arr[0].rel == 0x79 -> clear (0)
    *(int32_t*)(obj + 0xf8) = 8;
    *(int64_t*)(arr + 8) = 0x79;
    assert(call_nikeid_guard(obj) == 0);
    assert(*(int32_t*)(obj + 0xf8) == 0);
    assert(*(uint64_t*)(obj + 0x100) == 0);

    // 6. 8008_style pattern: cnt == 5, arr[0].rel == 0x49 -> clear (0)
    *(int32_t*)(obj + 0xf8) = 5;
    *(uint64_t*)(obj + 0x100) = (uint64_t)arr;
    *(int64_t*)(arr + 8) = 0x49;
    assert(call_nikeid_guard(obj) == 0);
    assert(*(int32_t*)(obj + 0xf8) == 0);
    assert(*(uint64_t*)(obj + 0x100) == 0);

    // 7. Optional stdin stream of real .NikeIdStyle files: [u32 len][bytes...]
    uint32_t sz = 0;
    int files_tested = 0;
    int cleared_count = 0;
    while (fread(&sz, 4, 1, stdin) == 1) {
        uint8_t* buf = (uint8_t*)malloc(sz);
        assert(buf != NULL);
        assert(fread(buf, 1, sz, stdin) == sz);
        // Simulate 0x140920230..0x140920245 fixup of [rdi + 0x100]
        uint64_t raw100 = *(uint64_t*)(buf + 0x100);
        if (raw100 != 0) {
            *(uint64_t*)(buf + 0x100) = (uint64_t)(buf + 0xff + raw100);
        }
        int32_t orig_cnt = *(int32_t*)(buf + 0xf8);
        int r = call_nikeid_guard(buf);
        if (orig_cnt > 0) {
            assert(r == 0);
            assert(*(int32_t*)(buf + 0xf8) == 0);
            assert(*(uint64_t*)(buf + 0x100) == 0);
            cleared_count++;
        } else {
            assert(r == 0);
        }
        free(buf);
        files_tested++;
    }

    printf("ALL NIKEID TESTS PASSED: edge_cases=6, real_nikeid_files=%d, cleared=%d\n",
           files_tested, cleared_count);
    return 0;
}
