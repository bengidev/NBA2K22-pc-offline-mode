#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

extern int ptsm_fixup_win64(void *rdx_val);

static int call_ptsm_fixup(void *desc) {
    uint64_t rbx0, rbp0, r12_0, r13_0, r14_0, r15_0;
    uint64_t rbx1, rbp1, r12_1, r13_1, r14_1, r15_1;
    int ret;
    __asm__ volatile (
        "mov %%rbx, %0\n\t"
        "mov %%rbp, %1\n\t"
        "mov %%r12, %2\n\t"
        "mov %%r13, %3\n\t"
        "mov %%r14, %4\n\t"
        "mov %%r15, %5\n\t"
        : "=m"(rbx0), "=m"(rbp0), "=m"(r12_0), "=m"(r13_0), "=m"(r14_0), "=m"(r15_0)
    );
    __asm__ volatile (
        "mov %1, %%rdx\n\t"
        "call _ptsm_fixup\n\t"
        : "=a"(ret)
        : "r"(desc)
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
    __asm__ volatile (
        "mov %%rbx, %0\n\t"
        "mov %%rbp, %1\n\t"
        "mov %%r12, %2\n\t"
        "mov %%r13, %3\n\t"
        "mov %%r14, %4\n\t"
        "mov %%r15, %5\n\t"
        : "=m"(rbx1), "=m"(rbp1), "=m"(r12_1), "=m"(r13_1), "=m"(r14_1), "=m"(r15_1)
    );
    assert(rbx0 == rbx1 && rbp0 == rbp1 && r12_0 == r12_1 && r13_0 == r13_1 && r14_0 == r14_1 && r15_0 == r15_1);
    return ret;
}

typedef struct {
    uint64_t pad[3];
    void *hdr;
} ResourceDesc;

int main(void) {
    // 1. Edge case: hdr == NULL -> returns 0
    ResourceDesc d_null = {{0,0,0}, NULL};
    assert(call_ptsm_fixup(&d_null) == 0);

    // 2. Edge case: num_groups == 0
    uint8_t buf0[0x30] = {0};
    *(uint64_t *)(buf0 + 0x08) = 0x29;
    *(uint64_t *)(buf0 + 0x18) = 0x19;
    *(uint32_t *)(buf0 + 0x20) = 0x30;
    ResourceDesc d0 = {{0,0,0}, buf0};
    assert(call_ptsm_fixup(&d0) == 1);

    // 3. Edge case: synthetic v1.0 (0x210) with count=2
    uint8_t buf_v10[0x30 + 0xf0 * 2 + 0x210] = {0};
    *(uint64_t *)(buf_v10 + 0x00) = 2;
    *(uint64_t *)(buf_v10 + 0x08) = 0x29;
    *(uint64_t *)(buf_v10 + 0x10) = 1;
    *(uint64_t *)(buf_v10 + 0x18) = 0x1f9;
    *(uint32_t *)(buf_v10 + 0x20) = sizeof(buf_v10);
    uint8_t *g_v10 = buf_v10 + 0x210;
    *(uint32_t *)(g_v10 + 0) = 42;
    *(uint32_t *)(g_v10 + 0x208) = 2;
    *(int64_t *)(g_v10 + 8) = 0x30 - (0x210 + 8) + 1;
    *(int64_t *)(g_v10 + 16) = 0x120 - (0x210 + 16) + 1;
    ResourceDesc d_v10 = {{0,0,0}, buf_v10};
    assert(call_ptsm_fixup(&d_v10) == 1);
    assert(*(uint64_t *)(g_v10 + 8) == (uint64_t)(buf_v10 + 0x30));
    assert(*(uint64_t *)(g_v10 + 16) == (uint64_t)(buf_v10 + 0x120));

    // 4. Stdin stream of raw .PTSM files: [u32 len][bytes...]
    uint32_t sz = 0;
    int files_tested = 0;
    while (fread(&sz, 4, 1, stdin) == 1) {
        uint8_t *buf = (uint8_t *)malloc(sz);
        assert(buf != NULL);
        assert(fread(buf, 1, sz, stdin) == sz);
        uint32_t num_m = *(uint32_t *)(buf + 0x00);
        uint32_t num_g = *(uint32_t *)(buf + 0x10);

        ResourceDesc desc = {{0,0,0}, buf};
        int r = call_ptsm_fixup(&desc);
        assert(r == 1);

        uint8_t *markers = *(uint8_t **)(buf + 0x08);
        uint8_t *groups  = *(uint8_t **)(buf + 0x18);
        assert(markers == buf + 0x30);

        // Simulate v1.0 copy constructor 0x1418d6a20
        uint8_t *ptr_table[107] = {0};
        uint32_t cnt_table[107] = {0};
        for (uint32_t i = 0; i < num_g; i++) {
            uint8_t *g = groups + i * 0x210;
            int32_t gid = *(int32_t *)g;
            int32_t gcnt = *(int32_t *)(g + 0x208);
            assert(gid >= 0 && gid < 107);
            assert(gcnt >= 0 && gcnt <= 64);
            for (int32_t k = 0; k < gcnt; k++) {
                uint64_t p = *(uint64_t *)(g + 8 + k * 8);
                assert(p >= (uint64_t)markers && p < (uint64_t)(markers + num_m * 0xf0));
                assert((p - (uint64_t)markers) % 0xf0 == 0);
            }
            for (int32_t k = gcnt; k < 64; k++) {
                assert(*(uint64_t *)(g + 8 + k * 8) == 0);
            }
            if (gcnt > 0) ptr_table[gid] = g;
        }
        for (uint32_t i = 0; i < num_m; i++) {
            int32_t gid = *(int32_t *)(markers + i * 0xf0 + 0xe0);
            assert(gid >= 0 && gid < 107);
            assert(ptr_table[gid] != NULL);
            cnt_table[gid]++;
            assert(cnt_table[gid] <= 64);
        }
        free(buf);
        files_tested++;
    }
    printf("ALL TESTS PASSED: edge_cases=3, real_ptsm_files=%d\n", files_tested);
    return 0;
}
