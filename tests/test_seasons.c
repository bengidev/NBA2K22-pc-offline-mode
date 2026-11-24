#include <assert.h>
#include <stdint.h>
#include <stdio.h>

uint32_t g_seasons_loaded = 0;
uint64_t g_seasons_claimed_level = 0;
uint64_t g_seasons_current_level = 0;

static int g_popup_called = 0;
static uint64_t g_cap_rcx = 0;
static uint64_t g_cap_rdx = 0;
static uint64_t g_cap_r8 = 0;
static uint64_t g_cap_r9 = 0;
static uint64_t g_cap_arg5 = 0;

__attribute__((ms_abi))
void mock_waiting_popup(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9) {
    /* Read 5th Win64 stack arg from caller's frame (above retaddr + 32-byte shadow) */
    uint64_t *sp = (uint64_t *)__builtin_frame_address(0);
    /* Frame: [rbp] = saved rbp, [rbp+8] = retaddr, [rbp+0x10..0x28] = shadow, [rbp+0x30] = arg5 */
    g_popup_called++;
    g_cap_rcx = rcx;
    g_cap_rdx = rdx;
    g_cap_r8 = r8;
    g_cap_r9 = r9;
    g_cap_arg5 = sp[6];
}

extern void call_seasons_guard_with_frame(uint32_t create_status, uint32_t send_status);

static void test_offline_create_failed(void) {
    g_seasons_loaded = 0;
    g_seasons_claimed_level = 99;
    g_seasons_current_level = 40;
    g_popup_called = 0;

    call_seasons_guard_with_frame(0xDEADBEEF, 0xCAFEBABE);

    assert(g_popup_called == 0);
    assert(g_seasons_loaded == 1);
    assert(g_seasons_claimed_level == 0);
    assert(g_seasons_current_level == 0);
}

static void test_offline_send_failed(void) {
    g_seasons_loaded = 0;
    g_seasons_claimed_level = 12;
    g_seasons_current_level = 25;
    g_popup_called = 0;

    call_seasons_guard_with_frame(0x504521A8, 0x80004005);

    assert(g_popup_called == 0);
    assert(g_seasons_loaded == 1);
    assert(g_seasons_claimed_level == 0);
    assert(g_seasons_current_level == 0);
}

static void test_online_passthrough(void) {
    g_seasons_loaded = 0;
    g_seasons_claimed_level = 5;
    g_seasons_current_level = 10;
    g_popup_called = 0;
    g_cap_rcx = g_cap_rdx = g_cap_r8 = g_cap_r9 = g_cap_arg5 = 0;

    call_seasons_guard_with_frame(0x504521A8, 0x504521A8);

    assert(g_popup_called == 1);
    assert(g_cap_rcx == 0x1111222233334444ULL);
    assert(g_cap_rdx == 0x2222333344445555ULL);
    assert(g_cap_r8  == 0x3333444455556666ULL);
    assert(g_cap_r9  == 0x4444555566667777ULL);
    assert(g_cap_arg5 == 0x55ULL);
    assert(g_seasons_loaded == 0);
    assert(g_seasons_claimed_level == 5);
    assert(g_seasons_current_level == 10);
}

int main(void) {
    test_offline_create_failed();
    test_offline_send_failed();
    test_online_passthrough();
    printf("ALL SEASONS GUARD TESTS PASSED\n");
    return 0;
}
