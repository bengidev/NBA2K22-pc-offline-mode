.intel_syntax noprefix
.text

// Test wrapper: takes rdi = NikeIdStyle* (called via inline asm in test_nikeid.c)
// Returns eax = 0 on skip/clear, eax = 1 on v1.0 path.
.globl _nikeid_f8_guard_test
_nikeid_f8_guard_test:
    movsxd rcx, dword ptr [rdi + 0xf8]
    test rcx, rcx
    jle Ltest_skip
    mov r9, qword ptr [rdi + 0x100]
    test r9, r9
    jz Ltest_clear
    mov rax, qword ptr [r9 + 8]
    test rax, rax
    jz Ltest_v10
    add rax, 7
    imul rdx, rcx, 0x18
    cmp rax, rdx
    jae Ltest_v10

Ltest_clear:
    mov dword ptr [rdi + 0xf8], 0
    mov qword ptr [rdi + 0x100], 0

Ltest_skip:
    xor eax, eax
    ret

Ltest_v10:
    xor r10d, r10d
    mov eax, 1
    ret
