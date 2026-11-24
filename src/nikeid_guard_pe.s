.intel_syntax noprefix
.text

// NikeIdStyle [+0xf8]/[+0x100] v1.12 guard -> .bind VA 0x146ca5680 (max 128 bytes)
// Hooked from 0x14092024c (`xor r10d, r10d; cmp [rdi+0xf8], r10d; jle 0x1409202ef`).
// Preserves rdi, rbx, rbp, rsi and all callee-saved registers.
.globl _pe_nikeid_f8_guard
_pe_nikeid_f8_guard:
    movsxd rcx, dword ptr [rdi + 0xf8]
    test rcx, rcx
    jle Lnikeid_skip
    mov r9, qword ptr [rdi + 0x100]
    test r9, r9
    jz Lnikeid_clear
    mov rax, qword ptr [r9 + 8]
    test rax, rax
    jz Lnikeid_v10
    add rax, 7
    imul rdx, rcx, 0x18
    cmp rax, rdx
    jae Lnikeid_v10

Lnikeid_clear:
    mov dword ptr [rdi + 0xf8], 0
    mov qword ptr [rdi + 0x100], 0

Lnikeid_skip:
    // Patched to jmp 0x1409202ef (rel32)
    .byte 0xe9, 0x11, 0x22, 0x33, 0x44

Lnikeid_v10:
    xor r10d, r10d
    // Patched to jmp 0x14092025c (rel32)
    .byte 0xe9, 0x22, 0x33, 0x44, 0x55
.globl _pe_nikeid_f8_guard_end
_pe_nikeid_f8_guard_end:
