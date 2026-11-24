.intel_syntax noprefix
.text
.globl _ptsm_fixup
_ptsm_fixup:
    mov r11, qword ptr [rdx + 0x18]
    test r11, r11
    jnz Lhave_hdr
    xor eax, eax
    ret

Lhave_hdr:
    # 1. Fix up header->markers ([r11 + 0x08])
    mov rax, qword ptr [r11 + 0x08]
    test rax, rax
    jz Lno_markers
    lea rax, [r11 + rax + 7]
    mov qword ptr [r11 + 0x08], rax
Lno_markers:

    # 2. Fix up header->groups ([r11 + 0x18])
    mov r9, qword ptr [r11 + 0x18]
    test r9, r9
    jz Ldone
    lea r9, [r11 + r9 + 0x17]
    mov qword ptr [r11 + 0x18], r9

    # 3. Check num_groups ([r11 + 0x10])
    movsxd r10, dword ptr [r11 + 0x10]
    test r10, r10
    jle Ldone

    # 4. Auto-detect v1.12 (0xFB0) vs v1.0 (0x210):
    #    actual_groups_bytes = (uint32_t)[r11 + 0x20] - (r9 - r11)
    #    expected_v112_bytes = r10 * 0xFB0
    mov eax, dword ptr [r11 + 0x20]
    add rax, r11
    sub rax, r9
    imul rcx, r10, 0xFB0
    mov r11d, 0x210
    mov edx, 0xFB0
    cmp rax, rcx
    cmove r11, rdx

    # r11 = src_stride (0xFB0 or 0x210), r10 = remaining groups
    # r9 = src group ptr, r8 = dst group ptr
    mov r8, r9

Lgroup_loop:
    mov eax, dword ptr [r9]
    movsxd rdx, dword ptr [r9 + r11 - 8]
    xor ecx, ecx
    test rdx, rdx
    cmovs rdx, rcx
    mov ecx, 64
    cmp rdx, rcx
    cmovg rdx, rcx

    mov dword ptr [r8], eax
    mov dword ptr [r8 + 4], 0
    mov dword ptr [r8 + 0x208], edx
    mov dword ptr [r8 + 0x20c], 0

    xor ecx, ecx
    shl rdx, 3
    cmp rcx, rdx
    jge Lzero_tail
Lptr_loop:
    mov rax, qword ptr [r9 + rcx + 8]
    test rax, rax
    jz Lstore_ptr
    lea rax, [rax + rcx + 7]
    add rax, r9
Lstore_ptr:
    mov qword ptr [r8 + rcx + 8], rax
    add rcx, 8
    cmp rcx, rdx
    jl Lptr_loop

Lzero_tail:
    xor eax, eax
Lzero_loop:
    cmp rcx, 0x200
    jge Lnext_group
    mov qword ptr [r8 + rcx + 8], rax
    add rcx, 8
    jmp Lzero_loop

Lnext_group:
    add r9, r11
    add r8, 0x210
    dec r10
    jnz Lgroup_loop

Ldone:
    mov eax, 1
    ret
