.intel_syntax noprefix
.text

// Stub 1: winhttp_connect_failfast -> .bind VA 0x146ca5320 (max 128 bytes)
.globl _pe_winhttp_connect_failfast
_pe_winhttp_connect_failfast:
    test rdx, rdx
    jz Lpe_winhttp_allow

    cmp word ptr [rdx], '1'
    jne Lpe_check_localhost
    cmp word ptr [rdx+2], '2'
    jne Lpe_check_localhost
    cmp word ptr [rdx+4], '7'
    jne Lpe_check_localhost
    cmp word ptr [rdx+6], '.'
    jne Lpe_check_localhost
    cmp word ptr [rdx+8], '0'
    jne Lpe_check_localhost
    cmp word ptr [rdx+10], '.'
    jne Lpe_check_localhost
    cmp word ptr [rdx+12], '0'
    jne Lpe_check_localhost
    cmp word ptr [rdx+14], '.'
    jne Lpe_check_localhost
    cmp word ptr [rdx+16], '1'
    jne Lpe_check_localhost
    cmp word ptr [rdx+18], 0
    je Lpe_winhttp_allow

Lpe_check_localhost:
    movzx eax, word ptr [rdx]
    or eax, 0x20
    cmp eax, 'l'
    jne Lpe_winhttp_block
    movzx eax, word ptr [rdx+2]
    or eax, 0x20
    cmp eax, 'o'
    jne Lpe_winhttp_block
    movzx eax, word ptr [rdx+4]
    or eax, 0x20
    cmp eax, 'c'
    jne Lpe_winhttp_block
    movzx eax, word ptr [rdx+6]
    or eax, 0x20
    cmp eax, 'a'
    jne Lpe_winhttp_block
    movzx eax, word ptr [rdx+8]
    or eax, 0x20
    cmp eax, 'l'
    jne Lpe_winhttp_block
    movzx eax, word ptr [rdx+10]
    or eax, 0x20
    cmp eax, 'h'
    jne Lpe_winhttp_block
    movzx eax, word ptr [rdx+12]
    or eax, 0x20
    cmp eax, 'o'
    jne Lpe_winhttp_block
    movzx eax, word ptr [rdx+14]
    or eax, 0x20
    cmp eax, 's'
    jne Lpe_winhttp_block
    movzx eax, word ptr [rdx+16]
    or eax, 0x20
    cmp eax, 't'
    jne Lpe_winhttp_block
    cmp word ptr [rdx+18], 0
    je Lpe_winhttp_allow

Lpe_winhttp_block:
    mov rax, qword ptr gs:[0x30]
    mov dword ptr [rax + 0x68], 12029
    xor eax, eax
    ret

Lpe_winhttp_allow:
    // Patched by apply_net_failfast.py to jmp qword ptr [rip + disp32] -> 0x142199880
    .byte 0xff, 0x25, 0x11, 0x22, 0x33, 0x44
.globl _pe_winhttp_end
_pe_winhttp_end:


// Stub 2: ws2_connect1_failfast -> .bind VA 0x146ca5420 (max 128 bytes)
// Site 1 (0x141eadcb4) was `call qword ptr [WS2_32!connect]`; replaced with `jmp 0x146ca53a0`.
// On fail: set LastError = 10061, eax = -1, jmp 0x141eade69.
// On allow: call qword ptr [0x142199998], jmp 0x141eadcba.
.globl _pe_ws2_connect1_failfast
_pe_ws2_connect1_failfast:
    test rdx, rdx
    jz Lpe_ws2_1_allow
    movzx eax, word ptr [rdx]
    cmp eax, 2
    jne Lpe_ws2_1_check_v6
    mov eax, dword ptr [rdx+4]
    and eax, 0xFF
    cmp eax, 127
    je Lpe_ws2_1_allow
    jmp Lpe_ws2_1_block

Lpe_ws2_1_check_v6:
    cmp eax, 23
    jne Lpe_ws2_1_block
    mov rax, qword ptr [rdx+8]
    test rax, rax
    jnz Lpe_ws2_1_block
    mov rax, qword ptr [rdx+16]
    mov r10, 0x0100000000000000
    cmp rax, r10
    je Lpe_ws2_1_allow

Lpe_ws2_1_block:
    mov rax, qword ptr gs:[0x30]
    mov dword ptr [rax + 0x68], 10061
    mov eax, -1
    // Patched to jmp 0x141eade69 (rel32)
    .byte 0xe9, 0x11, 0x22, 0x33, 0x44

Lpe_ws2_1_allow:
    // Patched to call qword ptr [rip + disp32] -> 0x142199998
    .byte 0xff, 0x15, 0x22, 0x33, 0x44, 0x55
    // Patched to jmp 0x141eadcba (rel32)
    .byte 0xe9, 0x33, 0x44, 0x55, 0x66
.globl _pe_ws2_1_end
_pe_ws2_1_end:


// Stub 3: ws2_connect_failfast -> .bind VA 0x146ca54a0 (max 128 bytes)
// Used by Sites 2 & 3 (`call 0x146ca5420; nop`).
.globl _pe_ws2_connect_failfast
_pe_ws2_connect_failfast:
    test rdx, rdx
    jz Lpe_ws2_allow
    movzx eax, word ptr [rdx]
    cmp eax, 2
    jne Lpe_ws2_check_v6
    mov eax, dword ptr [rdx+4]
    and eax, 0xFF
    cmp eax, 127
    je Lpe_ws2_allow
    jmp Lpe_ws2_block

Lpe_ws2_check_v6:
    cmp eax, 23
    jne Lpe_ws2_block
    mov rax, qword ptr [rdx+8]
    test rax, rax
    jnz Lpe_ws2_block
    mov rax, qword ptr [rdx+16]
    mov r10, 0x0100000000000000
    cmp rax, r10
    je Lpe_ws2_allow

Lpe_ws2_block:
    mov rax, qword ptr gs:[0x30]
    mov dword ptr [rax + 0x68], 10061
    mov eax, -1
    ret

Lpe_ws2_allow:
    // Patched to jmp qword ptr [rip + disp32] -> 0x142199998
    .byte 0xff, 0x25, 0x44, 0x55, 0x66, 0x77
.globl _pe_ws2_end
_pe_ws2_end:
