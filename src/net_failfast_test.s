.intel_syntax noprefix
.text

// WinHttpConnect(HINTERNET hSession [rcx], LPCWSTR pswzServerName [rdx], INTERNET_PORT nServerPort [r8], DWORD dwReserved [r9])
// On Win64 ABI:
// - If pswzServerName == NULL -> allow (jump to real WinHttpConnect)
// - If pswzServerName is "127.0.0.1" (UTF-16LE) or "localhost" (case-insensitive UTF-16LE) -> allow
// - Otherwise: set LastError = 12029 (ERROR_INTERNET_CANNOT_CONNECT), return NULL (rax = 0)
.globl _winhttp_connect_failfast
_winhttp_connect_failfast:
    test rdx, rdx
    jz Lwinhttp_allow

    // Check "127.0.0.1" (9 chars + NUL = 10 words)
    cmp word ptr [rdx], '1'
    jne Lcheck_localhost
    cmp word ptr [rdx+2], '2'
    jne Lcheck_localhost
    cmp word ptr [rdx+4], '7'
    jne Lcheck_localhost
    cmp word ptr [rdx+6], '.'
    jne Lcheck_localhost
    cmp word ptr [rdx+8], '0'
    jne Lcheck_localhost
    cmp word ptr [rdx+10], '.'
    jne Lcheck_localhost
    cmp word ptr [rdx+12], '0'
    jne Lcheck_localhost
    cmp word ptr [rdx+14], '.'
    jne Lcheck_localhost
    cmp word ptr [rdx+16], '1'
    jne Lcheck_localhost
    cmp word ptr [rdx+18], 0
    je Lwinhttp_allow

Lcheck_localhost:
    // Check "localhost" case-insensitive (9 chars + NUL)
    // For ASCII letters, | 0x20 converts A-Z to a-z
    movzx eax, word ptr [rdx]
    or eax, 0x20
    cmp eax, 'l'
    jne Lwinhttp_block
    movzx eax, word ptr [rdx+2]
    or eax, 0x20
    cmp eax, 'o'
    jne Lwinhttp_block
    movzx eax, word ptr [rdx+4]
    or eax, 0x20
    cmp eax, 'c'
    jne Lwinhttp_block
    movzx eax, word ptr [rdx+6]
    or eax, 0x20
    cmp eax, 'a'
    jne Lwinhttp_block
    movzx eax, word ptr [rdx+8]
    or eax, 0x20
    cmp eax, 'l'
    jne Lwinhttp_block
    movzx eax, word ptr [rdx+10]
    or eax, 0x20
    cmp eax, 'h'
    jne Lwinhttp_block
    movzx eax, word ptr [rdx+12]
    or eax, 0x20
    cmp eax, 'o'
    jne Lwinhttp_block
    movzx eax, word ptr [rdx+14]
    or eax, 0x20
    cmp eax, 's'
    jne Lwinhttp_block
    movzx eax, word ptr [rdx+16]
    or eax, 0x20
    cmp eax, 't'
    jne Lwinhttp_block
    cmp word ptr [rdx+18], 0
    je Lwinhttp_allow

Lwinhttp_block:
    // Set LastError = 12029 (ERROR_INTERNET_CANNOT_CONNECT)
    mov dword ptr [_g_mock_last_error + rip], 12029
    xor eax, eax
    ret

Lwinhttp_allow:
    jmp _mock_real_winhttp_connect


// WS2_32!connect(SOCKET s [rcx], const struct sockaddr* name [rdx], int namelen [r8])
// Helper logic:
// - If name == NULL -> allow
// - If sa_family == AF_INET (2) and (sin_addr & 0xFF) == 127 -> allow (127.0.0.0/8)
// - If sa_family == AF_INET6 (23) and sin6_addr == ::1 -> allow
// - Otherwise: set LastError = 10061 (WSAECONNREFUSED), return -1 (eax = -1)
.globl _ws2_connect_failfast
_ws2_connect_failfast:
    test rdx, rdx
    jz Lws2_allow
    movzx eax, word ptr [rdx]
    cmp eax, 2 // AF_INET
    jne Lws2_check_v6
    mov eax, dword ptr [rdx+4]
    and eax, 0xFF
    cmp eax, 127
    je Lws2_allow
    jmp Lws2_block

Lws2_check_v6:
    cmp eax, 23 // AF_INET6
    jne Lws2_block
    // sockaddr_in6: sin6_addr is at offset +8 (16 bytes)
    mov rax, qword ptr [rdx+8]
    test rax, rax
    jnz Lws2_block
    mov rax, qword ptr [rdx+16]
    // ::1 in big-endian at +16..+23 is 0x0100000000000000
    mov r10, 0x0100000000000000
    cmp rax, r10
    je Lws2_allow

Lws2_block:
    mov dword ptr [_g_mock_last_error + rip], 10061
    mov eax, -1
    ret

Lws2_allow:
    jmp _mock_real_ws2_connect


// WS2_32!gethostbyname(const char* name [rcx])
// Allow: NULL, "", "127.0.0.1", case-insensitive "localhost"
// Block: set LastError = 11001 (WSAHOST_NOT_FOUND), return NULL
.globl _ws2_gethostbyname_failfast
_ws2_gethostbyname_failfast:
    test rcx, rcx
    jz Lghbn_allow
    cmp byte ptr [rcx], 0
    je Lghbn_allow

    // Check "127.0.0.1" (9 bytes + NUL)
    cmp byte ptr [rcx], '1'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+1], '2'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+2], '7'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+3], '.'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+4], '0'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+5], '.'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+6], '0'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+7], '.'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+8], '1'
    jne Lghbn_check_localhost
    cmp byte ptr [rcx+9], 0
    je Lghbn_allow

Lghbn_check_localhost:
    movzx eax, byte ptr [rcx]
    or eax, 0x20
    cmp eax, 'l'
    jne Lghbn_block
    movzx eax, byte ptr [rcx+1]
    or eax, 0x20
    cmp eax, 'o'
    jne Lghbn_block
    movzx eax, byte ptr [rcx+2]
    or eax, 0x20
    cmp eax, 'c'
    jne Lghbn_block
    movzx eax, byte ptr [rcx+3]
    or eax, 0x20
    cmp eax, 'a'
    jne Lghbn_block
    movzx eax, byte ptr [rcx+4]
    or eax, 0x20
    cmp eax, 'l'
    jne Lghbn_block
    movzx eax, byte ptr [rcx+5]
    or eax, 0x20
    cmp eax, 'h'
    jne Lghbn_block
    movzx eax, byte ptr [rcx+6]
    or eax, 0x20
    cmp eax, 'o'
    jne Lghbn_block
    movzx eax, byte ptr [rcx+7]
    or eax, 0x20
    cmp eax, 's'
    jne Lghbn_block
    movzx eax, byte ptr [rcx+8]
    or eax, 0x20
    cmp eax, 't'
    jne Lghbn_block
    cmp byte ptr [rcx+9], 0
    je Lghbn_allow

Lghbn_block:
    mov dword ptr [_g_mock_last_error + rip], 11001
    xor eax, eax
    ret

Lghbn_allow:
    jmp _mock_real_ws2_gethostbyname


// WS2_32!sendto(SOCKET s [rcx], const char* buf [rdx], int len [r8], int flags [r9], const struct sockaddr* to [rsp+0x28], int tolen [rsp+0x30])
// Note: preserve rcx, rdx, r8, r9, rsp, and callee-saved regs; use r11 for `to`.
.globl _ws2_sendto_failfast
_ws2_sendto_failfast:
    mov r11, qword ptr [rsp + 0x28]
    test r11, r11
    jz Lsendto_allow
    movzx eax, word ptr [r11]
    cmp eax, 2 // AF_INET
    jne Lsendto_check_v6
    mov eax, dword ptr [r11+4]
    and eax, 0xFF
    cmp eax, 127
    je Lsendto_allow
    jmp Lsendto_block

Lsendto_check_v6:
    cmp eax, 23 // AF_INET6
    jne Lsendto_block
    mov rax, qword ptr [r11+8]
    test rax, rax
    jnz Lsendto_block
    mov rax, qword ptr [r11+16]
    mov r10, 0x0100000000000000
    cmp rax, r10
    je Lsendto_allow

Lsendto_block:
    mov dword ptr [_g_mock_last_error + rip], 10051
    mov eax, -1
    ret

Lsendto_allow:
    jmp _mock_real_ws2_sendto
