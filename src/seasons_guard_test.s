.intel_syntax noprefix
.text

// Unit-testable version of seasons_wait_guard + Win64-frame trampoline for macOS SysV ABI.
// uint64_t call_seasons_guard_with_frame(uint32_t create_status, uint32_t send_status)
// SysV args: edi = create_status, esi = send_status
.globl _call_seasons_guard_with_frame
_call_seasons_guard_with_frame:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0xf8

    // Match MyCareer_Seasons::Init stack layout:
    // [rsp + 0x100] = create_status, [rsp + 0x108] = send_status, [rsp + 0x20] = 5th arg sentinel
    mov dword ptr [rsp + 0x100], edi
    mov dword ptr [rsp + 0x108], esi
    mov qword ptr [rsp + 0x20], 0x55

    mov rcx, 0x1111222233334444
    mov rdx, 0x2222333344445555
    mov r8,  0x3333444455556666
    mov r9,  0x4444555566667777
    call Lseasons_wait_guard

    add rsp, 0xf8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

Lseasons_wait_guard:
    cmp dword ptr [rsp + 0x108], 0x504521a8
    jne Ltest_seasons_offline
    cmp dword ptr [rsp + 0x110], 0x504521a8
    jne Ltest_seasons_offline
    jmp _mock_waiting_popup

Ltest_seasons_offline:
    mov eax, 1
    mov dword ptr [rip + _g_seasons_loaded], eax
    xor eax, eax
    mov qword ptr [rip + _g_seasons_claimed_level], rax
    mov qword ptr [rip + _g_seasons_current_level], rax
    ret
