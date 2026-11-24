.intel_syntax noprefix
.text

// Season Prizes (MyCareer_Seasons::Init) offline blackscreen guard -> .bind VA 0x146ca5700 (max 128 bytes)
// Hooked from 0x140465add (`call 0x140f22720`, TASK_BLOCKER::WaitingPopup).
// Inside the stub, [rsp + 0x108] is caller [rsp + 0x100] (CreateRequest status)
// and [rsp + 0x110] is caller [rsp + 0x108] (SendRequest status).
// If both == 0x504521a8 (online), tail-jump to TASK_BLOCKER::WaitingPopup.
// Otherwise (offline), set g_seasons_loaded = 1, clear claimed/current levels, and return.
.globl _pe_seasons_wait_guard
_pe_seasons_wait_guard:
    cmp dword ptr [rsp + 0x108], 0x504521a8
    jne Lseasons_offline
    cmp dword ptr [rsp + 0x110], 0x504521a8
    jne Lseasons_offline
    // Patched to jmp 0x140f22720 (rel32)
    .byte 0xe9, 0x11, 0x22, 0x33, 0x44

Lseasons_offline:
    mov eax, 1
    // mov dword ptr [rip + disp32], eax -> 0x144e9f0c8 (g_seasons_loaded)
    .byte 0x89, 0x05, 0x22, 0x33, 0x44, 0x55
    xor eax, eax
    // mov qword ptr [rip + disp32], rax -> 0x144ea42d0 (g_seasons_claimed_level)
    .byte 0x48, 0x89, 0x05, 0x33, 0x44, 0x55, 0x66
    // mov qword ptr [rip + disp32], rax -> 0x144ea42d8 (g_seasons_current_level)
    .byte 0x48, 0x89, 0x05, 0x44, 0x55, 0x66, 0x77
    ret
.globl _pe_seasons_wait_guard_end
_pe_seasons_wait_guard_end:
