# Technical Notes

## 1. PE `.bind` Section Code-Cave Map (`NBA2K22.exe`)

| Virtual Address | Raw File Offset | Size | Owner |
| :--- | :--- | :--- | :--- |
| `0x146ca5000..0x146ca513f` | `0x04eee400..0x04eee53f` | 320 B | Existing MyCAREER `.ini` unlocker (untouched) |
| `0x146ca5200..0x146ca52fa` | `0x04eee600..0x04eee6fa` | 251 B | `ptsm_fixup` (v1.12 → v1.0 in-place converter) |
| `0x146ca5320..0x146ca53fc` | `0x04eee720..0x04eee7fc` | 221 B | `winhttp_connect_failfast` (`WinHttpConnect` hook) |
| `0x146ca5420..0x146ca5481` | `0x04eee820..0x04eee881` | 98 B | `ws2_connect1_failfast` (`WS2_32!connect` site #1 hook) |
| `0x146ca54a0..0x146ca54f8` | `0x04eee8a0..0x04eee8f8` | 89 B | `ws2_connect_failfast` (`WS2_32!connect` sites #2 & #3 hook) |
| `0x146ca5500..0x146ca55da` | `0x04eee900..0x04eee9da` | 219 B | `ws2_gethostbyname_failfast` (`WS2_32!gethostbyname` external DNS hook) |
| `0x146ca5600..0x146ca565f` | `0x04eeea00..0x04eeea5f` | 96 B | `ws2_sendto_failfast` (`WS2_32!sendto` external UDP hook) |
| `0x146ca6000+` | `0x04eef400+` | — | Existing unlocker strings/buffers (untouched) |

---

## 2. `PTSTADIUM_MARKER_GROUP` v1.0 vs v1.12 Layout

- **v1.0 (`NBA2K22.exe`):** `0x210` bytes per group:
  - `+0x00`: `uint32_t group_id`
  - `+0x08..+0x207`: `uint64_t ptrs[64]` (64 marker pointer slots)
  - `+0x208`: `uint32_t count` (clamped `0..64`)
- **v1.12 (`ptsm_*.iff` assets):** `0xFB0` bytes per group (500 pointer slots, `count` at `+0xFA8`).
- **Auto-Detection:**
  `actual_groups_bytes = (uint32_t)header[0x20] - (groups_ptr - header)`
  If `actual_groups_bytes == num_groups * 0xFB0`, source stride is `0xFB0`; otherwise `0x210`.
- **Hook Site:** `0x1418d7a50` (raw `0x018d7050`, 167 bytes) → `jmp 0x146ca5200` + `0xcc` padding.

---

## 3. Network Fail-Fast Implementation

- **TEB `LastError` Under Windows & Wine/CrossOver:**
  Both `kernelbase.dll!GetLastError` and `ws2_32.dll!WSAGetLastError` read `dword ptr [gs:[0x30] + 0x68]`. Setting this field directly avoids importing extra APIs.
- **`WinHttpConnect` (`0x141eba545`):**
  Compares `pswzServerName` (`rdx`, UTF-16LE) word-by-word against `"127.0.0.1"` and case-insensitive `"localhost"` (so short strings near page boundaries never over-read). External hosts set `LastError = 12029` (`ERROR_INTERNET_CANNOT_CONNECT`) and return `NULL`.
- **`WS2_32!connect` (`0x141eadcb4`, `0x141eae156`, `0x142132b6a`):**
  Allows `NULL`, IPv4 `127.0.0.0/8` (`AF_INET = 2`), and IPv6 `::1` (`AF_INET6 = 23`). External addresses set `LastError = 10061` (`WSAECONNREFUSED`) and return `-1`.
  - Site #1 (`0x141eadcb4`) uses `jmp 0x146ca5420` and jumps directly to `0x141eade69` on failure because the caller at `0x141eadd44` (`cmp r15d, -1; jne 0x141eade30`) treats any non-`-1` state as connected.
- **`WS2_32!gethostbyname` (`0x142125913`):**
  Hooks only the external resolver wrapper (`0x142125900`); local IP discovery sites (`0x141e18b06` for `"localhost"` and `0x141e18b14` for the local host name) are untouched. Allows `NULL`, `""`, `"127.0.0.1"`, and case-insensitive `"localhost"` (byte-by-byte); external hostnames set `LastError = 11001` (`WSAHOST_NOT_FOUND`) and return `NULL`.
- **`WS2_32!sendto` (`0x141eaef15`):**
  Reads the 5th argument (`const struct sockaddr* to`) from `[rsp + 0x28]` into `r11` without disturbing `rcx`/`rdx`/`r8`/`r9`/`rsp`. Allows `NULL`, IPv4 `127.0.0.0/8`, and IPv6 `::1`; external destinations set `LastError = 10051` (`WSAENETUNREACH`, mapped to engine error `0x96532a4b` in `0x142e24630`) and return `-1`.

---

## 4. UI Menu Guard Audit Rationale

`NavList_Main` and `TkWorld_Gateway_SetMode` dispatch menu transitions through indirect vtables and an internal state machine. Intercepting them mid-transition risks leaving the UI in a soft-locked state. Because the Network Fail-Fast patch already forces external connections to fail immediately and cleanly surface `Error code: 7cfb1845` with an **OK** button, UI interception was intentionally omitted.
