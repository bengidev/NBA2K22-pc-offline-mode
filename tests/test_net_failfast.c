#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

uint32_t g_mock_last_error = 0;
int g_real_winhttp_called = 0;
int g_real_ws2_called = 0;

__attribute__((ms_abi))
void* mock_real_winhttp_connect(void* hSession, const uint16_t* pswzServerName, uint16_t nServerPort, uint32_t dwReserved) {
    (void)hSession; (void)pswzServerName; (void)nServerPort; (void)dwReserved;
    g_real_winhttp_called++;
    return (void*)0x12345678ULL;
}

__attribute__((ms_abi))
int mock_real_ws2_connect(uint64_t s, const void* name, int namelen) {
    (void)s; (void)name; (void)namelen;
    g_real_ws2_called++;
    return 0;
}

__attribute__((ms_abi))
extern void* winhttp_connect_failfast(void* hSession, const uint16_t* pswzServerName, uint16_t nServerPort, uint32_t dwReserved);

__attribute__((ms_abi))
extern int ws2_connect_failfast(uint64_t s, const void* name, int namelen);

static void to_utf16(const char* s, uint16_t* out, size_t max_chars) {
    size_t i = 0;
    while (s[i] && i + 1 < max_chars) {
        out[i] = (uint16_t)(unsigned char)s[i];
        i++;
    }
    out[i] = 0;
}

int main(void) {
    uint16_t buf[64];

    // 1. WinHttpConnect: external host -> blocked, LastError = 12029, returns NULL
    g_mock_last_error = 0;
    g_real_winhttp_called = 0;
    to_utf16("api.nba2k.com", buf, 64);
    assert(winhttp_connect_failfast((void*)1, buf, 443, 0) == NULL);
    assert(g_mock_last_error == 12029);
    assert(g_real_winhttp_called == 0);

    // 2. WinHttpConnect: short string (edge case) -> blocked
    g_mock_last_error = 0;
    to_utf16("a", buf, 64);
    assert(winhttp_connect_failfast((void*)1, buf, 80, 0) == NULL);
    assert(g_mock_last_error == 12029);
    assert(g_real_winhttp_called == 0);

    // 3. WinHttpConnect: "127.0.0.1" -> allowed
    g_mock_last_error = 0;
    to_utf16("127.0.0.1", buf, 64);
    assert(winhttp_connect_failfast((void*)1, buf, 8080, 0) == (void*)0x12345678ULL);
    assert(g_mock_last_error == 0);
    assert(g_real_winhttp_called == 1);

    // 4. WinHttpConnect: "LocalHost" (mixed case) -> allowed
    to_utf16("LocalHost", buf, 64);
    assert(winhttp_connect_failfast((void*)1, buf, 8080, 0) == (void*)0x12345678ULL);
    assert(g_real_winhttp_called == 2);

    // 5. WinHttpConnect: "localhost.evil.com" -> blocked
    g_mock_last_error = 0;
    to_utf16("localhost.evil.com", buf, 64);
    assert(winhttp_connect_failfast((void*)1, buf, 443, 0) == NULL);
    assert(g_mock_last_error == 12029);
    assert(g_real_winhttp_called == 2);

    // 6. WinHttpConnect: NULL -> allowed
    assert(winhttp_connect_failfast((void*)1, NULL, 80, 0) == (void*)0x12345678ULL);
    assert(g_real_winhttp_called == 3);

    // 7. WS2_32!connect: IPv4 external (8.8.8.8) -> blocked, LastError = 10061, returns -1
    uint8_t sa_v4[16] = {0};
    sa_v4[0] = 2; sa_v4[1] = 0; // AF_INET
    sa_v4[4] = 8; sa_v4[5] = 8; sa_v4[6] = 8; sa_v4[7] = 8;
    g_mock_last_error = 0;
    g_real_ws2_called = 0;
    assert(ws2_connect_failfast(1, sa_v4, 16) == -1);
    assert(g_mock_last_error == 10061);
    assert(g_real_ws2_called == 0);

    // 8. WS2_32!connect: IPv4 loopback (127.0.0.1) -> allowed
    sa_v4[4] = 127; sa_v4[5] = 0; sa_v4[6] = 0; sa_v4[7] = 1;
    g_mock_last_error = 0;
    assert(ws2_connect_failfast(1, sa_v4, 16) == 0);
    assert(g_real_ws2_called == 1);

    // 9. WS2_32!connect: IPv6 ::1 -> allowed
    uint8_t sa_v6[28] = {0};
    sa_v6[0] = 23; sa_v6[1] = 0; // AF_INET6
    sa_v6[23] = 1; // ::1
    assert(ws2_connect_failfast(1, sa_v6, 28) == 0);
    assert(g_real_ws2_called == 2);

    // 10. WS2_32!connect: IPv6 external (2001:4860:4860::8888) -> blocked
    sa_v6[8] = 0x20; sa_v6[9] = 0x01;
    g_mock_last_error = 0;
    assert(ws2_connect_failfast(1, sa_v6, 28) == -1);
    assert(g_mock_last_error == 10061);
    assert(g_real_ws2_called == 2);

    printf("ALL NET FAILFAST TESTS PASSED (10/10)\n");
    return 0;
}
