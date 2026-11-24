#!/usr/bin/env python3
"""
Standalone cross-platform binary patcher for NBA 2K22 PC (v1.12 + MyCAREER Unlocker).

Applies:
  1. PTSM v1.12 -> v1.0 in-place runtime fixup (fixes MyCAREER Practice/Neighborhood CTD)
  2. Network fail-fast stubs for WinHttpConnect and WS2_32!connect (prevents offline hangs)

No external dependencies or compiler required.
"""

import argparse
import datetime
import hashlib
import os
import shutil
import sys

EXPECTED_EXE_SIZE = 83_000_504

KNOWN_EXE_HASHES = {
    "05f9e593067d4e43da63e93d1b0ad426a441f9ad18d53b36f12a6961193cae23": "unpatched (base v1.0 + MyCAREER unlocker)",
    "2784fe59e6ff602c8efef84d927d7f718db875bc2b6e527c724646635aaff6ca": "ptsm-only (PTSM fix applied)",
    "6aa419978a78dab941b6cafce4a777d8237bfad52d3e2e01dc8e729f1deabb36": "fully-patched-v1 (PTSM + WinHttpConnect + WS2 connect; run apply to add DNS/UDP fail-fast)",
    "2dc02098412f96f46749b4cb64a2aa49c6e839510199fb15840d683bb0c3fc8e": "fully-patched (PTSM + full Network fail-fast: WinHttp, TCP connect, DNS gethostbyname, UDP sendto)",
}

# --- PTSM Fixup ---
PTSM_HOOK_OFF = 0x018D7050
PTSM_HOOK_LEN = 167
PTSM_ORIG_HOOK_SHA256 = "59b19202c05f8af8f3c795aa68cac13a35951d531f89fbbd9ab4ae9b62d69754"
PTSM_TRAMPOLINE = bytes.fromhex("e9abd73c05") + (b"\xcc" * (PTSM_HOOK_LEN - 5))

PTSM_CAVE_OFF = 0x04EEE600
PTSM_STUB = bytes.fromhex(
    "4c8b5a184d85db750331c0c3498b43084885c07409498d440307498943084d8b"
    "4b184d85c90f84ca0000004f8d4c0b174d894b184d6353104d85d20f8eb40000"
    "00418b43204c01d84c29c84969cab00f000041bb10020000bab00f00004839c8"
    "4c0f44da4d89c8418b014b635419f831c94885d2480f48d1b9400000004839ca"
    "480f4fd141890041c74004000000004189900802000041c7800c020000000000"
    "0031c948c1e2034839d17d20498b4409084885c07408488d4408074c01c84989"
    "4408084883c1084839d17ce031c04881f9000200007d0b49894408084883c108"
    "ebec4d01d94981c01002000049ffca0f8572ffffffb801000000c3"
)

# --- Network Fail-Fast ---
NET_CAVES = [
    (
        0x04EEE720,
        bytes.fromhex(
            "4885d20f84ce00000066833a31754366837a0232753c66837a0437753566837a"
            "062e752e66837a0830752766837a0a2e752066837a0c30751966837a0e2e7512"
            "66837a1031750b66837a12000f84850000000fb70283c82083f86c75670fb742"
            "0283c82083f86f755b0fb7420483c82083f863754f0fb7420683c82083f86175"
            "430fb7420883c82083f86c75370fb7420a83c82083f868752b0fb7420c83c820"
            "83f86f751f0fb7420e83c82083f87375130fb7421083c82083f874750766837a"
            "1200741365488b042530000000c74068fd2e000031c0c3ff2583444ffb"
        ),
        "WinHttpConnect stub",
    ),
    (
        0x04EEE820,
        bytes.fromhex(
            "4885d274520fb70283f802750f8b420425ff00000083f87f743deb2183f81775"
            "1c488b42084885c07513488b421049ba00000000000000014c39d0741a65488b"
            "042530000000c740684d270000b8ffffffffe9f28920fbff151b454ffbe93888"
            "20fb"
        ),
        "WS2_32!connect #1 stub",
    ),
    (
        0x04EEE8A0,
        bytes.fromhex(
            "4885d2744e0fb70283f802750f8b420425ff00000083f87f7439eb2183f81775"
            "1c488b42084885c07513488b421049ba00000000000000014c39d0741665488b"
            "042530000000c740684d270000b8ffffffffc3ff259f444ffb"
        ),
        "WS2_32!connect #2/#3 stub",
    ),
    (
        0x04EEE900,
        bytes.fromhex(
            "4885c90f84cc0000008039000f84c3000000803931753a807901327534807902"
            "37752e8079032e75288079043075228079052e751c8079063075168079072e75"
            "1080790831750a807909000f84840000000fb60183c82083f86c75660fb64101"
            "83c82083f86f755a0fb6410283c82083f863754e0fb6410383c82083f8617542"
            "0fb6410483c82083f86c75360fb6410583c82083f868752a0fb6410683c82083"
            "f86f751e0fb6410783c82083f87375120fb6410883c82083f874750680790900"
            "741365488b042530000000c74068f92a000031c0c3ff258d434ffb"
        ),
        "WS2_32!gethostbyname stub",
    ),
    (
        0x04EEEA00,
        bytes.fromhex(
            "4c8b5c24284d85db7450410fb70383f8027510418b430425ff00000083f87f74"
            "39eb2183f817751c498b43084885c07513498b431049ba00000000000000014c"
            "39d0741665488b042530000000c7406843270000b8ffffffffc3ff25c0424ffb"
        ),
        "WS2_32!sendto stub",
    ),
]

NET_SITES = [
    (0x01EB9B45, bytes.fromhex("ff1535f32d00"), bytes.fromhex("e8d6adde0490"), "WinHttpConnect"),
    (0x01EAD2B4, bytes.fromhex("ff15debc2e00"), bytes.fromhex("e96777df0490"), "WS2_32!connect #1"),
    (0x01EAD756, bytes.fromhex("ff153cb82e00"), bytes.fromhex("e84573df0490"), "WS2_32!connect #2"),
    (0x0213216A, bytes.fromhex("ff15286e0600"), bytes.fromhex("e83129b70490"), "WS2_32!connect #3"),
    (0x02124F13, bytes.fromhex("ff154f400700"), bytes.fromhex("e8e8fbb70490"), "WS2_32!gethostbyname"),
    (0x01EAE515, bytes.fromhex("ff1505aa2e00"), bytes.fromhex("e8e666df0490"), "WS2_32!sendto"),
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def cmd_status(exe_path: str) -> int:
    if not os.path.isfile(exe_path):
        print(f"Error: File not found: {exe_path}", file=sys.stderr)
        return 1
    size = os.path.getsize(exe_path)
    digest = sha256_file(exe_path)
    desc = KNOWN_EXE_HASHES.get(digest, "unknown/custom")
    print(f"File   : {exe_path}")
    print(f"Size   : {size:,} bytes (expected {EXPECTED_EXE_SIZE:,})")
    print(f"SHA-256: {digest}")
    print(f"State  : {desc}")
    return 0


def apply_ptsm(f, force: bool) -> bool:
    f.seek(PTSM_HOOK_OFF)
    hook_bytes = f.read(PTSM_HOOK_LEN)
    f.seek(PTSM_CAVE_OFF)
    cave_bytes = f.read(len(PTSM_STUB))

    if hook_bytes == PTSM_TRAMPOLINE and cave_bytes == PTSM_STUB:
        print("[PTSM] Already applied, skipping.")
        return False

    orig_sha = hashlib.sha256(hook_bytes).hexdigest()
    if orig_sha != PTSM_ORIG_HOOK_SHA256 and not force:
        raise RuntimeError(
            f"[PTSM] Unexpected original bytes at 0x{PTSM_HOOK_OFF:x} (sha256={orig_sha}). "
            "Use --force to override."
        )
    if cave_bytes != b"\x00" * len(PTSM_STUB) and not force:
        raise RuntimeError(
            f"[PTSM] .bind cave at 0x{PTSM_CAVE_OFF:x} is not empty. Use --force to override."
        )

    f.seek(PTSM_CAVE_OFF)
    f.write(PTSM_STUB)
    f.seek(PTSM_HOOK_OFF)
    f.write(PTSM_TRAMPOLINE)
    print("[PTSM] Applied v1.12 -> v1.0 in-place fixup.")
    return True


def apply_net(f, force: bool) -> bool:
    caves_to_write = []
    for off, stub, label in NET_CAVES:
        f.seek(off)
        cur = f.read(len(stub))
        if cur == stub:
            continue
        if cur != b"\x00" * len(stub) and not force:
            raise RuntimeError(
                f"[NET] .bind cave for {label} at 0x{off:x} is not empty. Use --force to override."
            )
        caves_to_write.append((off, stub, label))

    sites_to_write = []
    for off, orig, patched, label in NET_SITES:
        f.seek(off)
        cur = f.read(len(orig))
        if cur == patched:
            continue
        if cur != orig and not force:
            raise RuntimeError(
                f"[NET] Unexpected bytes at {label} (0x{off:x}): {cur.hex()}. "
                "Use --force to override."
            )
        sites_to_write.append((off, patched, label))

    if not caves_to_write and not sites_to_write:
        print("[NET]  Already applied, skipping.")
        return False

    for off, stub, label in caves_to_write:
        f.seek(off)
        f.write(stub)
    for off, patched, label in sites_to_write:
        f.seek(off)
        f.write(patched)
    print(f"[NET]  Applied {len(sites_to_write)} call-site hook(s) and {len(caves_to_write)} stub(s).")
    return True


def cmd_apply(args: argparse.Namespace) -> int:
    exe_path = args.exe
    if not os.path.isfile(exe_path):
        print(f"Error: File not found: {exe_path}", file=sys.stderr)
        return 1

    size = os.path.getsize(exe_path)
    if size != EXPECTED_EXE_SIZE and not args.force:
        print(
            f"Error: File size is {size:,} bytes, expected {EXPECTED_EXE_SIZE:,} bytes. "
            "Use --force to override.",
            file=sys.stderr,
        )
        return 1

    do_ptsm = args.all or args.ptsm_only or (not args.ptsm_only and not args.net_only)
    do_net = args.all or args.net_only or (not args.ptsm_only and not args.net_only)

    if not args.no_backup:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        bak_path = f"{exe_path}.bak-before-patch-{ts}"
        shutil.copy2(exe_path, bak_path)
        print(f"Backup created: {bak_path}")

    with open(exe_path, "r+b") as f:
        if do_ptsm:
            apply_ptsm(f, args.force)
        if do_net:
            apply_net(f, args.force)

    digest = sha256_file(exe_path)
    desc = KNOWN_EXE_HASHES.get(digest, "custom/modified")
    print(f"Post-patch SHA-256: {digest}")
    print(f"Verified state    : {desc}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NBA 2K22 PC offline-mode binary patcher (PTSM v1.12 fix + Network fail-fast)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="Inspect NBA2K22.exe patch status")
    p_status.add_argument("exe", help="Path to NBA2K22.exe")

    p_apply = sub.add_parser("apply", help="Apply offline-mode patches to NBA2K22.exe")
    p_apply.add_argument("exe", help="Path to NBA2K22.exe")
    mode = p_apply.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_true", help="Apply both PTSM and Network fail-fast patches (default)")
    mode.add_argument("--ptsm-only", action="store_true", help="Apply only the PTSM v1.12 MyCAREER crash fix")
    mode.add_argument("--net-only", action="store_true", help="Apply only the Network fail-fast patch")
    p_apply.add_argument("--no-backup", action="store_true", help="Do not create a .bak file before patching")
    p_apply.add_argument("--force", action="store_true", help="Bypass size/hash safety checks")

    args = parser.parse_args()
    if args.command == "status":
        return cmd_status(args.exe)
    if args.command == "apply":
        return cmd_apply(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
