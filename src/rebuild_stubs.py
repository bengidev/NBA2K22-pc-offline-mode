#!/usr/bin/env python3
"""
Assemble x86_64 PE stubs from src/ptsm_fixup.s and src/net_failfast_pe.s,
verify zero relocations, patch RIP-relative displacements, and check
the resulting machine code against known-good SHA-256 hashes.
"""

import hashlib
import os
import platform
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT, "src")
BUILD_DIR = os.path.join(ROOT, "build")

EXPECTED_SHA256 = {
    "ptsm_stub": "f1f86beeb421b862b38544d58601a0204209f006e8388f2f6d247a22609f4469",
    "net_stub1": "9e0c0eca859ce640709ffa2d5005b77888df016436b39cd165a9bafe9911a9ff",
    "net_stub2": "51eee6687cfa037c1ccb82728b7abad7a742a6d5f0c8dd4502da23c8b014c9c5",
    "net_stub3": "5c04dc0543d07517f196b025ad410c3d312327f5dcd1fd05aac8bc82e8b4b443",
    "net_stub4": "02c0bb9deb6da5c0ba71c26d21a455884ad7c6d5cb1d1606b1471d9da7640b65",
    "net_stub5": "38630fd32dfdece6b1b1ced646b95a53b9715ab1e08bc9725037d994fc75a257",
    "nikeid_stub": "9ce691de6154bcec23253d66080bbf05d131738485566a24a625f9814c591de9",
}


def assemble(src_name: str, obj_name: str) -> str:
    src_path = os.path.join(SRC_DIR, src_name)
    obj_path = os.path.join(BUILD_DIR, obj_name)
    cmd = ["clang"]
    if platform.system() == "Darwin":
        cmd += ["-arch", "x86_64"]
    else:
        cmd += ["-target", "x86_64-pc-linux-elf"]
    cmd += ["-c", src_path, "-o", obj_path]
    subprocess.run(cmd, check=True)

    reloc = subprocess.check_output(["objdump", "-r", obj_path], text=True)
    for line in reloc.splitlines():
        if line.strip() and not line.startswith(obj_path) and "file format" not in line and "RELOCATION" not in line and "OFFSET" not in line:
            raise RuntimeError(f"Unexpected relocation in {obj_name}: {line}")
    return obj_path


def extract_macho_text(obj_path: str) -> bytes:
    out = subprocess.check_output(["otool", "-s", "__TEXT", "__text", obj_path], text=True)
    buf = bytearray()
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) > 1 and len(parts[0]) == 16:
            for b in parts[1:]:
                buf.append(int(b, 16))
    return bytes(buf)


def get_symbols(obj_path: str) -> dict[str, int]:
    out = subprocess.check_output(["nm", "-n", obj_path], text=True)
    syms: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            syms[parts[2]] = int(parts[0], 16)
    return syms


def patch_placeholder(buf: bytearray, cave_va: int, placeholder: bytes, target_va: int) -> None:
    idx = buf.find(placeholder)
    if idx == -1:
        raise RuntimeError(f"Placeholder {placeholder.hex()} not found")
    disp = target_va - (cave_va + idx + 4)
    buf[idx : idx + 4] = struct.pack("<i", disp)


def main() -> int:
    os.makedirs(BUILD_DIR, exist_ok=True)
    ptsm_obj = assemble("ptsm_fixup.s", "ptsm_fixup.o")
    net_obj = assemble("net_failfast_pe.s", "net_failfast_pe.o")
    nikeid_obj = assemble("nikeid_guard_pe.s", "nikeid_guard_pe.o")

    ptsm_stub = extract_macho_text(ptsm_obj)

    net_text = extract_macho_text(net_obj)
    syms = get_symbols(net_obj)

    nikeid_text = extract_macho_text(nikeid_obj)
    nikeid_syms = get_symbols(nikeid_obj)

    stub1 = bytearray(net_text[syms["_pe_winhttp_connect_failfast"] : syms["_pe_winhttp_end"]])
    stub2 = bytearray(net_text[syms["_pe_ws2_connect1_failfast"] : syms["_pe_ws2_1_end"]])
    stub3 = bytearray(net_text[syms["_pe_ws2_connect_failfast"] : syms["_pe_ws2_end"]])
    stub4 = bytearray(net_text[syms["_pe_ws2_gethostbyname_failfast"] : syms["_pe_ws2_ghbn_end"]])
    stub5 = bytearray(net_text[syms["_pe_ws2_sendto_failfast"] : syms["_pe_ws2_sendto_end"]])
    nikeid_stub = bytearray(nikeid_text[nikeid_syms["_pe_nikeid_f8_guard"] : nikeid_syms["_pe_nikeid_f8_guard_end"]])

    assert len(stub4) <= 256, f"stub4 too large: {len(stub4)}"
    assert len(stub5) <= 128, f"stub5 too large: {len(stub5)}"
    assert len(nikeid_stub) <= 128, f"nikeid_stub too large: {len(nikeid_stub)}"

    patch_placeholder(stub1, 0x146CA5320, b"\x11\x22\x33\x44", 0x142199880)
    patch_placeholder(stub2, 0x146CA5420, b"\x11\x22\x33\x44", 0x141EADE69)
    patch_placeholder(stub2, 0x146CA5420, b"\x22\x33\x44\x55", 0x142199998)
    patch_placeholder(stub2, 0x146CA5420, b"\x33\x44\x55\x66", 0x141EADCBA)
    patch_placeholder(stub3, 0x146CA54A0, b"\x44\x55\x66\x77", 0x142199998)
    patch_placeholder(stub4, 0x146CA5500, b"\x55\x66\x77\x88", 0x142199968)
    patch_placeholder(stub5, 0x146CA5600, b"\x66\x77\x88\x99", 0x142199920)
    patch_placeholder(nikeid_stub, 0x146CA5680, b"\x11\x22\x33\x44", 0x1409202EF)
    patch_placeholder(nikeid_stub, 0x146CA5680, b"\x22\x33\x44\x55", 0x14092025C)

    stubs = {
        "ptsm_stub": ptsm_stub,
        "net_stub1": bytes(stub1),
        "net_stub2": bytes(stub2),
        "net_stub3": bytes(stub3),
        "net_stub4": bytes(stub4),
        "net_stub5": bytes(stub5),
        "nikeid_stub": bytes(nikeid_stub),
    }

    for name, data in stubs.items():
        digest = hashlib.sha256(data).hexdigest()
        expected = EXPECTED_SHA256.get(name, "")
        status = "OK" if digest == expected else ("NEW" if not expected else "MISMATCH")
        print(f"{name:10s}  size={len(data):3d}B  sha256={digest}  [{status}]")
        if not expected:
            print(f"  hex: {data.hex()}")
        elif digest != expected:
            print(f"Expected: {expected}", file=sys.stderr)
            return 1

    print("ALL 7 STUBS REBUILT AND VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
