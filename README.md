# NBA 2K22 PC Offline Mode — Stability Patches & Save Utilities

Binary patches, x86_64 assembly sources, unit tests, and save-backup utilities to fix **MyCAREER Crash-to-Desktop (CTD)** and **offline network hangs** in **NBA 2K22 PC** (tested on Windows and macOS Apple Silicon via CrossOver Preview `27.0.0.41303` + D3DMetal).

> **Disclaimer:** This repository does **not** distribute copyrighted game binaries, assets, cracks, or save files. It only provides open-source binary patchers, assembly sources, tests, and documentation.

---

## Target Game Build / Source

- **Game Source:** [NBA 2K22 v1.12 + All DLC + MyCAREER Unlocker](https://zeigames.com/topic/6919-nba-2k22-free-download-v112-all-dlc-mycareer-unlocker/)
- **Target Executable:** `NBA2K22.exe` (`83,000,504` bytes)

| State | SHA-256 |
| :--- | :--- |
| Unpatched base (`v1.0` exe + MyCAREER unlocker from v1.12 release) | `05f9e593067d4e43da63e93d1b0ad426a441f9ad18d53b36f12a6961193cae23` |
| PTSM fix only (`--ptsm-only`) | `2784fe59e6ff602c8efef84d927d7f718db875bc2b6e527c724646635aaff6ca` |
| Full patch: PTSM fix + Network fail-fast (`--all`, recommended) | `6aa419978a78dab941b6cafce4a777d8237bfad52d3e2e01dc8e729f1deabb36` |

---

## What Each Patch Fixes

### 1. PTSM v1.12 → v1.0 In-Place Runtime Fixup
- **Symptom:** Instant crash-to-desktop (`0xc0000005` at RVA `0x018d6cac`) when entering MyCAREER **Practice**, **Neighborhood**, or other stadium-loaded scenes.
- **Root Cause:** The v1.12 release ships v1.12 `ptsm_*.iff` assets (`PTSTADIUM_MARKER_GROUP` stride `0xFB0`, 500 pointer slots) alongside a v1.0 `NBA2K22.exe` that expects `0x210` (64 slots).
- **Fix:** Hooks the PTSM loader at `0x1418d7a50` and runs an in-place `.bind` code-cave converter (`0x146ca5200`) that auto-detects v1.12 vs v1.0 stride and converts `0xFB0` → `0x210` on load.

### 2. Network Fail-Fast Patch
- **Symptom:** Long freezes or hangs when accidentally clicking online/VC-synced features (Neighborhood, MyTEAM, 2K Store, etc.), since official NBA 2K22 servers are shut down.
- **Fix:** Hooks `WinHttpConnect` (`0x141eba545`) and all 3 `WS2_32!connect` call sites (`0x141eadcb4`, `0x141eae156`, `0x142132b6a`). Loopback addresses (`127.0.0.1`, `localhost`, `::1`) are allowed; external connections fail immediately with `ERROR_INTERNET_CANNOT_CONNECT` (`12029`) or `WSAECONNREFUSED` (`10061`).
- **Expected Behavior:** Accessing online-only menus now immediately displays `Error code: 7cfb1845` with a working **OK** button instead of hanging.

### 3. Save Backup & Restore Utility
- `scripts/nba2k22_save_backup.command` backs up and restores `data/steam/steam_settings/1644960/remote/` into `_save_backups/`.

### 4. Why UI Menu Guard Was Intentionally Omitted
- Auditing `NavList_Main` / `TkWorld_Gateway_SetMode` showed that Neighborhood/Online menu transitions use indirect vtable and internal state-machine dispatch. Blocking mid-transition risks UI soft-locks. With the Network Fail-Fast patch active, accidental clicks already return cleanly via `Error code: 7cfb1845`.

---

## Quick Start

### Apply the Binary Patch
No compiler is needed — `patcher/patch_nba2k22.py` uses Python 3 standard library only:

```bash
# 1. Check current status
python3 patcher/patch_nba2k22.py status /path/to/NBA2K22.exe

# 2. Apply both PTSM fix and Network fail-fast (creates a timestamped .bak automatically)
python3 patcher/patch_nba2k22.py apply /path/to/NBA2K22.exe
```

Optional flags:
- `--ptsm-only` — apply only the MyCAREER PTSM crash fix
- `--net-only` — apply only the Network fail-fast patch
- `--no-backup` — skip automatic `.bak` creation

To revert, restore the `.bak-before-patch-*` file created next to `NBA2K22.exe`.

### Backup / Restore Saves (macOS / zsh)
Copy `scripts/nba2k22_save_backup.command` into your NBA 2K22 game directory (or set `NBA2K22_DIR=/path/to/NBA2K22`):

```zsh
./nba2k22_save_backup.command backup initial
./nba2k22_save_backup.command list
./nba2k22_save_backup.command restore initial
```

---

## Building & Running Unit Tests

Requires `clang` (on Apple Silicon macOS, compiles `x86_64` and runs under Rosetta 2):

```bash
make test
make verify-stubs
```

---

## Offline Mode Limitations

| Mode / Feature | Status | Notes |
| :--- | :--- | :--- |
| MyCAREER (NBA Games, Practice, Story) | Works | PTSM crash fixed; offline progression works |
| Play Now / Quick Game / MyLEAGUE | Works | Fully playable offline |
| Neighborhood / The City | Unavailable | Server-side; returns `Error code: 7cfb1845` cleanly |
| MyTEAM / 2K Store / VC Sync | Unavailable | Server-side; returns `Error code: 7cfb1845` cleanly |
