#!/usr/bin/env python3
"""
Era Wine/Proton Compatibility Patcher v1.0
==========================================
Patches era.dll to work on both Windows AND Linux (Wine/Proton).

PROBLEM:
  era.dll uses a PAGE_GUARD + VEH (Vectored Exception Handler) hook to
  intercept Fortnite's HTTP request function. The VEH handler only checks
  for exception code 0x80000001 (STATUS_GUARD_PAGE_VIOLATION).

  Under Wine/Proton, the same guard page trigger can raise 0xc0000005
  (STATUS_ACCESS_VIOLATION) due to how Wine emulates page protection in
  multi-threaded contexts. This causes an unhandled exception → crash.

FIX:
  Adds a second check for 0xc0000005 alongside the existing 0x80000001.
  The downstream RIP verification (already in era.dll) ensures only the
  intended target function gets redirected — other exceptions pass through.

SAFETY ON WINDOWS:
  The added 0xc0000005 + matching RIP scenario NEVER occurs natively.
  The extra comparison is a harmless no-op — zero impact on Windows users.

Usage:
  python patch_era.py [path_to_era.dll]
  python patch_era.py --verify [path_to_era.dll]
  python patch_era.py --restore [path_to_era.dll]

Works on: Windows, Linux, macOS (as a patching tool)
"""

import struct
import sys
import os
import shutil

# ──────────────────────────────────────────────────────────────────────
# PE helpers
# ──────────────────────────────────────────────────────────────────────

def parse_text_section(data: bytes):
    """Return (rva, vsize, file_offset, raw_size) of .text section."""
    if data[:2] != b"MZ":
        raise RuntimeError("Not a valid PE file (missing MZ header)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise RuntimeError("Not a valid PE file (missing PE signature)")
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_offset = e_lfanew + 24 + opt_hdr_size
    for i in range(num_sections):
        hdr = data[sec_offset + i * 40 : sec_offset + (i + 1) * 40]
        name = hdr[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", hdr, 8)
        if name == ".text":
            return rva, vsize, raw_ptr, raw_size
    raise RuntimeError(".text section not found")


def file_to_va(off, text_rva, text_raw, base=0x180000000):
    return base + (off - text_raw + text_rva)


# ──────────────────────────────────────────────────────────────────────
# Pattern search
# ──────────────────────────────────────────────────────────────────────

# VEH handler preamble in era.dll (unique signature):
#   mov rax, [rcx]            ; 48 8B 01        — ExceptionRecord ptr
#   mov edx, [rax]            ; 8B 10           — ExceptionCode
#   cmp edx, 0x80000001       ; 81 FA 01 00 00 80
#   jne <skip>                ; 75 XX
ORIG_PATTERN = bytes.fromhex("48 8B 01 8B 10 81 FA 01 00 00 80 75".replace(" ", ""))

# After patching, the cmp+jne becomes jmp+nops:
#   mov rax, [rcx]            ; 48 8B 01        (preserved)
#   mov edx, [rax]            ; 8B 10           (preserved)
#   jmp <cave>                ; E9 XX XX XX XX
#   nop; nop; nop             ; 90 90 90
PATCHED_MARKER = bytes.fromhex("48 8B 01 8B 10 E9".replace(" ", ""))


def find_code_cave(data, text_raw, text_raw_size, near, min_size=32):
    """Find a run of 0xCC (int3 padding) >= min_size bytes in .text."""
    best = None
    i = text_raw
    end = text_raw + text_raw_size
    while i < end:
        if data[i] != 0xCC:
            i += 1
            continue
        j = i
        while j < end and data[j] == 0xCC:
            j += 1
        length = j - i
        if length >= min_size:
            if best is None or abs(i - near) < abs(best[0] - near):
                best = (i, length)
        i = j
    if best is None:
        raise RuntimeError(f"No code cave >= {min_size} bytes found")
    return best


# ──────────────────────────────────────────────────────────────────────
# Patch logic
# ──────────────────────────────────────────────────────────────────────

def patch(dll_path, backup=True):
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())

    text_rva, text_vsize, text_raw, text_rsize = parse_text_section(data)
    print(f"  .text  RVA 0x{text_rva:X}  raw 0x{text_raw:X}  size 0x{text_rsize:X}")

    # ── check if already patched ──
    if data.find(PATCHED_MARKER) != -1 and data.find(ORIG_PATTERN) == -1:
        print("\n  [!] era.dll is ALREADY patched. Nothing to do.")
        print("      Use --restore to revert, then patch again if needed.")
        return False

    # ── find original pattern ──
    idx = data.find(ORIG_PATTERN)
    if idx == -1:
        raise RuntimeError(
            "VEH pattern not found. Unsupported era.dll version?\n"
            "Expected bytes: " + ORIG_PATTERN.hex()
        )

    hook_off = idx + 5                       # file offset of cmp instruction
    hook_va = file_to_va(hook_off, text_rva, text_raw)
    jne_disp = data[idx + 12]                # unsigned byte
    if jne_disp > 127:
        jne_disp -= 256                      # sign-extend
    is_guard_off = idx + 13                  # fall-through (exception IS guard)
    not_guard_off = idx + 13 + jne_disp      # jne target  (exception is NOT guard)
    is_guard_va = file_to_va(is_guard_off, text_rva, text_raw)
    not_guard_va = file_to_va(not_guard_off, text_rva, text_raw)

    print(f"  VEH check at  0x{hook_va:X}  (file 0x{hook_off:X})")
    print(f"    → guard path   0x{is_guard_va:X}")
    print(f"    → skip path    0x{not_guard_va:X}")

    # ── find code cave ──
    cave_off, cave_len = find_code_cave(data, text_raw, text_rsize, hook_off)
    cave_va = file_to_va(cave_off, text_rva, text_raw)
    print(f"  Code cave at  0x{cave_va:X}  (file 0x{cave_off:X}, {cave_len} bytes)")

    # ── assemble cave code (29 bytes) ──
    #   cmp edx, 0x80000001        ; original Windows check
    #   je  is_guard_va            ; → matches — handle it
    #   cmp edx, 0xc0000005        ; Wine/Proton check (NEW)
    #   je  is_guard_va            ; → matches — handle it
    #   jmp not_guard_va           ; neither — skip
    cave = bytearray()

    cave += b"\x81\xFA\x01\x00\x00\x80"                           # cmp edx, 0x80000001
    rip1 = cave_va + len(cave) + 6
    cave += b"\x0F\x84" + struct.pack("<i", is_guard_va - rip1)   # je is_guard

    cave += b"\x81\xFA\x05\x00\x00\xC0"                           # cmp edx, 0xc0000005
    rip2 = cave_va + len(cave) + 6
    cave += b"\x0F\x84" + struct.pack("<i", is_guard_va - rip2)   # je is_guard

    rip3 = cave_va + len(cave) + 5
    cave += b"\xE9" + struct.pack("<i", not_guard_va - rip3)      # jmp not_guard

    assert len(cave) == 29

    # ── assemble hook-site redirect (8 bytes) ──
    #   jmp cave_va   ; 5 bytes
    #   nop; nop; nop ; 3 bytes padding
    jmp_rip = hook_va + 5
    hook = b"\xE9" + struct.pack("<i", cave_va - jmp_rip) + b"\x90\x90\x90"
    assert len(hook) == 8

    # ── verify targets are safe to overwrite ──
    assert all(b == 0xCC for b in data[cave_off : cave_off + 29]), \
        "Code cave is not clean int3 padding"
    assert data[hook_off : hook_off + 8] == bytes.fromhex("81FA010000807544"[: 16]), \
        "Hook site bytes mismatch"

    # ── backup ──
    if backup:
        bak = dll_path + ".orig" if not dll_path.endswith(".orig") else dll_path + ".bak"
        if not os.path.exists(bak):
            shutil.copy2(dll_path, bak)
            print(f"  Backup → {os.path.basename(bak)}")
        else:
            print(f"  Backup already exists: {os.path.basename(bak)}")

    # ── apply ──
    data[cave_off : cave_off + 29] = cave
    data[hook_off : hook_off + 8] = hook

    with open(dll_path, "wb") as f:
        f.write(data)

    print()
    print("  [OK] Patched successfully!")
    print("       VEH now accepts 0x80000001 (Windows) AND 0xc0000005 (Wine/Proton)")
    return True


def verify(dll_path):
    with open(dll_path, "rb") as f:
        data = f.read()

    has_orig = data.find(ORIG_PATTERN) != -1
    has_patch = data.find(PATCHED_MARKER) != -1

    if has_orig and not has_patch:
        print("  [ORIGINAL] era.dll is NOT patched (Windows-only)")
        return False
    elif has_patch and not has_orig:
        print("  [PATCHED]  era.dll has the Wine/Proton compatibility fix")
        return True
    else:
        print("  [UNKNOWN]  Could not determine patch status")
        return False


def restore(dll_path):
    bak = dll_path + ".orig"
    if not os.path.exists(bak):
        bak = dll_path + ".bak"
    if not os.path.exists(bak):
        raise RuntimeError("No backup file found (.orig or .bak)")
    shutil.copy2(bak, dll_path)
    print(f"  [OK] Restored from {os.path.basename(bak)}")


# ──────────────────────────────────────────────────────────────────────
# Auto-detect era.dll
# ──────────────────────────────────────────────────────────────────────

def find_era_dll():
    """Try common install locations."""
    candidates = []

    # Windows: %APPDATA%\era\dll\era.dll
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        candidates.append(os.path.join(appdata, "era", "dll", "era.dll"))

    # Linux Wine prefixes
    home = os.path.expanduser("~")
    for prefix in ["project-era-test", "project-era", "era"]:
        candidates.append(os.path.join(
            home, "Games", prefix,
            "drive_c/users/steamuser/AppData/Roaming/era/dll/era.dll"
        ))

    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    action = "patch"

    if "--restore" in args:
        action = "restore"
        args.remove("--restore")
    elif "--verify" in args:
        action = "verify"
        args.remove("--verify")
    elif "-h" in args or "--help" in args:
        print(__doc__)
        return

    dll_path = args[0] if args else find_era_dll()
    if dll_path is None:
        print("Usage: python patch_era.py [--verify|--restore] <path_to_era.dll>")
        print("       Could not auto-detect era.dll location.")
        sys.exit(1)

    if not os.path.isfile(dll_path):
        print(f"Error: file not found: {dll_path}")
        sys.exit(1)

    print(f"\n  Era Wine/Proton Compatibility Patcher v1.0")
    print(f"  File: {dll_path}")
    print(f"  Size: {os.path.getsize(dll_path):,} bytes\n")

    try:
        if action == "verify":
            verify(dll_path)
        elif action == "restore":
            restore(dll_path)
        elif action == "patch":
            patch(dll_path)
    except Exception as e:
        print(f"\n  [ERROR] {e}")
        sys.exit(1)

    print()


if __name__ == "__main__":
    main()
