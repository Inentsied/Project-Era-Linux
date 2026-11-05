# Era Linux/Wine/Proton Compatibility Patches

> [!WARNING]
> **This project is a work in progress. The game does NOT fully work yet.**
> We are actively investigating and fixing Wine/Proton compatibility issues.
> Contributions, ideas, and reverse-engineering help are very welcome!

Patches to run **Project Era** (Fortnite OG Season 6.21, build `CL-4526925`) on **Linux** via Wine/Proton.
On Windows everything works out of the box — this project is only for **Linux / Steam Deck**.

## Current Status

| Step | Status | Details |
|------|--------|---------|
| Game launches | ✅ | Splash screen appears |
| Lobby loads | ✅ | Maps and assets load correctly |
| Hotfixes download | ✅ | Server config applied |
| Authorization begins | ✅ | "Logging in…" appears |
| **Login completes** | **❌ CRASH** | Access Violation in UE4 native function — **this is where we're stuck** |

The crash happens because `era.dll`'s signature scanner (`FindPattern`) fails under Wine, leaving all internal function pointers as `NULL`. When the DLL tries to call these pointers during login — instant crash.

## The Problem

Era Launcher works perfectly on Windows but crashes on Linux (Wine/Proton) due to several issues:

| # | Component | What breaks under Wine | Status |
|---|-----------|----------------------|--------|
| 1 | `era.dll` — VEH Handler | Wine throws `0xc0000005` instead of `0x80000001` for `PAGE_GUARD` violations | ✅ Fixed |
| 2 | `era_injector.node` — `WaitForInputIdle` | Hangs for 90+ seconds, DLL gets injected too late | ✅ Fixed |
| 3 | `er2.dll` — `FindPattern` | Signature scanner can't find byte patterns in Wine's memory → all function pointers = `NULL` | ⚠️ Partial (workaround stubs) |
| 4 | `er2.dll` — `GetPropertyAddress` | Calls through NULL `FindPropertyByName` pointer → Access Violation | ⚠️ Partial (3 of ~20+ functions patched) |
| 5 | `er2.dll` — UE4 engine functions | NULL passed to native Fortnite functions → UE4 crash | ❌ **Not fixed — current blocker** |

## Architecture (important to understand)

```
Era.exe (Electron launcher)
  → era_injector.node — injects DLL into the Fortnite process
    → era.dll — original DLL (hash-checked, CANNOT be modified)
      → er2.dll — copy of era.dll with our Wine patches (loaded instead of era.dll)
```

### Why `er2.dll` instead of patching `era.dll` directly?

The launcher **checks the SHA256 hash** of `era.dll` on every launch and redownloads it if modified. So:
- `era.dll` — stays **untouched** (hash in `era.dll.json`)
- `er2.dll` — copy of `era.dll` with our patches
- `era_injector.node` is patched to redirect the DLL path: `era.dll` → `er2.dll`

### The Core Issue: `FindPattern`

At startup, `er2.dll` calls `FindPattern` (`VA 0x1801c21b0`), which scans the `.text` section of `FortniteClient-Win64-Shipping.exe` using IDA-style byte signatures. It looks for addresses of ~20+ internal UE4 functions and stores the pointers in global variables.

**On Windows** — the `.text` section is mapped into memory in a standard way, patterns are found.

**On Wine/Proton** — due to differences in memory page mapping, protection flags (`PAGE_EXECUTE_READ`), and section alignment, `FindPattern` **fails to find ANY pattern** and returns `NULL` for every function.

As a result, all global pointers (`[0x1804c26b8]`, `[0x1804c2990]`, `[0x1804c2ce0]`, etc.) remain zero, and the first call through any of them causes an Access Violation crash.

## Applied Patches

### Fix 1: VEH Exception Handler

```
File: era.dll → patched into er2.dll
Offset: VEH handler (~0x1801c13f8)
```

The VEH handler checks the exception code:
```asm
; Before:
cmp edx, 0x80000001    ; STATUS_GUARD_PAGE_VIOLATION (Windows only)
jne skip

; After (via code cave):
cmp edx, 0x80000001    ; Windows
je  handle
cmp edx, 0xc0000005    ; STATUS_ACCESS_VIOLATION (Wine/Proton)
je  handle
jmp skip
```

### Fix 2: `WaitForInputIdle` timing

```
File: era_injector.node
Change: WaitForInputIdle(h, INFINITE) → WaitForSingleObject(h, 3000)
```

`WaitForInputIdle` under Wine hangs indefinitely for non-GUI processes, causing the DLL injection to happen too late (after the game already progresses past the hook point).

### Fix 3: `GetPropertyAddress` stubs

Instead of calling `FindPropertyByName` through a NULL pointer, we replace entire functions with 9-byte stubs returning hardcoded offsets from the Fortnite 6.21 binary:

| Function | VA | File Offset | Property | UE4 Offset | Status |
|----------|-----|-------------|----------|------------|--------|
| `GetPropertyAddress` | `0x18016f010` | `0x16e410` | `GameViewport` (`UGameEngine`) | `0x748` | ✅ |
| `GetPropertyAddress` | `0x18016f1d0` | `0x16e5d0` | `ViewportConsole` (`UGameViewportClient`) | `0x40` | ✅ |
| `GetPropertyAddress` | `0x1801bf600` | `0x1bea00` | `CheatManager` (`APlayerController`) | `0x448` | ✅ |

Stub format:
```asm
mov eax, <OFFSET>   ; B8 XX XX 00 00
add rax, rcx         ; 48 03 C1
ret                  ; C3
; int3 padding       ; CC CC CC CC CC
```

## Current Crash (help needed!)

After all patches above, the game crashes during login:

**Call stack:**
```
FortniteClient + 0x26d03f2  ← CRASH (access violation, reads [0x34...])
  ↑ er2.dll + 0x1a2159     ← call [0x1804c2ce0] (another FindPattern-resolved function = NULL)
  ↑ er2.dll + 0x1a212d     ← call rbx (FindPropertyByName = NULL!)
  ↑ er2.dll + 0x1a20a0     ← property lookup block (XOR-decrypts property name + FindPattern)
```

The pointer at `[0x1804c2ce0]` is yet another function resolved via `FindPattern` (pattern: `48 85 C9 0F 84 ? ? ? ? 56 48 83 EC 70 4C 8B 4A 78 41 8B F0 8B 82 ? ? ? ? 45 8B 41 3C 89 44 24 64`). Under Wine it's also `NULL`.

## Global Pointer Map (`er2.dll`)

All of these are populated by `FindPattern` and remain `NULL` under Wine:

| Address | Description | Pattern (`.rdata`) |
|---------|-------------|-------------------|
| `0x1804c26b8` | `FindPropertyByName` / `UStruct::FindField` | ? |
| `0x1804c26c0` | `FName::Init` or similar | ? |
| `0x1804c2990` | Set of 3 functions | ? |
| `0x1804c2ce0` | UE4 function (object array iteration) | `48 85 C9 0F 84...` |
| `0x1804c34a0` | HTTP hook target (VEH) | ? |
| `0x1804c34a8` | Era hook redirect | ? |
| `0x1804c3478` | `FindPattern` result cached | ? |
| `0x1804c3490` | `FindPattern` result cached | ? |

## How to Help

### Most important right now:

1. **Fix `FindPattern` itself** (`VA 0x1801c21b0`) — make it work under Wine, or bypass it entirely by pre-populating all global pointer slots with correct values found offline from the EXE. This is the **nuclear option** that fixes everything at once.

2. **Find all `GetPropertyAddress`-like functions** in `er2.dll` that call `FindPropertyByName` via `[0x1804c26b8]` and crash. There are ~20+ of them, we've only patched 3.

3. **For each one, find the corresponding UE4 property** — decrypt the XOR-encrypted property name and look up `Offset_Internal` in FortniteClient 6.21's UProperty table.

### How property names are encrypted:

Each function loads an encrypted property name via `movabs rax, <val>` + `pxor` before calling `FindPropertyByName`:

```python
# Example: CheatManager
v1 = (0xa1cbdffee8712fa8).to_bytes(8, 'little') + (0x3fabe3cf65cef415).to_bytes(8, 'little')
v2 = (0xcfaa928a891447eb).to_bytes(8, 'little') + (0x3fabe3cf17ab9374).to_bytes(8, 'little')
result = bytes(a ^ b for a, b in zip(v1, v2))
# → b'CheatManager\x00\x00\x00\x00'
```

### How to find `Offset_Internal` in FortniteClient:

Search for the property name string in `.rdata`, then find the reference to it in the UProperty structure, where `[+0x28]` = `Offset_Internal`:

```python
# In FortniteClient 6.21 binary:
# UProperty: { name_ptr, 0x45, flags, 1, 0, Offset_Internal, ... }
```

## Project Structure

```
├── patch_era.py                # Auto-patcher: VEH fix in era.dll → er2.dll
├── patch_injector.py           # Patcher for era_injector.node (WaitForInputIdle)
├── patch_properties.py         # GetPropertyAddress stubs for er2.dll
├── install_fluxapp_handler.py  # Register fluxapp:// protocol handler for OAuth
└── README.md                   # This file
```

## Requirements

- **Fortnite Build**: `928551d8-c2b6-457e-9201-90144cc519d3` (Season 6.21, CL-4526925)
- **Era Launcher**: v4.x (tested on 4.0.31)
- **Wine**: Proton-GE or Wine-staging 11+
- **GPU**: NVIDIA GTX 1050 Ti+ (tested), AMD — untested
- **System**: Arch Linux, Wayland (tested), X11 — should work
- **Tools**: Python 3 for running patch scripts

## Disclaimer

This project is a Wine/Proton compatibility research effort for running already-installed software. We do not distribute any Era or Fortnite files. All patches are applied to local copies of DLLs.
