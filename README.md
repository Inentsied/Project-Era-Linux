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
