#!/usr/bin/env python3
"""Register a per-user Linux handler for Era's fluxapp:// OAuth callback.

The handler forwards the callback URL to an Era executable inside a Wine
prefix. It does not patch era.dll. It supports system Wine and Proton.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, help="Wine prefix directory")
    parser.add_argument(
        "--exe", required=True,
        help="Linux path to the Era .exe inside PREFIX/drive_c",
    )
    parser.add_argument("--id", default="era", help="Handler ID, e.g. era-v3")
    parser.add_argument("--name", default="Project Era", help="Desktop entry name")
    parser.add_argument(
        "--runner", choices=("wine", "proton"), default="wine",
        help="Use system/custom Wine or a Proton runner (default: wine)",
    )
    parser.add_argument(
        "--runner-path", help="Optional path to wine or proton executable",
    )
    parser.add_argument(
        "--steam-root", help="Steam root for Proton (auto-detected if omitted)",
    )
    return parser.parse_args()


def windows_executable(prefix: Path, exe_arg: str) -> tuple[Path, str]:
    drive_c = (prefix / "drive_c").resolve(strict=True)
    exe = Path(exe_arg).expanduser().resolve(strict=True)
    try:
        relative = exe.relative_to(drive_c)
    except ValueError as exc:
        raise ValueError("--exe must point to a file inside PREFIX/drive_c") from exc
    if not exe.is_file() or exe.suffix.lower() != ".exe":
        raise ValueError("--exe must point to an existing .exe file")
    win_path = "C:\\" + str(relative).replace(os.sep, "\\")
    return exe, win_path


def find_runner(args) -> tuple[str, str]:
    if args.runner == "wine":
        runner = args.runner_path or shutil.which("wine")
        if not runner:
            raise ValueError("Wine was not found; install Wine or pass --runner-path")
        runner_path = Path(runner).expanduser().resolve(strict=True)
        if not os.access(runner_path, os.X_OK):
            raise ValueError("Wine runner is not executable")
        return args.runner, str(runner_path)

    if not args.runner_path:
        raise ValueError("--runner proton requires --runner-path /path/to/proton")
    runner_path = Path(args.runner_path).expanduser().resolve(strict=True)
    if not os.access(runner_path, os.X_OK):
        raise ValueError("Proton runner is not executable")
    return args.runner, str(runner_path)


def steam_root(args) -> str:
    candidates = [
        Path(args.steam_root).expanduser() if args.steam_root else None,
        Path.home() / ".local/share/Steam",
        Path.home() / ".steam/steam",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return str(candidate.resolve())
    return str((Path.home() / ".local/share/Steam").resolve())


def desktop_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    args = parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.id):
        print("Error: --id may contain lowercase letters, digits, and hyphens only", file=sys.stderr)
        return 2
    if "\n" in args.name or "\r" in args.name:
        print("Error: --name must be a single line", file=sys.stderr)
        return 2

    try:
        prefix = Path(args.prefix).expanduser().resolve(strict=True)
        if not prefix.is_dir():
            raise ValueError("--prefix must be a directory")
        exe, win_exe = windows_executable(prefix, args.exe)
        runner, runner_path = find_runner(args)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    bin_dir = Path.home() / ".local/bin"
    apps_dir = Path.home() / ".local/share/applications"
    bin_dir.mkdir(parents=True, exist_ok=True)
    apps_dir.mkdir(parents=True, exist_ok=True)
    handler = bin_dir / f"{args.id}-fluxapp-handler.py"
    desktop = apps_dir / f"{args.id}-fluxapp.desktop"
    config = {
        "prefix": str(prefix),
        "exe": win_exe,
        "runner": runner,
        "runner_path": runner_path,
        "steam_root": steam_root(args),
    }

    handler_source = '''#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

CONFIG = json.loads(r''' + repr(json.dumps(config)) + ''')

def main():
    if len(sys.argv) < 2 or not sys.argv[1].startswith("fluxapp://"):
        return 0
    url = sys.argv[1]
    env = os.environ.copy()
    env["WINEPREFIX"] = CONFIG["prefix"]
    env["WINEDEBUG"] = "-all"
    env["STEAM_COMPAT_DATA_PATH"] = CONFIG["prefix"]
    env["STEAM_COMPAT_CLIENT_INSTALL_PATH"] = CONFIG["steam_root"]
    if CONFIG["runner"] == "proton":
        command = [sys.executable, CONFIG["runner_path"], "runinprefix", CONFIG["exe"], url]
    else:
        command = [CONFIG["runner_path"], CONFIG["exe"], url]
    try:
        subprocess.Popen(
            command,
            cwd=str(Path(CONFIG["prefix"]) / "drive_c"),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        log = Path.home() / ".cache/era-fluxapp-handler.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as stream:
            stream.write(f"Could not launch OAuth callback handler: {exc}\\n")
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''
    handler.write_text(handler_source, encoding="utf-8")
    handler.chmod(0o755)

    desktop.write_text(
        "[Desktop Entry]\n"
        f"Name={args.name} Protocol Handler\n"
        "Type=Application\n"
        f"Exec={desktop_quote(str(handler))} %u\n"
        "Terminal=false\n"
        "NoDisplay=true\n"
        "MimeType=x-scheme-handler/fluxapp;\n",
        encoding="utf-8",
    )

    xdg_mime = shutil.which("xdg-mime")
    if not xdg_mime:
        print("Handler files were created, but xdg-mime was not found.", file=sys.stderr)
        print(f"Register manually: xdg-mime default {desktop.name} x-scheme-handler/fluxapp", file=sys.stderr)
        return 1
    try:
        subprocess.run(
            [xdg_mime, "default", desktop.name, "x-scheme-handler/fluxapp"],
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Handler files were created, but registration failed: {exc}", file=sys.stderr)
        return 1

    print(f"Registered fluxapp:// handler: {desktop}")
    print(f"Wine prefix: {prefix}")
    print(f"Era executable: {exe}")
    print(f"Runner: {runner_path} ({runner})")
    print("OAuth URLs are not written to logs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
