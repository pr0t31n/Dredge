#!/usr/bin/env python3
"""Dredge installer — multi-platform."""
import subprocess, sys, os, shutil
from pathlib import Path

TOOL_NAME = "Dredge"
MIN_PYTHON = (3, 10)


def _run(cmd, check=True):
    print(f"  -> {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)


def _has(binary):
    return shutil.which(binary) is not None


def _pip_installed(pkg_spec):
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "pywinrm": "winrm",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    try:
        return importlib.util.find_spec(mod) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def install_system_deps():
    """No system dependencies required for Dredge."""
    print("[1/4] System dependencies: none required")


def install_pip_deps():
    """Install Python packages, checking each before installing."""
    print("[2/4] Python dependencies...")
    req = Path(__file__).resolve().parent / "requirements.txt"
    if not req.exists():
        print("  requirements.txt not found, skipping")
        return

    pip = [sys.executable, "-m", "pip"]
    for line in req.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if _pip_installed(line):
            print(f"  ✓ {line} already installed")
        else:
            print(f"  Installing {line} …")
            try:
                _run(pip + ["install", "--break-system-packages", line])
            except RuntimeError as exc:
                print(f"  ! pip install failed for {line}: {exc}")


def create_directories():
    """Create required runtime directories."""
    print("[3/4] Creating directories...")
    base = Path(__file__).resolve().parent
    dirs = [
        base / "analyzers",
        base / "threat_intel" / "data",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        print(f"  -> {d}")


def verify_install():
    """Quick verification."""
    print("[4/4] Verifying installation...")
    base = Path(__file__).resolve().parent
    main = base / "dredge.py"
    if not main.exists():
        print(f"  WARNING: {main} not found")
        return
    try:
        import ast
        ast.parse(main.read_text())
        print("  dredge.py syntax OK")
    except SyntaxError as e:
        print(f"  WARNING: dredge.py syntax error: {e}")

    version_file = base / "VERSION"
    if version_file.exists():
        ver = version_file.read_text().strip()
        print(f"  Version: {ver}")
    else:
        print("  WARNING: VERSION file not found")


def main():
    if sys.version_info < MIN_PYTHON:
        print(f"ERROR: Python {'.'.join(map(str, MIN_PYTHON))}+ required")
        sys.exit(1)
    print(f"\n{TOOL_NAME} — Installation\n{'=' * 40}")
    install_system_deps()
    install_pip_deps()
    create_directories()
    verify_install()
    print(f"\n{TOOL_NAME} installed successfully.")
    print("Usage:")
    print("  Import mode:  python3 dredge.py --collection <json_path>")
    print("  Remote mode:  python3 dredge.py --winrm-host <host> --winrm-user <user> --winrm-pass <pass>")
    print("\nPowerShell collector:")
    print("  Run dredge_collect.bat (or .ps1) on the Windows target machine")


if __name__ == "__main__":
    main()
