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

def install_system_deps():
    """No system dependencies required for Dredge."""
    print("[1/4] System dependencies: none required")

def install_pip_deps():
    """Install Python packages."""
    print("[2/4] Installing Python packages...")
    req = Path(__file__).resolve().parent / "requirements.txt"
    if req.exists():
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages", "-r", str(req)])
    else:
        print("  requirements.txt not found, skipping")

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
