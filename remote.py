import json
import os
import sys
import tempfile
from pathlib import Path


def run_remote_collection(host, username, password, port=5985, use_ssl=False,
                          skip_sections=None, no_hash=False, output_dir=None):
    try:
        import winrm
    except ImportError:
        print("ERROR: pywinrm not installed. Run: pip3 install pywinrm", file=sys.stderr)
        return None

    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"

    session = winrm.Session(
        endpoint,
        auth=(username, password),
        transport="ntlm",
        server_cert_validation="ignore" if use_ssl else "validate",
    )

    script_path = Path(__file__).resolve().parent / "dredge_collect.ps1"
    if not script_path.exists():
        print(f"ERROR: {script_path} not found", file=sys.stderr)
        return None

    script_content = script_path.read_text(encoding="utf-8")

    args = "-Quiet"
    if skip_sections:
        args += f' -Skip {",".join(skip_sections)}'
    if no_hash:
        args += " -NoHash"

    ps_command = f"""
$tempDir = $env:TEMP
$scriptPath = Join-Path $tempDir "dredge_collect_remote.ps1"
$outputPath = $tempDir

@'
{script_content}
'@ | Set-Content -Path $scriptPath -Encoding UTF8

& $scriptPath -OutputPath $outputPath {args}

$outputFile = Get-ChildItem $outputPath -Filter "dredge_collection_*.json" |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($outputFile) {{
    Get-Content $outputFile.FullName -Raw
    Remove-Item $outputFile.FullName -Force -ErrorAction SilentlyContinue
}}
Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
"""

    print(f"Connecting to {endpoint}...")
    result = session.run_ps(ps_command)

    if result.status_code != 0:
        stderr = result.std_err.decode("utf-8", errors="replace") if result.std_err else ""
        print(f"ERROR: Remote execution failed (exit {result.status_code})", file=sys.stderr)
        if stderr:
            print(f"STDERR: {stderr[:500]}", file=sys.stderr)
        return None

    stdout = result.std_out.decode("utf-8", errors="replace") if result.std_out else ""
    if not stdout.strip():
        print("ERROR: No output received from remote host", file=sys.stderr)
        return None

    try:
        collection_data = json.loads(stdout)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse remote JSON output: {e}", file=sys.stderr)
        return None

    if output_dir:
        hostname = collection_data.get("hostname", host)
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = Path(output_dir) / f"dredge_collection_{hostname}_{ts}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(collection_data, indent=2), encoding="utf-8")
        print(f"Collection saved: {out_path}")

    return collection_data
