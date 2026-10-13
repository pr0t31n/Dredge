#!/usr/bin/env python3
"""Dredge — Windows Endpoint Security Auditor (Analysis Engine)."""
import argparse
import csv
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

MANAGED = os.environ.get("DREDGE_MANAGED") == "1" or os.environ.get("CRUCIBLE_MANAGED") == "1"

try:
    _sp = "/opt/pr0t31n/shared"
    if _sp not in sys.path:
        sys.path.insert(0, _sp)
    import pr0t31n_schema as _us
    import pr0t31n_event_log as _el
    import pr0t31n_pause as _pp
except ImportError:
    _us = None
    _el = None
    _pp = None

_pause: "_pp.PauseManager | None" = None  # type: ignore[name-defined]


def _check_pause():
    if _pause is not None and _pause.check_and_pause():
        sys.exit(_pp.EXIT_PAUSED)

from analyzers.system import SystemAnalyzer
from analyzers.hardening import HardeningAnalyzer
from analyzers.network import NetworkAnalyzer
from analyzers.users import UserAnalyzer
from analyzers.active_directory import ActiveDirectoryAnalyzer as ADAnalyzer
from analyzers.processes import ProcessAnalyzer
from analyzers.browsers import BrowserAnalyzer
from analyzers.remote_mgmt import RemoteManagementAnalyzer
from analyzers.server_software import ServerSoftwareAnalyzer
from analyzers.event_logs import EventLogAnalyzer
from analyzers.software import SoftwareAnalyzer
from analyzers.certificates import CertificateAnalyzer
from analyzers.compliance import ComplianceAnalyzer
from analyzers.credential_exposure import CredentialExposureAnalyzer
from analyzers.privilege_escalation import PrivilegeEscalationAnalyzer
from analyzers.persistence import PersistenceAnalyzer
from analyzers.adcs import ADCSAnalyzer
from analyzers.disk_storage import DiskStorageAnalyzer
from analyzers.hardware import HardwareInventoryAnalyzer

from threat_intel.static_lists import ThreatIntelChecker

try:
    from intel_writer import write_intel_files as _write_intel
except ImportError:
    _write_intel = None
from threat_intel.api_enrichment import enrich_findings


def _log(msg, level="INFO"):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    line = f"[{ts}] {level} {msg}"
    print(line, file=sys.stderr)
    if MANAGED:
        payload = json.dumps({"ts": ts, "msg": msg, "level": level})
        print(f"__CRUCIBLE_LOG__:{payload}", flush=True)


def _status(phase, progress=0, detail=""):
    if MANAGED:
        payload = json.dumps({
            "phase": phase,
            "progress": progress,
            "detail": detail,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        print(f"__CRUCIBLE_STATUS__:{payload}", flush=True)


def load_collection(path):
    p = Path(path)
    if not p.exists():
        print(f"ERROR: Collection file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"ERROR: Failed to parse collection file: {e}", file=sys.stderr)
        sys.exit(1)
    return data


def extract_os_info(data):
    si = data.get("system_info", {})
    return {
        "os_name": si.get("os_name", ""),
        "os_version": si.get("os_version", ""),
        "os_build": si.get("os_build", 0),
        "product_type": si.get("os_product_type", ""),
        "domain_role": si.get("domain_role", ""),
        "is_domain_joined": si.get("is_domain_joined", False),
    }


def run_analyzers(data, hostname, ip, os_info, threat_intel, skip=None):
    skip = set(skip or [])

    analyzer_classes = [
        ("system", SystemAnalyzer),
        ("hardening", HardeningAnalyzer),
        ("network", NetworkAnalyzer),
        ("users", UserAnalyzer),
        ("active_directory", ADAnalyzer),
        ("processes", ProcessAnalyzer),
        ("browsers", BrowserAnalyzer),
        ("remote_mgmt", RemoteManagementAnalyzer),
        ("server_software", ServerSoftwareAnalyzer),
        ("event_logs", EventLogAnalyzer),
        ("software", SoftwareAnalyzer),
        ("certificates", CertificateAnalyzer),
        ("compliance", ComplianceAnalyzer),
        ("credential_exposure", CredentialExposureAnalyzer),
        ("privilege_escalation", PrivilegeEscalationAnalyzer),
        ("persistence", PersistenceAnalyzer),
        ("adcs", ADCSAnalyzer),
        ("disk_storage", DiskStorageAnalyzer),
        ("hardware", HardwareInventoryAnalyzer),
    ]

    all_findings = []
    analyzers_run = []
    analyzers_failed = []

    for name, cls in analyzer_classes:
        if name in skip:
            _log(f"Skipping analyzer: {name}")
            continue

        _status("Analyzing", int(len(analyzers_run) / len(analyzer_classes) * 100), name)
        _log(f"Running analyzer: {name}")

        try:
            analyzer = cls(data, hostname, ip, os_info=os_info, threat_intel=threat_intel)
            findings = analyzer.analyze()
            all_findings.extend(findings)
            analyzers_run.append(name)
            _log(f"  {name}: {len(findings)} findings")
        except Exception as e:
            _log(f"Analyzer {name} failed: {e}", level="ERROR")
            analyzers_failed.append({"analyzer": name, "error": str(e)})

    return all_findings, analyzers_run, analyzers_failed


def build_summary(findings, hostname, ip, os_info, analyzers_run, analyzers_failed,
                  collection_ts, duration):
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = f.get("risk", "INFO").upper()
        if r in risk_counts:
            risk_counts[r] += 1

    return {
        "tool": "dredge",
        "version": VERSION,
        "hostname": hostname,
        "ip": ip,
        "os_name": os_info.get("os_name", ""),
        "os_version": os_info.get("os_version", ""),
        "is_domain_joined": os_info.get("is_domain_joined", False),
        "collection_timestamp": collection_ts,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "analysis_duration_seconds": round(duration, 2),
        "total_findings": len(findings),
        "risk_breakdown": risk_counts,
        "analyzers_run": analyzers_run,
        "analyzers_failed": analyzers_failed,
    }


def write_findings_json(findings, path):
    Path(path).write_text(json.dumps(findings, indent=2), encoding="utf-8")


def write_findings_csv(findings, path):
    if not findings:
        Path(path).write_text("", encoding="utf-8")
        return
    fields = [
        "id", "catalogue_id", "title", "risk", "ip", "port", "hostname",
        "description", "impact", "remediation", "cves", "service",
        "confidence", "remediation_effort", "datetime",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = {}
            for k in fields:
                v = finding.get(k, "")
                if isinstance(v, (list, dict)):
                    v = json.dumps(v)
                row[k] = v
            writer.writerow(row)


def write_output(findings, summary, output_dir, client_short=None, data=None):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    findings_json = out / "findings.json"
    findings_csv = out / "findings.csv"
    summary_json = out / "summary.json"

    write_findings_json(findings, findings_json)
    write_findings_csv(findings, findings_csv)
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if _us:
        try:
            meta = _us.make_meta(
                tool="dredge",
                version=VERSION,
                client_short=client_short or "unknown",
            )
            _us.write_meta(meta, out / "meta.json")
        except Exception:
            pass

    if _write_intel is not None:
        try:
            written = _write_intel(data, out)
            for fn in written:
                _log(f"  {fn}: written")
        except Exception:
            pass

    _log(f"Output written to {out}")
    _log(f"  findings.json: {len(findings)} findings")
    _log(f"  findings.csv: {len(findings)} rows")
    _log(f"  summary.json: written")

    return str(findings_json)


def main():
    parser = argparse.ArgumentParser(
        description=f"Dredge v{VERSION} — Windows Endpoint Security Auditor")
    parser.add_argument("--collection", "-c",
                        help="Path to collection JSON from dredge_collect.ps1")
    parser.add_argument("--winrm-host",
                        help="Target hostname/IP for WinRM remote collection")
    parser.add_argument("--winrm-user",
                        help="WinRM username")
    parser.add_argument("--winrm-pass",
                        help="WinRM password")
    parser.add_argument("--winrm-port", type=int, default=5985,
                        help="WinRM port (default: 5985)")
    parser.add_argument("--winrm-ssl", action="store_true",
                        help="Use HTTPS for WinRM")
    parser.add_argument("--ip", default="",
                        help="Target IP address (overrides collection data)")
    parser.add_argument("--hostname", default="",
                        help="Target hostname (overrides collection data)")
    parser.add_argument("--output-dir", "-o", default=".",
                        help="Output directory for results")
    parser.add_argument("--client", default="",
                        help="Client short name for universal output structure")
    parser.add_argument("--skip-analyzers", nargs="*", default=[],
                        help="Analyzer modules to skip")
    parser.add_argument("--skip-enrichment", action="store_true",
                        help="Skip threat intel API enrichment")
    parser.add_argument("--vt-api-key", default="",
                        help="VirusTotal API key for enrichment")
    parser.add_argument("--abuseipdb-key", default="",
                        help="AbuseIPDB API key for enrichment")
    parser.add_argument("--no-hash", action="store_true",
                        help="Skip process hash checking (passed to remote collection)")
    parser.add_argument("--json", action="store_true",
                        help="Output findings as JSON to stdout")
    parser.add_argument("--parse-seatbelt",
                        help="Path to Seatbelt JSON output to ingest")
    parser.add_argument("--parse-winpeas",
                        help="Path to WinPEAS output to ingest")
    parser.add_argument("--parse-hardeningkitty",
                        help="Path to HardeningKitty CSV output to ingest")
    parser.add_argument("--parse-bloodhound",
                        help="Path to SharpHound JSON export directory to ingest")
    parser.add_argument("--parse-pingcastle",
                        help="Path to PingCastle XML report to ingest")
    parser.add_argument("--parse-privesccheck",
                        help="Path to PrivescCheck JSON output to ingest")
    parser.add_argument("--version", "-V", action="version",
                        version=f"Dredge v{VERSION}")

    args = parser.parse_args()

    _log(f"Dredge v{VERSION} starting")
    _status("Starting", 0, f"Dredge v{VERSION}")
    start_time = datetime.now(timezone.utc)

    global _pause
    _out_dir = Path(args.output_dir).resolve()
    _out_dir.mkdir(parents=True, exist_ok=True)
    if _pp is not None:
        _pause = _pp.PauseManager(_out_dir, "dredge")
        _pause.start_watcher(grace_period=60)
        _pause.log_run_type(False)

    # Load collection data
    if args.collection:
        _log(f"Loading collection from {args.collection}")
        data = load_collection(args.collection)
    elif args.winrm_host:
        _log(f"Running remote collection against {args.winrm_host}")
        _status("Collecting", 0, f"WinRM to {args.winrm_host}")
        if not args.winrm_user or not args.winrm_pass:
            print("ERROR: --winrm-user and --winrm-pass required for remote mode",
                  file=sys.stderr)
            sys.exit(1)
        from remote import run_remote_collection
        data = run_remote_collection(
            args.winrm_host, args.winrm_user, args.winrm_pass,
            port=args.winrm_port, use_ssl=args.winrm_ssl,
            no_hash=args.no_hash, output_dir=args.output_dir,
        )
        if not data:
            sys.exit(1)
    else:
        print("ERROR: Specify --collection <path> or --winrm-host <host>",
              file=sys.stderr)
        sys.exit(1)

    hostname = args.hostname or data.get("hostname", "unknown")
    if args.ip:
        ip = args.ip
    else:
        addrs = data.get("system_info", {}).get("ip_addresses", [])
        ip = addrs[0].get("ip_address", "") if addrs and isinstance(addrs[0], dict) else ""
    if not ip:
        ip = hostname

    os_info = extract_os_info(data)
    collection_ts = data.get("collection_timestamp", start_time.isoformat())

    _log(f"Target: {hostname} ({ip})")
    _log(f"OS: {os_info.get('os_name', 'Unknown')}")
    _log(f"Domain joined: {os_info.get('is_domain_joined', False)}")

    # Initialize threat intelligence
    _status("Analyzing", 5, "Loading threat intelligence")
    ti = ThreatIntelChecker()
    _log(f"Threat intel loaded: {ti.stats()}")

    _check_pause()

    # Run analyzers
    _status("Analyzing", 10, "Running security analyzers")
    findings, analyzers_run, analyzers_failed = run_analyzers(
        data, hostname, ip, os_info, ti, skip=args.skip_analyzers)

    _check_pause()

    # External tool parser ingestion
    _ext_parsers = {
        "seatbelt": ("parsers.seatbelt", "SeatbeltParser", args.parse_seatbelt),
        "winpeas": ("parsers.winpeas", "WinPEASParser", args.parse_winpeas),
        "hardeningkitty": ("parsers.hardeningkitty", "HardeningKittyParser", args.parse_hardeningkitty),
        "bloodhound": ("parsers.bloodhound", "BloodHoundParser", args.parse_bloodhound),
        "pingcastle": ("parsers.pingcastle", "PingCastleParser", args.parse_pingcastle),
        "privesccheck": ("parsers.privesccheck", "PrivescCheckParser", args.parse_privesccheck),
    }
    for pname, (mod_path, cls_name, fpath) in _ext_parsers.items():
        if not fpath:
            continue
        if not Path(fpath).exists():
            _log(f"  {pname}: file not found: {fpath}", level="ERROR")
            continue
        _log(f"Ingesting {pname} output from {fpath}")
        _status("Parsing", 75, f"Ingesting {pname}")
        try:
            import importlib
            mod = importlib.import_module(mod_path)
            parser_cls = getattr(mod, cls_name)
            p = parser_cls(fpath, hostname=hostname, ip=ip)
            ext_findings = p.parse()
            findings.extend(ext_findings)
            _log(f"  {pname}: {len(ext_findings)} findings ingested")
        except Exception as e:
            _log(f"  {pname} parser failed: {e}", level="ERROR")

    # API enrichment
    if not args.skip_enrichment and (args.vt_api_key or args.abuseipdb_key):
        _status("Enriching", 80, "API threat intel enrichment")
        _log("Running API enrichment...")
        findings = enrich_findings(
            findings,
            vt_api_key=args.vt_api_key,
            abuseipdb_key=args.abuseipdb_key,
        )

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

    summary = build_summary(
        findings, hostname, ip, os_info,
        analyzers_run, analyzers_failed,
        collection_ts, duration,
    )

    # Output
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        findings_path = write_output(
            findings, summary, args.output_dir, client_short=args.client, data=data)

    if _pause is not None:
        _pause.write_stop_reason("completed", "all_phases_done")

    _status("Complete", 100, f"{len(findings)} findings")
    _log(f"Analysis complete: {len(findings)} findings in {duration:.1f}s")

    # Summary to stderr
    rc = summary["risk_breakdown"]
    print(f"\nDredge v{VERSION} — Analysis Complete", file=sys.stderr)
    print(f"  Target   : {hostname} ({ip})", file=sys.stderr)
    print(f"  OS       : {os_info.get('os_name', 'Unknown')}", file=sys.stderr)
    print(f"  Duration : {duration:.1f}s", file=sys.stderr)
    print(f"  Findings : {len(findings)} total", file=sys.stderr)
    print(f"    CRITICAL : {rc['CRITICAL']}", file=sys.stderr)
    print(f"    HIGH     : {rc['HIGH']}", file=sys.stderr)
    print(f"    MEDIUM   : {rc['MEDIUM']}", file=sys.stderr)
    print(f"    LOW      : {rc['LOW']}", file=sys.stderr)
    print(f"    INFO     : {rc['INFO']}", file=sys.stderr)
    if analyzers_failed:
        print(f"  Failed   : {len(analyzers_failed)} analyzer(s)", file=sys.stderr)

    if MANAGED:
        payload = json.dumps({
            "findings_path": str(Path(args.output_dir) / "findings.json"),
            "summary_path": str(Path(args.output_dir) / "summary.json"),
            "total_findings": len(findings),
            "risk_breakdown": rc,
        })
        print(f"__CRUCIBLE_RESULT__:{payload}", flush=True)


if __name__ == "__main__":
    main()
