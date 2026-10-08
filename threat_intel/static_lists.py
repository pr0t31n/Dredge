import json
import ipaddress
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent / "data"

_bad_processes = None
_bad_ips = None
_rmt_software = None
_extensions = None


def _load_json(name):
    p = _DATA_DIR / name
    if p.exists():
        with open(p, "r") as f:
            return json.load(f)
    return []


def _ensure_processes():
    global _bad_processes
    if _bad_processes is None:
        raw = _load_json("known_bad_processes.json")
        _bad_processes = {}
        for entry in raw:
            key = entry["name"].lower()
            _bad_processes[key] = entry
            for alias in entry.get("aliases", []):
                _bad_processes[alias.lower()] = entry


def _ensure_ips():
    global _bad_ips
    if _bad_ips is None:
        raw = _load_json("known_bad_ips.json")
        _bad_ips = []
        for entry in raw:
            ip_str = entry["ip"]
            try:
                net = ipaddress.ip_network(ip_str, strict=False)
                _bad_ips.append((net, entry))
            except ValueError:
                pass


def _ensure_rmt():
    global _rmt_software
    if _rmt_software is None:
        raw = _load_json("known_rmt_software.json")
        _rmt_software = {}
        for entry in raw:
            _rmt_software[entry["name"].lower()] = entry
            if entry.get("process"):
                _rmt_software[entry["process"].lower()] = entry
            if entry.get("service"):
                _rmt_software[entry["service"].lower()] = entry


def _ensure_extensions():
    global _extensions
    if _extensions is None:
        data = _DATA_DIR / "known_extensions.json"
        if data.exists():
            with open(data, "r") as f:
                _extensions = json.load(f)
        else:
            _extensions = {}


def is_known_bad_process(name_or_path):
    _ensure_processes()
    if not name_or_path:
        return False
    name = name_or_path.strip()
    basename = Path(name).name.lower() if "/" in name or "\\" in name else name.lower()
    stem = Path(basename).stem.lower()
    return stem in _bad_processes or basename in _bad_processes


def get_bad_process_info(name_or_path):
    _ensure_processes()
    if not name_or_path:
        return None
    name = name_or_path.strip()
    basename = Path(name).name.lower() if "/" in name or "\\" in name else name.lower()
    stem = Path(basename).stem.lower()
    return _bad_processes.get(stem) or _bad_processes.get(basename)


def is_known_bad_ip(ip):
    _ensure_ips()
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    for net, _entry in _bad_ips:
        if addr in net:
            return True
    return False


def get_bad_ip_info(ip):
    _ensure_ips()
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    for net, entry in _bad_ips:
        if addr in net:
            return entry
    return None


def is_known_bad_hash(sha256):
    return False


def get_rmt_classification(name):
    _ensure_rmt()
    if not name:
        return None
    key = name.strip().lower()
    return _rmt_software.get(key)


def is_known_extension(browser, ext_id):
    _ensure_extensions()
    if not browser or not ext_id:
        return {"known": False, "malicious": False, "name": ""}
    browser_data = _extensions.get(browser.lower(), {})
    for entry in browser_data.get("known_malicious", []):
        if entry["id"] == ext_id:
            return {"known": True, "malicious": True, "name": entry.get("name", ""),
                    "reason": entry.get("reason", "")}
    for entry in browser_data.get("known_legitimate", []):
        if entry["id"] == ext_id:
            return {"known": True, "malicious": False, "name": entry.get("name", "")}
    return {"known": False, "malicious": False, "name": ""}


class ThreatIntelChecker:
    def __init__(self):
        _ensure_processes()
        _ensure_ips()
        _ensure_rmt()
        _ensure_extensions()

    def check_ip(self, ip):
        info = get_bad_ip_info(ip)
        if info:
            return {"is_known_bad": True, "reason": info.get("reason", ""),
                    "category": info.get("category", "")}
        return {"is_known_bad": False}

    def check_process(self, name):
        info = get_bad_process_info(name)
        if info:
            return {"is_known_bad": True, "reason": info.get("reason", ""),
                    "category": info.get("category", "")}
        return {"is_known_bad": False}

    def check_hash(self, sha256):
        return {"is_known_bad": is_known_bad_hash(sha256)}

    def check_extension(self, browser, ext_id):
        return is_known_extension(browser, ext_id)

    def check_rmt(self, name):
        info = get_rmt_classification(name)
        if info:
            return {"is_known_bad": info.get("unauthorized", False),
                    "reason": info.get("reason", ""),
                    "category": info.get("category", "Remote Management")}
        return {"is_known_bad": False}

    def check_domain(self, domain):
        return {"is_known_bad": False}

    def stats(self):
        _ensure_processes()
        _ensure_ips()
        _ensure_rmt()
        _ensure_extensions()
        proc_count = len(_bad_processes) if _bad_processes else 0
        ip_count = len(_bad_ips) if _bad_ips else 0
        rmt_count = len(_rmt_software) if _rmt_software else 0
        ext_count = 0
        if _extensions:
            for browser in _extensions.values():
                if isinstance(browser, dict):
                    ext_count += len(browser.get("known_malicious", []))
        return (f"{proc_count} processes, {ip_count} IP ranges, "
                f"{rmt_count} RMT entries, {ext_count} malicious extensions")
