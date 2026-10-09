import uuid
import datetime
import json
import os
import re

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

_DANGEROUS_PRIVS = {
    "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
    "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege",
}


class WinPEASParser:
    def __init__(self, file_path, hostname="", ip=""):
        self.file_path = file_path
        self.hostname = hostname
        self.ip = ip
        self.findings = []

    def _add_finding(self, catalogue_id, title, risk, description, impact,
                     remediation, **kwargs):
        finding = {
            "id": str(uuid.uuid4()),
            "tool": "dredge",
            "catalogue_id": catalogue_id,
            "title": title,
            "datetime": datetime.datetime.now().isoformat(),
            "ip": self.ip,
            "port": kwargs.get("port", 0),
            "hostname": self.hostname,
            "risk": risk,
            "command": kwargs.get("command", ""),
            "description": description,
            "impact": impact,
            "sources": kwargs.get("sources", "dredge"),
            "affected": kwargs.get("affected", self.hostname or self.ip),
            "remediation": remediation,
            "exploitdb": kwargs.get("exploitdb", False),
            "metasploit": kwargs.get("metasploit", False),
            "exploit_details": kwargs.get("exploit_details", []),
            "scope": kwargs.get("scope", "endpoint"),
            "output": kwargs.get("output", ""),
            "output_file": kwargs.get("output_file", ""),
            "cves": kwargs.get("cves", ""),
            "service": kwargs.get("service", ""),
            "owasp": kwargs.get("owasp", ""),
            "nist": kwargs.get("nist", ""),
            "cwe": kwargs.get("cwe", []),
            "cvss_score": kwargs.get("cvss_score", None),
            "cvss_vector": kwargs.get("cvss_vector", ""),
            "confidence": kwargs.get("confidence", "Certain"),
            "remediation_effort": kwargs.get("remediation_effort", ""),
            "remediation_component": kwargs.get("remediation_component", ""),
            "remediation_category": kwargs.get("remediation_category", ""),
            "mitre_attack": kwargs.get("mitre_attack", []),
            "nist_800_53": kwargs.get("nist_800_53", []),
            "nist_csf2": kwargs.get("nist_csf2", []),
            "pci_dss_4": kwargs.get("pci_dss_4", []),
        }
        self.findings.append(finding)

    def parse(self):
        if not os.path.isfile(self.file_path):
            return self.findings
        try:
            with open(self.file_path, encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except OSError:
            return self.findings

        raw_stripped = raw.strip()
        if raw_stripped.startswith("{") or raw_stripped.startswith("["):
            try:
                data = json.loads(raw)
                self._parse_json(data)
                return self.findings
            except json.JSONDecodeError:
                pass

        self._parse_text(raw)
        return self.findings

    # ── JSON mode ───────────────────────────────────────────────────────
    def _parse_json(self, data):
        if isinstance(data, dict):
            entries = data.get("Results", data.get("results", []))
            if not isinstance(entries, list):
                entries = [data]
        else:
            entries = data

        for entry in entries:
            cat = entry.get("Category", entry.get("category", "")).lower()
            severity = entry.get("Severity", entry.get("severity", "")).upper()
            name = entry.get("Name", entry.get("name", ""))
            desc = entry.get("Description", entry.get("description", ""))
            result = entry.get("Result", entry.get("result", ""))

            if "alwaysinstallelevated" in name.lower():
                self._add_finding(
                    "DR-PRIV-001",
                    "AlwaysInstallElevated Enabled",
                    "CRITICAL",
                    "AlwaysInstallElevated is enabled in both HKLM and HKCU, "
                    "allowing any user to install MSI packages as SYSTEM.",
                    "An attacker can craft a malicious MSI package that executes "
                    "arbitrary code with SYSTEM privileges.",
                    "Disable AlwaysInstallElevated in both HKLM and HKCU "
                    "registry hives.",
                    output=str(result)[:500],
                    mitre_attack=[{"technique": "T1548.002",
                                   "tactic": "Privilege Escalation",
                                   "name": "Bypass User Account Control"}],
                )
            elif "modifiable service" in name.lower() or \
                    ("service" in cat and severity in ("HIGH", "CRITICAL")):
                self._add_finding(
                    "DR-PRIV-002",
                    f"Modifiable Service: {name}",
                    "HIGH",
                    f"Service '{name}' has a modifiable binary path or "
                    f"configuration. {desc}",
                    "An attacker can replace the service binary or modify its "
                    "configuration to execute arbitrary code as the service account.",
                    "Fix service binary permissions. Ensure only administrators "
                    "can modify service executables and configurations.",
                    output=str(result)[:500],
                )
            elif "unquoted" in name.lower() and "service" in name.lower():
                self._add_finding(
                    "DR-PRIV-005",
                    f"Unquoted Service Path: {name}",
                    "MEDIUM",
                    f"Service '{name}' has an unquoted path with spaces. {desc}",
                    "An attacker can place a binary in an intermediate directory "
                    "of the unquoted path to hijack service execution.",
                    "Quote the service binary path in the service configuration.",
                    output=str(result)[:500],
                )
            elif "dll hijack" in name.lower() or "path dll" in cat.lower():
                self._add_finding(
                    "DR-PRIV-003",
                    f"DLL Hijacking Opportunity: {name}",
                    "HIGH",
                    f"A DLL search order hijacking opportunity was found. {desc}",
                    "An attacker can place a malicious DLL in a writable PATH "
                    "directory to execute code when a privileged process loads it.",
                    "Remove writable directories from the system PATH. Restrict "
                    "write access to directories containing system DLLs.",
                    output=str(result)[:500],
                    mitre_attack=[{"technique": "T1574.001",
                                   "tactic": "Privilege Escalation",
                                   "name": "DLL Search Order Hijacking"}],
                )
            elif any(p.lower() in name.lower() for p in _DANGEROUS_PRIVS):
                self._add_finding(
                    "DR-PRIV-004",
                    "Dangerous Token Privileges Assigned",
                    "HIGH",
                    f"Dangerous privilege detected: {name}. {desc}",
                    "Dangerous token privileges can be abused for privilege "
                    "escalation via impersonation attacks.",
                    "Remove unnecessary privileges from service accounts.",
                    output=str(result)[:500],
                    mitre_attack=[{"technique": "T1134.001",
                                   "tactic": "Privilege Escalation",
                                   "name": "Token Impersonation/Theft"}],
                )
            elif "wifi" in name.lower() or "wireless" in cat.lower():
                self._add_finding(
                    "DR-CRED-001",
                    f"WiFi Password Exposed: {name}",
                    "MEDIUM",
                    f"Stored WiFi password(s) found. {desc}",
                    "Stored WiFi passwords can be extracted by an attacker with "
                    "local access, enabling wireless network compromise.",
                    "Remove stored WiFi profiles that are no longer needed. Use "
                    "enterprise WPA2/3-Enterprise (802.1X) instead of PSK.",
                    output=str(result)[:500],
                )
            elif "credential" in cat or "password" in name.lower():
                self._add_finding(
                    "DR-CRED-002",
                    f"Stored Credentials Found: {name}",
                    "MEDIUM",
                    f"Stored credentials or sensitive data found. {desc}",
                    "Exposed credentials can be used for lateral movement or "
                    "privilege escalation.",
                    "Remove stored credentials and use a secrets management "
                    "solution.",
                    output=str(result)[:500],
                )
            elif severity in ("HIGH", "CRITICAL") and name:
                self._add_finding(
                    "",
                    f"WinPEAS: {name}",
                    severity,
                    desc or f"WinPEAS flagged '{name}' as {severity}.",
                    f"This item was flagged as {severity} by WinPEAS privilege "
                    f"escalation checker.",
                    "Investigate and remediate per WinPEAS recommendation.",
                    output=str(result)[:500],
                )

    # ── Text mode ───────────────────────────────────────────────────────
    def _parse_text(self, raw):
        text = _ANSI_RE.sub("", raw)
        sections = re.split(r'[═]{4,}', text)

        for section in sections:
            lines = section.strip().splitlines()
            if not lines:
                continue
            header = lines[0].strip().lower()

            # AlwaysInstallElevated
            if "alwaysinstallelevated" in header or any(
                    "alwaysinstallelevated" in l.lower() for l in lines):
                for line in lines:
                    if "alwaysinstallelevated" in line.lower() and \
                            ("1" in line or "enabled" in line.lower()):
                        self._add_finding(
                            "DR-PRIV-001",
                            "AlwaysInstallElevated Enabled",
                            "CRITICAL",
                            "AlwaysInstallElevated is enabled, allowing any "
                            "user to install MSI packages as SYSTEM.",
                            "An attacker can craft a malicious MSI that runs "
                            "arbitrary code with SYSTEM privileges.",
                            "Disable AlwaysInstallElevated in HKLM and HKCU.",
                            output=line.strip(),
                        )
                        break

            # Token Privileges
            if "token privileges" in header or "tokenprivileges" in header:
                found_privs = []
                for line in lines:
                    for priv in _DANGEROUS_PRIVS:
                        if priv.lower() in line.lower():
                            found_privs.append(priv)
                if found_privs:
                    self._add_finding(
                        "DR-PRIV-004",
                        "Dangerous Token Privileges Assigned",
                        "HIGH",
                        f"Dangerous privilege(s) found: {', '.join(found_privs)}.",
                        "These privileges can be abused for privilege escalation.",
                        "Remove unnecessary privileges from service accounts.",
                        output="\n".join(found_privs),
                    )

            # Modifiable Services
            if "modifiable service" in header or "services information" in header:
                for line in lines[1:]:
                    if "modifiable" in line.lower() and line.strip():
                        self._add_finding(
                            "DR-PRIV-002",
                            "Modifiable Service Detected",
                            "HIGH",
                            "A service with a modifiable binary path was found.",
                            "An attacker can replace the service binary to "
                            "execute code as the service account.",
                            "Fix service binary permissions.",
                            output=line.strip()[:500],
                        )
                        break

            # Unquoted Service Paths
            if "unquoted service" in header:
                for line in lines[1:]:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("="):
                        self._add_finding(
                            "DR-PRIV-005",
                            "Unquoted Service Path",
                            "MEDIUM",
                            "A service has an unquoted path with spaces.",
                            "An attacker can place a binary in an intermediate "
                            "directory to hijack service execution.",
                            "Quote the service binary path.",
                            output=stripped[:500],
                        )
                        break

            # DLL Hijacking
            if "path dll hijacking" in header or "dll hijack" in header:
                writable_dirs = []
                for line in lines[1:]:
                    stripped = line.strip()
                    if stripped and ("writable" in stripped.lower() or
                                    ":" in stripped):
                        writable_dirs.append(stripped)
                if writable_dirs:
                    self._add_finding(
                        "DR-PRIV-003",
                        "DLL Search Order Hijacking Opportunity",
                        "HIGH",
                        f"{len(writable_dirs)} writable PATH director(ies) found.",
                        "A writable directory in the system PATH allows DLL "
                        "hijacking for privilege escalation.",
                        "Remove writable directories from the system PATH.",
                        output="\n".join(writable_dirs[:15]),
                    )

            # WiFi passwords
            if "wifi" in header or "wireless" in header:
                passwords = []
                for line in lines[1:]:
                    stripped = line.strip()
                    if stripped and ("password" in stripped.lower() or
                                    "key content" in stripped.lower()):
                        passwords.append(stripped)
                if passwords:
                    self._add_finding(
                        "DR-CRED-001",
                        "WiFi Passwords Found",
                        "MEDIUM",
                        f"{len(passwords)} stored WiFi password(s) found.",
                        "Stored WiFi passwords can be extracted by an attacker "
                        "with local access.",
                        "Remove unused WiFi profiles. Use WPA2/3-Enterprise.",
                        output="\n".join(passwords[:20]),
                    )

            # Interesting files / credentials
            if "interesting files" in header or "windows credentials" in header:
                files = []
                for line in lines[1:]:
                    stripped = line.strip()
                    if stripped and ("\\" in stripped or "/" in stripped):
                        files.append(stripped)
                if files:
                    self._add_finding(
                        "DR-CRED-002",
                        "Stored Credentials Found on Disk",
                        "MEDIUM",
                        f"{len(files)} potentially sensitive file(s) found.",
                        "Credential files left on disk can be harvested by "
                        "attackers.",
                        "Remove or secure sensitive files.",
                        output="\n".join(files[:20]),
                    )
