import uuid
import datetime
import json
import os

_DANGEROUS_PRIVS = {
    "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
    "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege",
}

_SEVERITY_MAP = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Info": "INFO",
    "Informational": "INFO",
    "None": "INFO",
}


class PrivescCheckParser:
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
            with open(self.file_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return self.findings

        if not isinstance(data, list):
            return self.findings

        for entry in data:
            compliance = str(entry.get("Compliance", "True")).lower()
            if compliance in ("true", "pass", "passed", "1"):
                continue

            category = entry.get("Category", "").strip()
            name = entry.get("DisplayName", entry.get("Name", "")).strip()
            desc = entry.get("Description", "").strip()
            severity = entry.get("Severity", "Medium").strip()
            result = entry.get("ResultRawString", entry.get("Result", ""))

            risk = _SEVERITY_MAP.get(severity, "MEDIUM")
            cat_lower = category.lower()

            # AlwaysInstallElevated → DR-PRIV-001
            if "alwaysinstallelevated" in name.lower():
                self._add_finding(
                    "DR-PRIV-001",
                    "AlwaysInstallElevated Enabled",
                    "CRITICAL",
                    "AlwaysInstallElevated is enabled in both HKLM and HKCU, "
                    "allowing any user to install MSI packages as SYSTEM.",
                    "An attacker can craft a malicious MSI that executes "
                    "arbitrary code with SYSTEM privileges.",
                    "Disable AlwaysInstallElevated in both HKLM and HKCU.",
                    output=str(result)[:500],
                    mitre_attack=[{"technique": "T1548.002",
                                   "tactic": "Privilege Escalation",
                                   "name": "Bypass User Account Control"}],
                )
                continue

            # Services — Unquoted → DR-PRIV-005, Modifiable → DR-PRIV-002
            if cat_lower == "services":
                if "unquoted" in name.lower():
                    self._add_finding(
                        "DR-PRIV-005",
                        f"Unquoted Service Path: {name}",
                        "MEDIUM",
                        f"Service has an unquoted path with spaces. {desc}",
                        "An attacker can place a binary in an intermediate "
                        "directory to hijack service execution.",
                        "Quote the service binary path.",
                        output=str(result)[:500],
                    )
                elif "modifiable" in name.lower() or "permission" in name.lower():
                    self._add_finding(
                        "DR-PRIV-002",
                        f"Modifiable Service: {name}",
                        "HIGH",
                        f"Service with modifiable configuration found. {desc}",
                        "An attacker can modify the service binary or config "
                        "to execute code as the service account.",
                        "Fix service binary permissions. Ensure only "
                        "administrators can modify service configurations.",
                        output=str(result)[:500],
                    )
                else:
                    self._add_finding(
                        "DR-PRIV-002",
                        f"Service Vulnerability: {name}",
                        risk,
                        desc or f"Service check '{name}' failed.",
                        "Service misconfigurations can lead to privilege "
                        "escalation.",
                        "Review and fix the service configuration.",
                        output=str(result)[:500],
                    )
                continue

            # DLL Hijacking → DR-PRIV-003
            if cat_lower == "dll hijacking" or "dll" in name.lower():
                self._add_finding(
                    "DR-PRIV-003",
                    f"DLL Hijacking: {name}",
                    "HIGH",
                    desc or f"DLL hijacking opportunity found: {name}.",
                    "A writable directory in the DLL search path allows code "
                    "execution when a privileged process loads a DLL.",
                    "Remove writable directories from the system PATH.",
                    output=str(result)[:500],
                    mitre_attack=[{"technique": "T1574.001",
                                   "tactic": "Privilege Escalation",
                                   "name": "DLL Search Order Hijacking"}],
                )
                continue

            # Token Privileges → DR-PRIV-004
            if cat_lower == "user" and any(
                    p.lower() in name.lower() for p in _DANGEROUS_PRIVS):
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
                continue

            # Credentials
            if cat_lower == "credentials" or "credential" in name.lower():
                self._add_finding(
                    "DR-CRED-003",
                    f"Credential Exposure: {name}",
                    risk,
                    desc or f"Credential exposure found: {name}.",
                    "Exposed credentials can be used for lateral movement or "
                    "privilege escalation.",
                    "Remove or secure stored credentials.",
                    output=str(result)[:500],
                )
                continue

            # Hardening
            if cat_lower == "hardening":
                cat_id = self._map_hardening(name)
                self._add_finding(
                    cat_id,
                    f"Hardening Issue: {name}",
                    risk,
                    desc or f"Hardening check '{name}' failed.",
                    "System hardening deficiencies increase the attack surface.",
                    "Apply the recommended hardening configuration.",
                    output=str(result)[:500],
                )
                continue

            # Catch-all for HIGH/CRITICAL
            if risk in ("HIGH", "CRITICAL"):
                self._add_finding(
                    "",
                    f"PrivescCheck: {name}",
                    risk,
                    desc or f"PrivescCheck flagged '{name}' in category "
                            f"'{category}' as {severity}.",
                    f"This item was rated {severity} by PrivescCheck.",
                    "Investigate and remediate per PrivescCheck guidance.",
                    output=str(result)[:500],
                )

        return self.findings

    def _map_hardening(self, name):
        nl = name.lower()
        if "uac" in nl:
            return "DR-HDN-001"
        if "smb" in nl and "signing" in nl:
            return "DR-HDN-004"
        if "smb" in nl and "v1" in nl:
            return "DR-HDN-003"
        if "lsa" in nl or "ppl" in nl:
            return "DR-HDN-007"
        if "wdigest" in nl:
            return "DR-HDN-008"
        if "credential guard" in nl:
            return "DR-HDN-009"
        if "bitlocker" in nl:
            return "DR-SYS-009"
        if "defender" in nl:
            return "DR-HDN-019"
        if "firewall" in nl:
            return "DR-NET-002"
        return ""
