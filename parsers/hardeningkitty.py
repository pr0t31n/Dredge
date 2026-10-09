import uuid
import datetime
import csv
import io
import os

_CATEGORY_MAP = {
    "accountpolicies": "DR-USR",
    "auditpolicies": "DR-HDN-025",
    "securityoptions": "DR-HDN",
    "windowscomponents": "DR-HDN",
    "administrativetemplates": "DR-HDN",
    "firewall": "DR-NET",
    "windowsdefender": "DR-HDN",
    "bitlocker": "DR-SYS",
}

_RISK_MAP = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
}


class HardeningKittyParser:
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
                text = f.read()
        except OSError:
            return self.findings

        try:
            reader = csv.DictReader(io.StringIO(text))
            rows = list(reader)
        except Exception:
            return self.findings

        self._parse_rows(rows)
        return self.findings

    def _parse_rows(self, rows):
        for row in rows:
            result = row.get("Result", "").strip()
            if result.lower() in ("passed", "pass"):
                continue

            severity = row.get("Severity", "").strip()
            risk = _RISK_MAP.get(severity)
            if not risk:
                continue

            hk_id = row.get("ID", "").strip()
            category = row.get("Category", "").strip()
            name = row.get("Name", "").strip()
            expected = row.get("Expected", row.get("RecommendedValue", "")).strip()
            current = row.get("Current", row.get("DefaultValue", "")).strip()

            catalogue_id = self._map_catalogue_id(category, name)

            output_parts = []
            if name:
                output_parts.append(f"Name: {name}")
            output_parts.append(f"Current: {current}")
            output_parts.append(f"Expected: {expected}")
            output_parts.append(f"Result: {result}")

            self._add_finding(
                catalogue_id,
                f"Hardening Check Failed: {name}",
                risk,
                f"HardeningKitty check '{name}' ({hk_id}) in category "
                f"'{category}' did not pass. Current value does not match "
                f"the recommended security baseline.",
                f"This misconfiguration was rated {severity} by HardeningKitty. "
                f"The setting deviates from the recommended security baseline, "
                f"potentially weakening the system's security posture.",
                f"Configure {name} to the expected value: {expected}.",
                output="\n".join(output_parts),
                remediation_effort="Easy",
            )

    def _map_catalogue_id(self, category, name):
        cat_lower = category.lower().replace(" ", "")
        name_lower = name.lower()

        if "enablelua" in name_lower:
            return "DR-HDN-001"
        if "consentpromptbehavioradmin" in name_lower:
            return "DR-HDN-002"
        if "smb1" in name_lower or "smbv1" in name_lower:
            return "DR-HDN-003"
        if "smb signing" in name_lower or "requiresecuritysignature" in name_lower:
            return "DR-HDN-004"
        if "lmcompatibilitylevel" in name_lower or "ntlmv1" in name_lower:
            return "DR-HDN-005"
        if "nolmhash" in name_lower or "lm hash" in name_lower:
            return "DR-HDN-006"
        if "lsa protection" in name_lower or "runasppl" in name_lower:
            return "DR-HDN-007"
        if "wdigest" in name_lower:
            return "DR-HDN-008"
        if "credential guard" in name_lower:
            return "DR-HDN-009"
        if "autorun" in name_lower or "autoplay" in name_lower:
            return "DR-HDN-011"
        if "llmnr" in name_lower:
            return "DR-HDN-012"
        if "wpad" in name_lower:
            return "DR-HDN-013"
        if "powershell" in name_lower and "logging" in name_lower:
            return "DR-HDN-014"
        if "powershell" in name_lower and ("v2" in name_lower or "version 2" in name_lower):
            return "DR-HDN-015"
        if "rdp" in name_lower and "nla" in name_lower:
            return "DR-HDN-016"
        if "dep" in name_lower or "nx" in name_lower:
            return "DR-HDN-017"
        if "firewall" in cat_lower:
            return "DR-NET-002"
        if "audit" in cat_lower:
            return "DR-HDN-025"

        prefix = _CATEGORY_MAP.get(cat_lower, "DR-HDN")
        if prefix == "DR-HDN-025":
            return prefix
        return ""
