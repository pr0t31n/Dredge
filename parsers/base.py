import uuid
from datetime import datetime, timezone


class BaseParser:
    def __init__(self, hostname="", ip=""):
        self.hostname = hostname
        self.ip = ip
        self.findings = []

    def parse(self, data):
        raise NotImplementedError

    def _make_finding(self, catalogue_id, title, risk, description, impact,
                      remediation, **kwargs):
        finding = {
            "id": str(uuid.uuid4()),
            "tool": "dredge",
            "catalogue_id": catalogue_id,
            "title": title,
            "datetime": datetime.now(timezone.utc).isoformat(),
            "ip": self.ip,
            "port": 0,
            "hostname": self.hostname,
            "risk": risk,
            "command": kwargs.get("source_tool", "external"),
            "description": description,
            "impact": impact,
            "sources": kwargs.get("source_tool", "external"),
            "affected": kwargs.get("affected", self.hostname),
            "remediation": remediation,
            "exploitdb": False,
            "metasploit": False,
            "exploit_details": [],
            "scope": "endpoint",
            "output": kwargs.get("output", ""),
            "output_file": kwargs.get("output_file", ""),
            "cves": kwargs.get("cves", ""),
            "service": kwargs.get("service", ""),
            "confidence": kwargs.get("confidence", "Firm"),
            "remediation_effort": kwargs.get("remediation_effort", ""),
            "remediation_component": kwargs.get("remediation_component", "Configuration"),
            "remediation_category": kwargs.get("remediation_category", ""),
            "mitre_attack": kwargs.get("mitre_attack", []),
            "nist_800_53": kwargs.get("nist_800_53", []),
            "nist_csf2": kwargs.get("nist_csf2", []),
            "pci_dss_4": kwargs.get("pci_dss_4", []),
            "cwe": kwargs.get("cwe", []),
            "cvss_score": kwargs.get("cvss_score"),
            "cvss_vector": kwargs.get("cvss_vector", ""),
        }
        self.findings.append(finding)
        return finding
