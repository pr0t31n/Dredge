import uuid
from datetime import datetime, timezone


class BaseAnalyzer:
    def __init__(self, collection_data, hostname, ip, os_info=None, threat_intel=None):
        self.data = collection_data
        self.hostname = hostname
        self.ip = ip
        self.os_info = os_info or {}
        self.ti = threat_intel
        self.findings = []

    def analyze(self):
        raise NotImplementedError

    def _add_finding(self, catalogue_id, title, risk, description, impact,
                     remediation, **kwargs):
        now_iso = datetime.now(timezone.utc).isoformat()
        finding = {
            "id": str(uuid.uuid4()),
            "tool": "dredge",
            "catalogue_id": catalogue_id,
            "title": title,
            "datetime": now_iso,
            "ip": self.ip,
            "port": 0,
            "hostname": self.hostname,
            "risk": risk,
            "command": "dredge_collect.ps1",
            "description": description,
            "impact": impact,
            "sources": "dredge",
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
            "owasp": kwargs.get("owasp", ""),
            "nist": kwargs.get("nist", ""),
            "cwe": kwargs.get("cwe", []),
            "cvss_score": kwargs.get("cvss_score"),
            "cvss_vector": kwargs.get("cvss_vector", ""),
            "confidence": kwargs.get("confidence", "Certain"),
            "remediation_effort": kwargs.get("remediation_effort", ""),
            "remediation_component": kwargs.get("remediation_component", "Configuration"),
            "remediation_category": kwargs.get("remediation_category", ""),
            "mitre_attack": kwargs.get("mitre_attack", []),
            "nist_800_53": kwargs.get("nist_800_53", []),
            "nist_csf2": kwargs.get("nist_csf2", []),
            "pci_dss_4": kwargs.get("pci_dss_4", []),
        }
        self.findings.append(finding)

    def _get_section(self, key, default=None):
        return self.data.get(key, default)

    def _is_server(self):
        product = self.os_info.get("product_type", "")
        if isinstance(product, str):
            return "server" in product.lower()
        if isinstance(product, int):
            return product in (2, 3)
        return False

    def _is_domain_controller(self):
        product = self.os_info.get("product_type", "")
        if isinstance(product, int):
            return product == 2
        if isinstance(product, str):
            return "domain controller" in product.lower()
        return False
