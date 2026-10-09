import uuid
import datetime
import os
import xml.etree.ElementTree as ET

_RISK_ID_MAP = {
    "S-SMB-v1": ("DR-HDN-003", "SMBv1 Protocol Enabled", "MEDIUM"),
    "S-SMB-Signing": ("DR-HDN-004", "SMB Signing Not Required", "MEDIUM"),
    "A-LAPS-NOT-Installed": ("DR-AD-011", "LAPS Not Deployed", "MEDIUM"),
    "A-Krbtgt": ("DR-AD-012", "krbtgt Key Not Rotated", "MEDIUM"),
    "A-DC-Spooler": ("DR-HDN-025", "Print Spooler Running on Domain Controller", "MEDIUM"),
    "A-LMHashAuthorized": ("DR-HDN-006", "LM Hash Storage Permitted", "HIGH"),
    "A-NTLMv1": ("DR-HDN-005", "NTLMv1 Authentication Allowed", "HIGH"),
    "A-AuditPol": ("DR-HDN-025", "Insufficient Audit Policy", "MEDIUM"),
    "S-ADRegistration": ("DR-AD-003", "Unconstrained Delegation", "HIGH"),
    "S-Inactive": ("DR-AD-013", "Stale Domain Accounts", "LOW"),
    "A-PreWin2000": ("DR-AD-009", "Pre-Windows 2000 Compatible Access", "MEDIUM"),
    "A-NoServicePolicy": ("DR-AD-004", "Weak Domain Password Policy", "MEDIUM"),
    "P-AdminNum": ("DR-AD-010", "Excessive Domain Admin Accounts", "MEDIUM"),
    "P-UnkownDelegation": ("DR-AD-003", "Unconstrained Delegation", "HIGH"),
    "P-ControlPathIndirectMany": ("DR-AD-010", "AdminSDHolder Orphans", "LOW"),
    "T-SIDHistory": ("DR-AD-014", "SID History Abuse Risk", "MEDIUM"),
}

_CATEGORY_RISK_MAP = {
    "StaleObjects": "LOW",
    "PrivilegedAccounts": "MEDIUM",
    "Trusts": "MEDIUM",
    "Anomalies": "MEDIUM",
}


class PingCastleParser:
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
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except (ET.ParseError, OSError):
            return self.findings

        self._parse_risk_rules(root)
        self._parse_gpp_passwords(root)
        self._parse_dc_spooler(root)
        self._parse_trusts(root)
        self._parse_scores(root)

        return self.findings

    # ── HealthcheckRiskRules ────────────────────────────────────────────
    def _parse_risk_rules(self, root):
        for rule_el in root.iter("RiskRule"):
            risk_id = self._el_text(rule_el, "RiskId", "")
            category = self._el_text(rule_el, "Category", "")
            rationale = self._el_text(rule_el, "Rationale", "")
            detail = self._el_text(rule_el, "Detail", "")
            points = self._el_text(rule_el, "Points", "0")

            mapped = _RISK_ID_MAP.get(risk_id)
            if mapped:
                cat_id, title, risk = mapped
            else:
                cat_id = ""
                title = f"PingCastle: {risk_id}"
                risk = _CATEGORY_RISK_MAP.get(category, "MEDIUM")
                try:
                    pts = int(points)
                    if pts >= 30:
                        risk = "HIGH"
                    elif pts >= 10:
                        risk = "MEDIUM"
                    elif pts > 0:
                        risk = "LOW"
                    else:
                        risk = "INFO"
                except ValueError:
                    pass

            self._add_finding(
                cat_id,
                title,
                risk,
                rationale or f"PingCastle rule {risk_id} triggered.",
                f"This AD security issue was flagged by PingCastle in the "
                f"'{category}' category with {points} risk point(s). {detail}",
                f"Address the issue identified by PingCastle rule {risk_id}. "
                f"See PingCastle documentation for detailed remediation steps.",
                output=(detail or rationale or "")[:500],
            )

    # ── GPP cpassword ───────────────────────────────────────────────────
    def _parse_gpp_passwords(self, root):
        gpp_entries = []
        for gpp in root.iter("GPPPassword"):
            user = self._el_text(gpp, "UserName", "")
            changed = self._el_text(gpp, "Changed", "")
            gpo = self._el_text(gpp, "GPOName", "")
            if user or gpo:
                gpp_entries.append(
                    f"User: {user} | GPO: {gpo} | Changed: {changed}")

        if gpp_entries:
            self._add_finding(
                "DR-CRED-004",
                "GPP cpassword Credentials Found",
                "CRITICAL",
                f"{len(gpp_entries)} Group Policy Preferences password(s) found "
                f"in SYSVOL. These are encrypted with a publicly known AES key.",
                "GPP cpassword values can be trivially decrypted by any "
                "authenticated domain user using tools like Get-GPPPassword, "
                "granting access to the stored credentials.",
                "Delete all GPP XML files containing cpassword from SYSVOL. "
                "Never use GPP for password distribution. Use LAPS for local "
                "admin password management.",
                output="\n".join(gpp_entries[:15]),
                mitre_attack=[{"technique": "T1552.006",
                               "tactic": "Credential Access",
                               "name": "Group Policy Preferences"}],
            )

    # ── DC Print Spooler ────────────────────────────────────────────────
    def _parse_dc_spooler(self, root):
        for dc in root.iter("DomainController"):
            name = self._el_text(dc, "DCName", "")
            spooler = self._el_text(dc, "PrintSpooler", "")
            if spooler and spooler.lower() in ("true", "running", "1"):
                self._add_finding(
                    "DR-HDN-025",
                    f"Print Spooler Running on DC: {name}",
                    "MEDIUM",
                    f"The Print Spooler service is running on domain controller "
                    f"'{name}'.",
                    "A running Print Spooler on a DC can be abused via "
                    "PrinterBug/SpoolSample to coerce the DC to authenticate "
                    "to an attacker-controlled host.",
                    "Disable the Print Spooler service on all domain "
                    "controllers: Stop-Service Spooler; "
                    "Set-Service Spooler -StartupType Disabled.",
                    affected=name,
                )

    # ── Trust SID Filtering ─────────────────────────────────────────────
    def _parse_trusts(self, root):
        for trust in root.iter("Trust"):
            partner = self._el_text(trust, "TrustPartner", "")
            direction = self._el_text(trust, "TrustDirection", "")
            sid_filter = self._el_text(trust, "SIDFiltering", "")

            if sid_filter and sid_filter.lower() in ("false", "no", "0"):
                self._add_finding(
                    "DR-AD-016",
                    f"SID Filtering Disabled on Trust: {partner}",
                    "HIGH",
                    f"SID filtering is disabled on the trust with '{partner}' "
                    f"(direction: {direction}).",
                    "Without SID filtering, a compromised trusted domain can "
                    "inject arbitrary SIDs into authentication tokens, "
                    "potentially gaining Enterprise Admin access.",
                    "Enable SID filtering on inter-forest trusts: "
                    "netdom trust /quarantine:yes.",
                    output=f"Partner: {partner} | Direction: {direction} | "
                           f"SIDFiltering: {sid_filter}",
                    mitre_attack=[{"technique": "T1134.005",
                                   "tactic": "Privilege Escalation",
                                   "name": "SID-History Injection"}],
                )

    # ── Scores ──────────────────────────────────────────────────────────
    def _parse_scores(self, root):
        scores = {}
        for tag in ("GlobalScore", "StaleObjectsScore",
                    "PrivilegiedGroupScore", "TrustScore", "AnomalyScore"):
            el = root.find(f".//{tag}")
            if el is not None and el.text:
                try:
                    scores[tag] = int(el.text)
                except ValueError:
                    pass

        if scores:
            parts = [f"{k}: {v}/100" for k, v in scores.items()]
            global_score = scores.get("GlobalScore", 0)
            risk = "INFO"
            if global_score >= 75:
                risk = "CRITICAL"
            elif global_score >= 50:
                risk = "HIGH"
            elif global_score >= 25:
                risk = "MEDIUM"
            elif global_score > 0:
                risk = "LOW"

            self._add_finding(
                "",
                "PingCastle AD Security Score",
                risk,
                f"PingCastle assessed the Active Directory security posture. "
                f"Global score: {global_score}/100 (lower is better).",
                "The PingCastle score reflects the overall security health of "
                "the Active Directory environment. High scores indicate "
                "significant security risks.",
                "Address findings identified by PingCastle, prioritizing "
                "those with the highest point values.",
                output="\n".join(parts),
            )

    # ── Helpers ─────────────────────────────────────────────────────────
    def _el_text(self, el, tag, default=""):
        child = el.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default
