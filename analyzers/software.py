import re
from analyzers.base import BaseAnalyzer

_EOL_SOFTWARE = [
    {"pattern": r"java\s*(7|1\.7)", "name": "Java 7", "eol": "2015-04"},
    {"pattern": r"java\s*(8|1\.8)", "name": "Java 8", "eol": "2030-12",
     "note": "commercial license required since 2019-04"},
    {"pattern": r"adobe\s*flash\s*player", "name": "Adobe Flash Player",
     "eol": "2020-12"},
    {"pattern": r"adobe\s*reader\s*(9|1[0-4]|[xX]{1,2})\b",
     "name": "Adobe Reader (pre-DC)", "eol": "2020-04"},
    {"pattern": r"adobe\s*acrobat\s*(9|1[0-4]|[xX]{1,2})\b",
     "name": "Adobe Acrobat (pre-DC)", "eol": "2020-04"},
    {"pattern": r"python\s*2\.", "name": "Python 2.x", "eol": "2020-01"},
    {"pattern": r"microsoft\s*silverlight", "name": "Microsoft Silverlight",
     "eol": "2021-10"},
    {"pattern": r"\.net\s*framework\s*(1\.|2\.|3\.|4\.[0-7](?:\.|$))",
     "name": ".NET Framework < 4.8", "eol": "varies"},
    {"pattern": r"visual\s*basic\s*6|vb\s*6\.0", "name": "Visual Basic 6",
     "eol": "2008-04"},
    {"pattern": r"visual\s*studio\s*200[0-8]", "name": "Visual Studio (pre-2010)",
     "eol": "varies"},
    {"pattern": r"internet\s*explorer", "name": "Internet Explorer",
     "eol": "2022-06"},
    {"pattern": r"office\s*(2007|2010|2013|2016)\b",
     "name": "Microsoft Office (pre-2019)", "eol": "varies"},
    {"pattern": r"windows\s*media\s*player\s*(10|11)\b",
     "name": "Windows Media Player (legacy)", "eol": "varies"},
    {"pattern": r"oracle\s*database\s*(10|11)\b",
     "name": "Oracle Database (pre-12c)", "eol": "varies"},
]

_REMOTE_ACCESS_TOOLS = [
    "teamviewer", "anydesk", "connectwise", "screenconnect", "splashtop",
    "logmein", "gotomypc", "gotoassist", "bomgar", "beyondtrust",
    "dameware", "rustdesk", "meshagent", "ultraviewer", "ammyy",
    "supremo", "remotepc", "atera", "n-able", "zoho assist",
    "radmin", "tigervnc", "tightvnc", "realvnc",
]

_P2P_TORRENT_SOFTWARE = [
    "utorrent", "bittorrent", "qbittorrent", "deluge", "transmission",
    "vuze", "frostwire", "limewire", "emule", "shareaza", "ares galaxy",
    "tixati", "biglybt", "tribler",
]

_SUSPICIOUS_STARTUP_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp",
    r"\\downloads\\", r"\\public\\", r"\\users\\public",
    r"\\programdata\\(?!microsoft)",
    r"\\recycle", r"%temp%", r"%tmp%",
]


class SoftwareAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_eol_software()
        self._check_remote_access_software()
        self._check_suspicious_startup()
        self._check_p2p_software()
        return self.findings

    def _check_eol_software(self):
        installed = self._get_section("installed_software", [])
        if not isinstance(installed, list):
            return

        eol_found = []
        seen_names = set()
        for sw in installed:
            if not isinstance(sw, dict):
                continue
            name = sw.get("name", "")
            if not name:
                continue
            name_lower = name.lower()
            for eol_entry in _EOL_SOFTWARE:
                if eol_entry["name"] in seen_names:
                    continue
                if re.search(eol_entry["pattern"], name_lower):
                    version = sw.get("version", "")
                    eol_found.append(
                        f"{name} (v{version}) — EOL: {eol_entry['eol']}")
                    seen_names.add(eol_entry["name"])
                    break

        if eol_found:
            output = "\n".join(eol_found[:15])
            risk = "HIGH" if len(eol_found) >= 3 else "MEDIUM"
            self._add_finding(
                "DR-SFT-001",
                "EOL Software: End-of-Life Software Installed",
                risk,
                f"{len(eol_found)} end-of-life or unsupported software package(s) "
                f"detected. EOL software no longer receives security patches, leaving "
                f"known vulnerabilities permanently unresolved.",
                "End-of-life software contains publicly known vulnerabilities that "
                "will never be patched. Attackers target EOL software because exploit "
                "code is widely available and defenses will never be updated.",
                "Uninstall or upgrade all EOL software to currently supported "
                "versions. Where upgrade is not possible, isolate the system and "
                "implement compensating controls (application whitelisting, network "
                "segmentation).",
                output=output,
                remediation_effort="Moderate",
                cwe=["CWE-1104"],
                nist_800_53=["SA-22", "SI-2"],
            )

    def _check_remote_access_software(self):
        installed = self._get_section("installed_software", [])
        if not isinstance(installed, list):
            return

        found = []
        for sw in installed:
            if not isinstance(sw, dict):
                continue
            name = sw.get("name", "")
            if not name:
                continue
            name_lower = name.lower()
            for ra_tool in _REMOTE_ACCESS_TOOLS:
                if ra_tool in name_lower:
                    version = sw.get("version", "")
                    found.append(f"{name} (v{version})")
                    break

        if found:
            output = "\n".join(found[:10])
            self._add_finding(
                "DR-SFT-002",
                "Software: Remote Access Software",
                "MEDIUM",
                f"{len(found)} remote access software package(s) found in installed "
                f"programs. These applications allow remote control of the endpoint "
                f"and may not be part of the approved software baseline.",
                "Unauthorized remote access software creates unmonitored backdoor "
                "channels into the network. Attackers also abuse legitimate remote "
                "access tools for persistent access.",
                "Verify each remote access tool is authorized per the organization's "
                "software policy. Remove unauthorized tools and implement application "
                "control policies to prevent reinstallation.",
                output=output,
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1219", "tactic": "Command and Control",
                               "name": "Remote Access Software"}],
                nist_800_53=["CM-7", "CM-11"],
            )

    def _check_suspicious_startup(self):
        startup = self._get_section("startup_items", [])
        if not isinstance(startup, list):
            return

        suspicious = []
        for item in startup:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            command = item.get("command", "") or item.get("path", "")
            location = item.get("location", "")
            if not command:
                continue
            command_lower = command.lower().replace("/", "\\")
            for pattern in _SUSPICIOUS_STARTUP_PATHS:
                if re.search(pattern, command_lower, re.IGNORECASE):
                    loc = location or "unknown"
                    suspicious.append(f"{name}: {command} (location: {loc})")
                    break

        if suspicious:
            output = "\n".join(suspicious[:10])
            self._add_finding(
                "DR-SFT-003",
                "Software: Suspicious Startup Item",
                "HIGH",
                f"{len(suspicious)} startup item(s) reference executables in unusual "
                f"locations (temp directories, Downloads, Public folders). Legitimate "
                f"software typically installs to Program Files.",
                "Malware frequently persists via Run registry keys pointing to "
                "executables in temporary or user-writable directories. These "
                "locations bypass standard file system permissions and allow "
                "unprivileged modification.",
                "Investigate each suspicious startup entry. Verify the executable's "
                "digital signature and purpose. Remove unauthorized entries from "
                "Run/RunOnce registry keys and Startup folders.",
                output=output,
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1547.001", "tactic": "Persistence",
                               "name": "Registry Run Keys / Startup Folder"}],
                nist_800_53=["SI-4", "CM-3"],
            )

    def _check_p2p_software(self):
        installed = self._get_section("installed_software", [])
        if not isinstance(installed, list):
            return

        found = []
        for sw in installed:
            if not isinstance(sw, dict):
                continue
            name = sw.get("name", "")
            if not name:
                continue
            name_lower = name.lower()
            for p2p in _P2P_TORRENT_SOFTWARE:
                if p2p in name_lower:
                    version = sw.get("version", "")
                    found.append(f"{name} (v{version})")
                    break

        if found:
            output = "\n".join(found[:5])
            self._add_finding(
                "DR-SFT-004",
                "Software: P2P/Torrent Software",
                "MEDIUM",
                f"{len(found)} peer-to-peer or torrent client(s) installed: "
                f"{', '.join(found[:3])}. P2P software is commonly prohibited in "
                f"enterprise environments due to data leakage and malware risks.",
                "P2P software can inadvertently share sensitive files, consume "
                "excessive bandwidth, download malware-laden content, and violate "
                "software licensing agreements. Many P2P clients also expose local "
                "files to the network by default.",
                "Uninstall all P2P and torrent software. Block P2P protocols at the "
                "firewall. Implement application control policies to prevent "
                "reinstallation.",
                output=output,
                remediation_effort="Easy",
                nist_800_53=["CM-7", "CM-11"],
            )
