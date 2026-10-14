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

_KNOWN_VULNERABLE_SOFTWARE = [
    {"pattern": r"openssl\s*(0\.\d|1\.0\.[0-1])", "name": "OpenSSL < 1.0.2",
     "risk": "CRITICAL", "cves": "CVE-2014-0160,CVE-2014-0224",
     "note": "Heartbleed and CCS injection"},
    {"pattern": r"log4j.*(2\.\d\.\d|2\.1[0-4]\.\d)\b",
     "name": "Log4j < 2.17", "risk": "CRITICAL",
     "cves": "CVE-2021-44228", "note": "Log4Shell RCE"},
    {"pattern": r"7-zip\s*(1[0-8]\.\d|19\.0)", "name": "7-Zip < 21.07",
     "risk": "HIGH", "cves": "CVE-2022-29072",
     "note": "Privilege escalation via Help file"},
    {"pattern": r"putty\s*(0\.[0-6]\d|0\.7[0-7])\b", "name": "PuTTY < 0.78",
     "risk": "HIGH", "cves": "CVE-2023-48795",
     "note": "Terrapin SSH prefix truncation"},
    {"pattern": r"curl\s*(7\.[0-7]\d\.\d|7\.8[0-3]\.\d)\b",
     "name": "curl < 7.84.0", "risk": "HIGH",
     "cves": "CVE-2022-32221", "note": "POST-after-PUT smuggling"},
    {"pattern": r"notepad\+\+\s*[67]\.", "name": "Notepad++ < 8.0",
     "risk": "MEDIUM", "cves": "CVE-2023-40031",
     "note": "Buffer overflow in XML parsing"},
    {"pattern": r"filezilla\s*(3\.[0-4]\d|3\.5[0-5])\b",
     "name": "FileZilla < 3.56", "risk": "MEDIUM",
     "cves": "", "note": "Plaintext credential storage, outdated TLS"},
    {"pattern": r"winscp\s*[45]\.", "name": "WinSCP < 6.0",
     "risk": "MEDIUM", "cves": "", "note": "Outdated; update for TLS 1.3"},
    {"pattern": r"vmware\s*tools\s*(1[01]\.\d|9\.)", "name": "VMware Tools < 12.0",
     "risk": "MEDIUM", "cves": "CVE-2022-31676",
     "note": "Local privilege escalation"},
    {"pattern": r"visual\s*c\+\+\s*200[58]", "name": "VC++ 2005/2008 Runtime",
     "risk": "LOW", "cves": "", "note": "Legacy runtime — may indicate EOL dependency"},
    {"pattern": r"java\s*(6|1\.6)", "name": "Java 6",
     "risk": "CRITICAL", "cves": "CVE-2013-0422",
     "note": "EOL since 2013; dozens of RCE vulns"},
    {"pattern": r"apache\s*tomcat\s*[67]\.", "name": "Apache Tomcat < 8.0",
     "risk": "HIGH", "cves": "CVE-2020-1938",
     "note": "Ghostcat AJP file read/RCE"},
    {"pattern": r"php\s*[567]\.[0-3]", "name": "PHP < 7.4",
     "risk": "HIGH", "cves": "CVE-2019-11043",
     "note": "EOL PHP with known RCE vulnerabilities"},
    {"pattern": r"cisco\s*asdm.*1\.[0-4]\.", "name": "Cisco ASDM-IDM < 1.5",
     "risk": "MEDIUM", "cves": "",
     "note": "Outdated ASDM launcher; update for security patches"},
]

_RISKY_SERVICES = {
    "telnet": ("Telnet", "HIGH", "Plaintext remote access protocol"),
    "tlntsvr": ("Telnet Server", "HIGH", "Plaintext remote access"),
    "snmp": ("SNMP", "MEDIUM", "Community-string auth; v1/v2c send cleartext"),
    "snmptrap": ("SNMP Trap", "MEDIUM", "SNMP trap receiver"),
    "ftpsvc": ("FTP (IIS)", "MEDIUM", "FTP transmits credentials in cleartext"),
    "msftpsvc": ("FTP (IIS)", "MEDIUM", "FTP transmits credentials in cleartext"),
    "iisadmin": ("IIS Admin", "MEDIUM", "Legacy IIS admin service"),
    "smtpsvc": ("SMTP", "MEDIUM", "SMTP service — verify if needed"),
    "remoteregistry": ("Remote Registry", "HIGH", "Allows remote registry editing"),
    "ssdpsrv": ("SSDP Discovery", "LOW", "UPnP discovery — disable on servers"),
    "upnphost": ("UPnP Device Host", "LOW", "UPnP device host"),
    "seclogon": ("Secondary Logon", "MEDIUM", "RunAs service — privesc vector"),
    "iphlpsvc": ("IP Helper", "LOW", "6to4/ISATAP/Teredo tunnel attack surface"),
    "wmsvc": ("Web Management Svc", "MEDIUM", "IIS remote management"),
    "lmhosts": ("NetBIOS Helper", "LOW", "LMHosts resolution"),
    "browser": ("Computer Browser", "LOW", "Legacy browser election protocol"),
    "tapisrv": ("Telephony", "LOW", "TAPI — rarely needed on servers"),
    "fax": ("Fax", "LOW", "Fax service — unnecessary attack surface"),
    "simptcp": ("Simple TCP/IP Svcs", "MEDIUM", "Echo/chargen/daytime — DoS risk"),
    "sacsvr": ("SAC Helper", "MEDIUM", "EMS console access — verify need"),
    "sessionenv": ("Remote Desktop Config", "MEDIUM", "RD session configuration"),
    "termservice": ("Remote Desktop Services", "INFO", "RDP — verify network controls"),
}

_TUNNEL_BYPASS_SOFTWARE = [
    "cloudflared", "ngrok", "localtunnel", "pagekite", "bore",
    "frp", "chisel", "rathole", "zerotier", "tailscale", "hamachi",
    "wireguard",
]

_DEV_TOOLS_PATTERNS = [
    (r"python\s*[23]\.", "Python interpreter"),
    (r"node\.?js|node\s+v", "Node.js runtime"),
    (r"ruby\s*\d", "Ruby interpreter"),
    (r"perl\s*\d", "Perl interpreter"),
    (r"\bphp\s*\d", "PHP runtime"),
    (r"visual\s*studio\s*code|vscode", "VS Code editor"),
    (r"git\s*for\s*windows|git\s*version", "Git for Windows"),
    (r"mingw|cygwin|msys2", "Unix compatibility layer"),
    (r"nmap", "Nmap scanner"),
    (r"wireshark", "Wireshark packet analyzer"),
    (r"burp\s*suite", "Burp Suite"),
    (r"postman", "Postman API client"),
    (r"fiddler", "Fiddler proxy"),
    (r"process\s*(explorer|monitor|hacker)", "Process analysis tool"),
    (r"x64dbg|ollydbg|ida\s*pro|ghidra|dnspy|ilspy|dotpeek",
     "Reverse engineering tool"),
]


class SoftwareAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_eol_software()
        self._check_remote_access_software()
        self._check_suspicious_startup()
        self._check_p2p_software()
        self._check_known_vulnerable_software()
        self._check_risky_services()
        self._check_service_accounts()
        self._check_tunnel_bypass_software()
        self._check_dev_tools_on_server()
        self._check_versionless_software()
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

    # ------------------------------------------------------------------ #
    # DR-SFT-005  Known Vulnerable Software Version
    # ------------------------------------------------------------------ #
    def _check_known_vulnerable_software(self):
        installed = self._get_section("installed_software", [])
        if not isinstance(installed, list):
            return

        vuln_found = []
        seen = set()
        for sw in installed:
            if not isinstance(sw, dict):
                continue
            name = sw.get("name", "")
            if not name:
                continue
            name_lower = name.lower()
            for ventry in _KNOWN_VULNERABLE_SOFTWARE:
                if ventry["name"] in seen:
                    continue
                if re.search(ventry["pattern"], name_lower):
                    version = sw.get("version", "")
                    cve_str = ventry.get("cves", "")
                    line = f"{name} (v{version})"
                    if cve_str:
                        line += f" [{cve_str}]"
                    line += f" — {ventry['note']}"
                    vuln_found.append({
                        "line": line,
                        "risk": ventry["risk"],
                        "cves": cve_str,
                    })
                    seen.add(ventry["name"])
                    break

        if not vuln_found:
            return
        output = "\n".join(v["line"] for v in vuln_found[:20])
        all_cves = ",".join(
            v["cves"] for v in vuln_found if v["cves"])
        worst = "INFO"
        for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if any(v["risk"] == r for v in vuln_found):
                worst = r
                break
        self._add_finding(
            "DR-SFT-005",
            "Software: Known Vulnerable Software Version",
            worst,
            f"{len(vuln_found)} installed software package(s) match known vulnerable "
            f"versions with published CVEs or documented security defects. These "
            f"versions contain exploitable vulnerabilities that have public exploit "
            f"code or proof-of-concept available.",
            "Running software with known vulnerabilities exposes the system to "
            "targeted attacks using publicly available exploit code. Attackers "
            "routinely scan for specific vulnerable software versions and use "
            "automated exploit frameworks (Metasploit, Nuclei) to gain access.",
            "Update all identified software to the latest patched version. Where "
            "an update is not possible, implement compensating controls: restrict "
            "network access to the service, deploy WAF rules, enable exploit "
            "prevention features (EMET/WDEG), and increase monitoring.",
            output=output,
            cves=all_cves,
            remediation_effort="Moderate",
            cwe=["CWE-1104", "CWE-937"],
            nist_800_53=["SI-2", "RA-5"],
            pci_dss_4=["6.3.3"],
        )

    # ------------------------------------------------------------------ #
    # DR-SFT-006  Risky / Unnecessary Services Running
    # ------------------------------------------------------------------ #
    def _check_risky_services(self):
        services = self._get_section("services", [])
        if not isinstance(services, list):
            return

        found_high = []
        found_other = []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            state = (svc.get("status", "") or svc.get("state", "")).upper()
            if state not in ("RUNNING", "RUN"):
                continue
            svc_name = (svc.get("name", "") or "").lower()
            if svc_name in _RISKY_SERVICES:
                label, risk, desc = _RISKY_SERVICES[svc_name]
                display = svc.get("display_name", "") or svc.get("name", "")
                start = svc.get("start_type", "") or svc.get("start_mode", "")
                line = f"{display} ({svc_name}) [{start}] — {desc}"
                if risk in ("HIGH", "CRITICAL"):
                    found_high.append(line)
                else:
                    found_other.append(line)

        if found_high:
            output = "\n".join(found_high[:15])
            self._add_finding(
                "DR-SFT-006",
                "Service: High-Risk Services Running",
                "HIGH",
                f"{len(found_high)} high-risk service(s) are running. These services "
                f"present significant security exposure including plaintext credential "
                f"transmission, remote code execution vectors, or unauthorized remote "
                f"access capabilities.",
                "High-risk services like Telnet, Remote Registry, and SNMP provide "
                "attack vectors that are routinely exploited. Telnet transmits all "
                "data including credentials in cleartext. Remote Registry allows "
                "attackers to read and modify registry settings remotely. SNMP with "
                "default community strings enables network reconnaissance.",
                "Disable unnecessary high-risk services. Replace Telnet with SSH. "
                "Replace SNMP v1/v2c with v3 using authentication and encryption. "
                "Disable Remote Registry unless required by a specific management "
                "tool. Restrict service access via Windows Firewall rules.",
                output=output,
                remediation_effort="Easy",
                cwe=["CWE-319", "CWE-284"],
                mitre_attack=[{"technique": "T1021", "tactic": "Lateral Movement",
                               "name": "Remote Services"}],
                nist_800_53=["CM-7", "SC-8"],
                pci_dss_4=["2.2.4"],
            )

        if found_other:
            output = "\n".join(found_other[:15])
            self._add_finding(
                "DR-SFT-007",
                "Service: Unnecessary Services Running",
                "LOW",
                f"{len(found_other)} unnecessary or legacy service(s) are running. "
                f"While individually low-risk, each running service expands the "
                f"system's attack surface and increases maintenance burden.",
                "Every running service is a potential entry point. Legacy services "
                "like SSDP, UPnP, Computer Browser, and Telephony are rarely needed "
                "on modern servers and can be exploited for reconnaissance, denial "
                "of service, or privilege escalation.",
                "Review each identified service and disable any that are not "
                "required for the system's operational role. Set unnecessary "
                "services to 'Disabled' startup type to prevent reactivation "
                "after reboot.",
                output=output,
                remediation_effort="Easy",
                nist_800_53=["CM-7"],
            )

    # ------------------------------------------------------------------ #
    # DR-SFT-008  Service Running Under Non-Standard User Account
    # ------------------------------------------------------------------ #
    def _check_service_accounts(self):
        services = self._get_section("services", [])
        if not isinstance(services, list):
            return

        _STANDARD = {
            "localsystem", "local system", "nt authority\\system",
            "nt authority\\localservice", "nt authority\\local service",
            "nt authority\\networkservice", "nt authority\\network service",
            "local service", "network service", "system",
            "nt service\\", "",
        }

        non_standard = []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            state = (svc.get("status", "") or svc.get("state", "")).upper()
            if state not in ("RUNNING", "RUN"):
                continue
            account = (svc.get("start_account", "")
                       or svc.get("logon_as", "")
                       or svc.get("start_name", "")
                       or "").strip()
            if not account:
                continue
            acct_lower = account.lower()
            if any(acct_lower == s or acct_lower.startswith(s)
                   for s in _STANDARD if s):
                continue
            display = svc.get("display_name", "") or svc.get("name", "")
            non_standard.append(f"{display} — runs as: {account}")

        if non_standard:
            output = "\n".join(non_standard[:15])
            risk = "HIGH" if len(non_standard) >= 5 else "MEDIUM"
            self._add_finding(
                "DR-SFT-008",
                "Service: Non-Standard Service Account",
                risk,
                f"{len(non_standard)} service(s) run under user accounts rather than "
                f"standard service accounts (LocalSystem, LocalService, "
                f"NetworkService). Services running under domain or local user "
                f"accounts may have excessive privileges and their credentials "
                f"are cached on the system.",
                "Services running under user accounts cache the account's "
                "credentials in memory (extractable via Mimikatz/LSASS dump). "
                "If the service account has domain admin or other elevated "
                "privileges, compromising this host yields those credentials. "
                "Service accounts often have weak, non-rotating passwords.",
                "Migrate services to Managed Service Accounts (gMSA) where "
                "possible. For services that must use a user account, ensure: "
                "the account has minimal privileges (least privilege principle), "
                "the password is long and rotated regularly, the account is "
                "denied interactive logon, and the account is not a member of "
                "Domain Admins or other privileged groups.",
                output=output,
                remediation_effort="Moderate",
                cwe=["CWE-269", "CWE-522"],
                mitre_attack=[{"technique": "T1003.001", "tactic": "Credential Access",
                               "name": "LSASS Memory"}],
                nist_800_53=["AC-6", "IA-5"],
                pci_dss_4=["7.2.1"],
            )

    # ------------------------------------------------------------------ #
    # DR-SFT-009  Network Tunnel / Bypass Software
    # ------------------------------------------------------------------ #
    def _check_tunnel_bypass_software(self):
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
            for tunnel in _TUNNEL_BYPASS_SOFTWARE:
                if tunnel in name_lower:
                    version = sw.get("version", "")
                    found.append(f"{name} (v{version})")
                    break

        svcs = self._get_section("services", [])
        if isinstance(svcs, list):
            for svc in svcs:
                if not isinstance(svc, dict):
                    continue
                svc_name = (svc.get("name", "") or "").lower()
                display = (svc.get("display_name", "") or "").lower()
                state = (svc.get("status", "") or svc.get("state", "")).upper()
                if state not in ("RUNNING", "RUN"):
                    continue
                for tunnel in _TUNNEL_BYPASS_SOFTWARE:
                    if tunnel in svc_name or tunnel in display:
                        disp = svc.get("display_name", "") or svc.get("name", "")
                        entry = f"[service] {disp} ({svc_name})"
                        if entry not in found:
                            found.append(entry)
                        break

        if found:
            output = "\n".join(found[:10])
            self._add_finding(
                "DR-SFT-009",
                "Software: Network Tunnel / Bypass Tool",
                "HIGH",
                f"{len(found)} network tunneling or VPN bypass tool(s) detected. "
                f"These tools can create encrypted tunnels that bypass firewall "
                f"rules, IDS/IPS inspection, and network segmentation controls.",
                "Tunnel and overlay network software (cloudflared, ngrok, "
                "ZeroTier, Tailscale, Chisel, etc.) creates encrypted channels "
                "that bypass perimeter security. An attacker with access to the "
                "endpoint can use these tools to establish persistent outbound "
                "command-and-control channels or expose internal services to the "
                "internet without firewall approval.",
                "Remove unauthorized tunnel software. If the tool is operationally "
                "required (e.g., Cloudflare Tunnel for published services), ensure "
                "it is documented, access-controlled, and monitored. Block known "
                "tunnel endpoints at the firewall. Deploy application control to "
                "prevent unauthorized installation.",
                output=output,
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1572", "tactic": "Command and Control",
                               "name": "Protocol Tunneling"}],
                nist_800_53=["CM-7", "SC-7"],
            )

    # ------------------------------------------------------------------ #
    # DR-SFT-010  Development / Offensive Tools on Production Server
    # ------------------------------------------------------------------ #
    def _check_dev_tools_on_server(self):
        if not self._is_server():
            return

        installed = self._get_section("installed_software", [])
        if not isinstance(installed, list):
            return

        found = []
        seen = set()
        for sw in installed:
            if not isinstance(sw, dict):
                continue
            name = sw.get("name", "")
            if not name:
                continue
            name_lower = name.lower()
            for pattern, tool_desc in _DEV_TOOLS_PATTERNS:
                if tool_desc in seen:
                    continue
                if re.search(pattern, name_lower):
                    version = sw.get("version", "")
                    found.append(f"{name} (v{version}) — {tool_desc}")
                    seen.add(tool_desc)
                    break

        if found:
            output = "\n".join(found[:15])
            self._add_finding(
                "DR-SFT-010",
                "Software: Development/Diagnostic Tools on Server",
                "MEDIUM",
                f"{len(found)} development, diagnostic, or offensive security "
                f"tool(s) found on a production server. These tools are commonly "
                f"used by attackers for post-exploitation (compilers for malware, "
                f"packet analyzers for credential capture, debuggers for memory "
                f"dumping).",
                "Development tools on production servers lower the bar for "
                "post-exploitation. An attacker who gains initial access can "
                "use installed compilers to build custom malware, packet "
                "analyzers to capture credentials, and debuggers to dump "
                "process memory — all without downloading additional tooling "
                "that might trigger endpoint detection.",
                "Remove unnecessary development, diagnostic, and security tools "
                "from production servers. Development should occur in isolated "
                "environments. If tools are required for operational purposes, "
                "document the business justification and restrict access via "
                "file system ACLs.",
                output=output,
                remediation_effort="Easy",
                cwe=["CWE-489"],
                mitre_attack=[{"technique": "T1588.002", "tactic": "Resource Development",
                               "name": "Obtain Capabilities: Tool"}],
                nist_800_53=["CM-7", "CM-11"],
            )

    # ------------------------------------------------------------------ #
    # DR-SFT-011  Software with No Version Information
    # ------------------------------------------------------------------ #
    def _check_versionless_software(self):
        installed = self._get_section("installed_software", [])
        if not isinstance(installed, list):
            return

        _IGNORE = {
            "microsoft", "windows", "update for", "security update",
            "hotfix", "kb", "service pack",
        }

        versionless = []
        for sw in installed:
            if not isinstance(sw, dict):
                continue
            name = sw.get("name", "")
            version = sw.get("version", "")
            if not name:
                continue
            if version and version.strip():
                continue
            name_lower = name.lower()
            if any(ign in name_lower for ign in _IGNORE):
                continue
            publisher = sw.get("publisher", "") or ""
            versionless.append(f"{name} (publisher: {publisher or 'unknown'})")

        if len(versionless) < 2:
            return
        output = "\n".join(versionless[:15])
        self._add_finding(
            "DR-SFT-011",
            "Software: Unversioned Software Installed",
            "INFO",
            f"{len(versionless)} software package(s) have no version information "
            f"in the Windows registry. This makes vulnerability assessment "
            f"impossible and may indicate manually installed, sideloaded, "
            f"or malicious software.",
            "Software without version metadata cannot be checked against "
            "vulnerability databases (CVE, NVD). This is common with "
            "sideloaded applications, portable tools, or software installed "
            "outside of standard deployment channels. Malware that registers "
            "itself in the Uninstall registry key often omits version data.",
            "Investigate each unversioned application: verify its purpose, "
            "check the install location for unsigned executables, compare "
            "file hashes against known-good baselines. Remove any software "
            "that cannot be identified or justified.",
            output=output,
            remediation_effort="Easy",
            nist_800_53=["CM-8", "CM-11"],
        )
