from analyzers.base import BaseAnalyzer

_UNAUTHORIZED_RMT_TOOLS = {
    "teamviewer": "TeamViewer",
    "anydesk": "AnyDesk",
    "connectwise": "ConnectWise Control",
    "screenconnect": "ConnectWise Control (ScreenConnect)",
    "splashtop": "Splashtop",
    "logmein": "LogMeIn",
    "gotomypc": "GoToMyPC",
    "gotoassist": "GoTo Assist",
    "bomgar": "BeyondTrust (Bomgar)",
    "beyondtrust": "BeyondTrust",
    "dameware": "DameWare",
    "rustdesk": "RustDesk",
    "meshagent": "MeshCentral",
    "ultraviewer": "UltraViewer",
    "ammyy": "Ammyy Admin",
    "supremo": "Supremo",
    "remotepc": "RemotePC",
    "atera": "Atera",
    "n-able": "N-able",
    "zoho assist": "Zoho Assist",
}


class RemoteManagementAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_unauthorized_rmt()
        self._check_rdp()
        self._check_winrm()
        self._check_ssh()
        self._check_multiple_rmt()
        return self.findings

    def _check_unauthorized_rmt(self):
        rmt = self._get_section("remote_management", {})
        tools = rmt.get("tools", [])
        if not isinstance(tools, list):
            tools = []

        installed_sw = self._get_section("installed_software", [])
        if not isinstance(installed_sw, list):
            installed_sw = []

        detected = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            if not name:
                continue
            name_lower = name.lower()
            for key, label in _UNAUTHORIZED_RMT_TOOLS.items():
                if key in name_lower:
                    detected.append(f"{name} (running)")
                    break

        for sw in installed_sw:
            if not isinstance(sw, dict):
                continue
            name = sw.get("name", "")
            if not name:
                continue
            name_lower = name.lower()
            for key, label in _UNAUTHORIZED_RMT_TOOLS.items():
                if key in name_lower:
                    entry = f"{name} (installed)"
                    if entry not in detected and f"{name} (running)" not in detected:
                        detected.append(entry)
                    break

        if self.ti:
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                name = tool.get("name", "")
                process = tool.get("process", "")
                for check_name in (name, process):
                    if check_name:
                        info = self.ti.get_rmt_classification(check_name)
                        if info and info.get("unauthorized", False):
                            entry = f"{check_name} (threat-intel flagged)"
                            if entry not in detected:
                                detected.append(entry)

        if detected:
            tool_list = "\n".join(detected[:15])
            self._add_finding(
                "DR-RMT-001",
                "Unauthorized Remote Management Tool Detected",
                "HIGH",
                f"{len(detected)} unauthorized remote management tool(s) detected on "
                f"the system. These tools allow remote access to the endpoint and may "
                f"not be sanctioned by organizational security policy.",
                "Unauthorized remote access tools can be used by attackers to maintain "
                "persistent access, bypass network security controls, and exfiltrate "
                "data. Even legitimate tools installed without authorization create "
                "an unmonitored remote access channel.",
                "Remove all unauthorized remote access software. Implement application "
                "whitelisting to prevent reinstallation. If remote access is required, "
                "use the organization's approved solution.",
                output=f"Detected tools:\n{tool_list}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1219", "tactic": "Command and Control",
                               "name": "Remote Access Software"}],
                nist_800_53=["CM-7", "CM-11"],
            )

    def _check_rdp(self):
        rmt = self._get_section("remote_management", {})
        rdp = rmt.get("rdp", {})
        if not isinstance(rdp, dict):
            return
        enabled = rdp.get("enabled", False)
        if not enabled:
            return

        nla = rdp.get("nla_required", True)
        risk = "MEDIUM" if nla else "HIGH"
        nla_note = "NLA is enforced." if nla else "NLA is NOT enforced."
        port = rdp.get("port", 3389)

        desc = (
            f"Remote Desktop Protocol (RDP) is enabled on this system (port {port}). "
            f"{nla_note} RDP exposes the system to brute-force attacks, credential "
            f"stuffing, and known RDP vulnerabilities (BlueKeep, DejaBlue)."
        )
        impact = (
            "An attacker who gains RDP access obtains full interactive control of the "
            "system. Without NLA, unauthenticated attackers can reach the login screen "
            "and exploit pre-authentication vulnerabilities."
        )
        remediation = (
            "Disable RDP if not required. If required, enforce Network Level "
            "Authentication (NLA), restrict access via firewall rules to authorized "
            "IP ranges, use an RDP gateway, and enable account lockout policies."
        )
        self._add_finding(
            "DR-RMT-002",
            "RDP Enabled",
            risk,
            desc, impact, remediation,
            output=f"RDP enabled: True\nPort: {port}\nNLA required: {nla}",
            service="rdp",
            port=port,
            remediation_effort="Easy",
            mitre_attack=[{"technique": "T1021.001", "tactic": "Lateral Movement",
                           "name": "Remote Desktop Protocol"}],
            nist_800_53=["AC-17"],
        )

    def _check_winrm(self):
        rmt = self._get_section("remote_management", {})
        winrm = rmt.get("winrm", {})
        if not isinstance(winrm, dict):
            return
        running = winrm.get("running", False)
        if not running:
            return

        allow_unencrypted = winrm.get("allow_unencrypted", False)
        allow_basic = winrm.get("allow_basic", False)
        risk = "HIGH" if (allow_unencrypted or allow_basic) else "MEDIUM"

        issues = []
        if allow_unencrypted:
            issues.append("unencrypted traffic allowed")
        if allow_basic:
            issues.append("basic authentication allowed")
        config_note = ("; ".join(issues)) if issues else "using default security settings"

        self._add_finding(
            "DR-RMT-003",
            "WinRM Service Running",
            risk,
            f"Windows Remote Management (WinRM) is running on this system "
            f"({config_note}). WinRM allows remote command execution via "
            f"PowerShell remoting and is a common lateral movement vector.",
            "An attacker with valid credentials can use WinRM to execute arbitrary "
            "commands remotely. If basic authentication or unencrypted traffic is "
            "allowed, credentials may be captured in transit.",
            "Disable WinRM if not required. If required, enforce HTTPS transport, "
            "disable basic authentication, configure TrustedHosts to restrict "
            "connections, and monitor WinRM event logs.",
            output=f"WinRM running: True\nAllow unencrypted: {allow_unencrypted}\n"
                   f"Allow basic auth: {allow_basic}",
            service="winrm",
            remediation_effort="Moderate",
            mitre_attack=[{"technique": "T1021.006", "tactic": "Lateral Movement",
                           "name": "Windows Remote Management"}],
            nist_800_53=["AC-17", "SC-8"],
        )

    def _check_ssh(self):
        rmt = self._get_section("remote_management", {})
        ssh = rmt.get("ssh", {})
        if not isinstance(ssh, dict):
            return
        enabled = ssh.get("enabled", False)
        if not enabled:
            return

        port = ssh.get("port", 22)
        password_auth = ssh.get("password_authentication", True)
        risk = "MEDIUM" if not password_auth else "MEDIUM"

        auth_note = "Password authentication is enabled." if password_auth else \
            "Key-based authentication only."

        self._add_finding(
            "DR-RMT-004",
            "SSH Server Enabled",
            risk,
            f"An SSH server (OpenSSH) is running on this Windows system (port {port}). "
            f"{auth_note} SSH on Windows endpoints is uncommon and may indicate "
            f"unauthorized installation or persistence.",
            "SSH provides encrypted remote shell access. While more secure than "
            "Telnet, it can be used for lateral movement, tunneling, and persistent "
            "access. On Windows endpoints, SSH is rarely business-justified.",
            "Disable the OpenSSH Server Windows feature if not required. If required, "
            "enforce key-based authentication, disable password login, and restrict "
            "access via firewall rules.",
            output=f"SSH enabled: True\nPort: {port}\nPassword auth: {password_auth}",
            service="ssh",
            port=port,
            remediation_effort="Easy",
            mitre_attack=[{"technique": "T1021.004", "tactic": "Lateral Movement",
                           "name": "SSH"}],
            nist_800_53=["AC-17"],
        )

    def _check_multiple_rmt(self):
        rmt = self._get_section("remote_management", {})
        tools = rmt.get("tools", [])
        if not isinstance(tools, list):
            tools = []

        active_tools = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            if name:
                active_tools.append(name)

        rdp = rmt.get("rdp", {})
        if isinstance(rdp, dict) and rdp.get("enabled", False):
            active_tools.append("RDP")
        winrm = rmt.get("winrm", {})
        if isinstance(winrm, dict) and winrm.get("running", False):
            active_tools.append("WinRM")
        ssh = rmt.get("ssh", {})
        if isinstance(ssh, dict) and ssh.get("enabled", False):
            active_tools.append("SSH")

        if len(active_tools) >= 3:
            tool_list = ", ".join(active_tools[:10])
            self._add_finding(
                "DR-RMT-005",
                "Multiple Remote Management Tools Installed",
                "MEDIUM",
                f"{len(active_tools)} remote management tools or services are active "
                f"on this system: {tool_list}. Multiple remote access vectors increase "
                f"the attack surface and complicate monitoring.",
                "Each remote access tool is an independent attack vector. Multiple "
                "tools make it harder to monitor and control remote access, and "
                "increase the likelihood that at least one has a misconfiguration "
                "or vulnerability.",
                "Standardize on a single, approved remote management solution. "
                "Remove all other remote access tools and disable unnecessary "
                "remote management services.",
                output=f"Active tools ({len(active_tools)}):\n{tool_list}",
                remediation_effort="Moderate",
                nist_800_53=["CM-7"],
            )
