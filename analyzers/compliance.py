from analyzers.base import BaseAnalyzer


class ComplianceAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_firewall_disabled()
        self._check_screen_lock_timeout()
        self._check_netbios()
        self._check_ipv6_transition()
        self._check_remote_registry()
        return self.findings

    def _check_firewall_disabled(self):
        fw = self._get_section("firewall", {})
        profiles = fw.get("profiles", {})
        if not isinstance(profiles, dict):
            return

        disabled = []
        for name in ("Domain", "Private", "Public"):
            profile = profiles.get(name, {})
            if not isinstance(profile, dict):
                continue
            enabled = profile.get("enabled", True)
            if enabled is False or str(enabled).lower() in ("false", "0", "off"):
                disabled.append(name)

        if disabled:
            profile_list = ", ".join(disabled)
            risk = "CRITICAL" if "Public" in disabled else "HIGH"
            self._add_finding(
                "DR-CMP-001",
                "Firewall Profile Disabled",
                risk,
                f"The following Windows Firewall profile(s) are disabled: "
                f"{profile_list}. This violates CIS Benchmark, STIG, and Microsoft "
                f"Security Baseline requirements for host-based firewall enforcement.",
                "Disabled firewall profiles allow unrestricted inbound and outbound "
                "network traffic, exposing all running services and enabling "
                "unrestricted data exfiltration. The Public profile being disabled "
                "is especially dangerous on mobile endpoints.",
                "Enable all Windows Firewall profiles via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Windows Defender Firewall. CIS Benchmark: Ensure Windows Firewall "
                "is set to 'On' for all profiles.",
                output=f"Disabled profiles: {profile_list}",
                remediation_effort="Easy",
                nist_800_53=["SC-7"],
                pci_dss_4=["1.4.1"],
                nist_csf2=["PR.AC-5"],
            )

    def _check_screen_lock_timeout(self):
        hardening = self._get_section("registry_hardening", {})

        timeout_seconds = hardening.get("screen_lock_timeout_seconds")
        screensaver_active = hardening.get("screensaver_active")
        screensaver_secure = hardening.get("screensaver_secure")
        inactivity_timeout = hardening.get("inactivity_timeout_seconds")

        timeout = None
        if timeout_seconds is not None:
            try:
                timeout = int(timeout_seconds)
            except (ValueError, TypeError):
                pass
        elif inactivity_timeout is not None:
            try:
                timeout = int(inactivity_timeout)
            except (ValueError, TypeError):
                pass

        not_configured = (timeout is None and screensaver_active is not True)
        too_long = (timeout is not None and timeout > 900)
        not_secured = (screensaver_active is True and screensaver_secure is not True)

        if not_configured:
            self._add_finding(
                "DR-CMP-002",
                "Screen Lock Timeout Not Configured",
                "MEDIUM",
                "No screen lock or inactivity timeout is configured. The workstation "
                "will not automatically lock when left unattended, violating CIS "
                "Benchmark and STIG requirements.",
                "An unlocked unattended workstation allows any passerby to access "
                "the user's session, including open applications, email, network "
                "shares, and cached credentials.",
                "Configure screen saver timeout via Group Policy: User Configuration > "
                "Administrative Templates > Control Panel > Personalization. Set "
                "'Screen saver timeout' to 900 seconds (15 minutes) or less, enable "
                "'Password protect the screen saver', and enable 'Enable screen saver'.",
                remediation_effort="Easy",
                nist_800_53=["AC-11"],
                pci_dss_4=["8.2.8"],
            )
        elif too_long:
            minutes = timeout // 60
            self._add_finding(
                "DR-CMP-002",
                "Screen Lock Timeout Exceeds 15 Minutes",
                "MEDIUM",
                f"The screen lock inactivity timeout is set to {timeout} seconds "
                f"({minutes} minutes), which exceeds the CIS Benchmark and STIG "
                f"maximum of 900 seconds (15 minutes).",
                "An excessively long inactivity timeout increases the window during "
                "which an unattended workstation can be accessed by unauthorized "
                "individuals.",
                "Reduce the screen lock timeout to 900 seconds (15 minutes) or less. "
                "Configure via Group Policy or the ScreenSaveTimeOut registry value. "
                "Many compliance frameworks recommend 600 seconds (10 minutes).",
                output=f"Current timeout: {timeout}s ({minutes} min)\n"
                       f"Maximum allowed: 900s (15 min)",
                remediation_effort="Easy",
                nist_800_53=["AC-11"],
                pci_dss_4=["8.2.8"],
            )
        elif not_secured:
            self._add_finding(
                "DR-CMP-002",
                "Screen Saver Not Password-Protected",
                "MEDIUM",
                "The screen saver is enabled but not configured to require a password "
                "on resume. The workstation will display the screen saver but not lock.",
                "Without password protection on resume, the screen saver provides no "
                "security benefit. Anyone can dismiss it and access the active session.",
                "Enable 'Password protect the screen saver' via Group Policy or set "
                "the ScreenSaverIsSecure registry value to 1.",
                remediation_effort="Easy",
                nist_800_53=["AC-11"],
            )

    def _check_netbios(self):
        net_config = self._get_section("network_config", {})

        netbios_enabled = net_config.get("netbios_over_tcpip", None)
        if netbios_enabled is None:
            adapters = net_config.get("adapters", [])
            if isinstance(adapters, list):
                for adapter in adapters:
                    if not isinstance(adapter, dict):
                        continue
                    nb = adapter.get("netbios_over_tcpip")
                    if nb is True or str(nb).lower() in ("enabled", "true", "default"):
                        netbios_enabled = True
                        break

        if netbios_enabled is True:
            self._add_finding(
                "DR-CMP-003",
                "NetBIOS over TCP/IP Enabled",
                "MEDIUM",
                "NetBIOS over TCP/IP is enabled on one or more network adapters. "
                "NetBIOS is a legacy protocol that exposes the system to name "
                "spoofing, enumeration, and relay attacks.",
                "NetBIOS name resolution is vulnerable to spoofing attacks (similar to "
                "LLMNR/NBT-NS poisoning), allowing attackers to intercept "
                "authentication traffic and capture NTLMv2 hashes. Responder and "
                "similar tools exploit this by default.",
                "Disable NetBIOS over TCP/IP on all network adapters: Network adapter "
                "properties > IPv4 > Advanced > WINS tab > Disable NetBIOS over "
                "TCP/IP. For domain environments, configure via DHCP option 001 or "
                "Group Policy registry preference.",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1557.001", "tactic": "Credential Access",
                               "name": "LLMNR/NBT-NS Poisoning and SMB Relay"}],
                nist_800_53=["CM-7", "SC-7"],
            )

    def _check_ipv6_transition(self):
        net_config = self._get_section("network_config", {})
        registry = self._get_section("registry_hardening", {})

        transition_techs = []

        teredo = (net_config.get("teredo_enabled")
                  or registry.get("teredo_enabled"))
        if teredo is True or str(teredo).lower() in ("client", "enterpriseclient",
                                                      "enabled", "true"):
            transition_techs.append("Teredo")

        isatap = (net_config.get("isatap_enabled")
                  or registry.get("isatap_enabled"))
        if isatap is True or str(isatap).lower() in ("enabled", "true"):
            transition_techs.append("ISATAP")

        sixto4 = (net_config.get("6to4_enabled")
                  or registry.get("6to4_enabled"))
        if sixto4 is True or str(sixto4).lower() in ("enabled", "true"):
            transition_techs.append("6to4")

        if transition_techs:
            tech_list = ", ".join(transition_techs)
            self._add_finding(
                "DR-CMP-004",
                "IPv6 Transition Technologies Enabled",
                "MEDIUM",
                f"The following IPv6 transition technologies are enabled: {tech_list}. "
                f"These mechanisms tunnel IPv6 traffic over IPv4, often bypassing "
                f"firewall rules and IDS/IPS that only inspect IPv4.",
                "IPv6 transition technologies (Teredo, ISATAP, 6to4) create tunneled "
                "communication channels that bypass IPv4 security controls. Attackers "
                "can use these tunnels for covert communication and data exfiltration.",
                "Disable all IPv6 transition technologies unless explicitly required. "
                "Via netsh: 'netsh interface teredo set state disabled', "
                "'netsh interface ipv6 isatap set state disabled', "
                "'netsh interface ipv6 6to4 set state disabled'. Via GPO: "
                "configure DisabledComponents registry value.",
                output=f"Enabled technologies: {tech_list}",
                remediation_effort="Easy",
                nist_800_53=["CM-7", "SC-7"],
                nist_csf2=["PR.AC-5"],
            )

    def _check_remote_registry(self):
        services = self._get_section("services", [])
        if not isinstance(services, list):
            return

        for svc in services:
            if not isinstance(svc, dict):
                continue
            name = svc.get("name", "").lower()
            display = svc.get("display_name", "").lower()
            if name == "remoteregistry" or "remote registry" in display:
                status = svc.get("status", "").lower()
                start_type = svc.get("start_type", "").lower()
                if status in ("running", "started") or start_type in (
                        "automatic", "auto", "manual"):
                    running = status in ("running", "started")
                    state_text = "running" if running else f"stopped but set to {start_type}"
                    self._add_finding(
                        "DR-CMP-005",
                        "Remote Registry Service Enabled",
                        "MEDIUM",
                        f"The Remote Registry service is {state_text}. This service "
                        f"allows remote access to the Windows registry, which can be "
                        f"used for reconnaissance, configuration changes, and "
                        f"persistence.",
                        "Remote Registry access allows authenticated users (and attackers "
                        "with valid credentials) to read and modify registry settings "
                        "remotely, including security policies, startup entries, and "
                        "service configurations.",
                        "Disable the Remote Registry service and set its startup type to "
                        "Disabled. Via PowerShell: "
                        "Set-Service -Name RemoteRegistry -StartupType Disabled -Status Stopped. "
                        "Via Group Policy: Computer Configuration > Windows Settings > "
                        "Security Settings > System Services > Remote Registry.",
                        output=f"Service status: {status}\nStart type: {start_type}",
                        remediation_effort="Easy",
                        mitre_attack=[{"technique": "T1012", "tactic": "Discovery",
                                       "name": "Query Registry"}],
                        nist_800_53=["CM-7", "AC-3"],
                    )
                return
