from datetime import datetime, timezone
from analyzers.base import BaseAnalyzer

_WIN_EOL = {
    "6.1":  {"name": "Windows 7 / Server 2008 R2",  "eol": "2020-01-14"},
    "6.2":  {"name": "Windows 8 / Server 2012",      "eol": "2016-01-12"},
    "6.3":  {"name": "Windows 8.1 / Server 2012 R2", "eol": "2023-01-10"},
}

_WIN10_BUILD_EOL = {
    10240: {"name": "Windows 10 1507", "eol": "2017-05-09"},
    10586: {"name": "Windows 10 1511", "eol": "2017-10-10"},
    14393: {"name": "Windows 10 1607 / Server 2016", "eol": "2027-01-12"},
    15063: {"name": "Windows 10 1703", "eol": "2019-10-08"},
    16299: {"name": "Windows 10 1709", "eol": "2020-10-13"},
    17134: {"name": "Windows 10 1803", "eol": "2020-11-10"},
    17763: {"name": "Windows 10 1809 / Server 2019", "eol": "2029-01-09"},
    18362: {"name": "Windows 10 1903", "eol": "2020-12-08"},
    18363: {"name": "Windows 10 1909", "eol": "2022-05-10"},
    19041: {"name": "Windows 10 2004", "eol": "2021-12-14"},
    19042: {"name": "Windows 10 20H2", "eol": "2023-05-09"},
    19043: {"name": "Windows 10 21H1", "eol": "2022-12-13"},
    19044: {"name": "Windows 10 21H2", "eol": "2024-06-11"},
    19045: {"name": "Windows 10 22H2", "eol": "2025-10-14"},
    20348: {"name": "Windows Server 2022", "eol": "2031-10-14"},
    22000: {"name": "Windows 11 21H2", "eol": "2024-10-08"},
    22621: {"name": "Windows 11 22H2", "eol": "2025-10-14"},
    22631: {"name": "Windows 11 23H2", "eol": "2026-11-10"},
    26100: {"name": "Windows 11 24H2 / Server 2025", "eol": "2035-10-10"},
}


class SystemAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_eol()
        self._check_updates()
        self._check_update_service()
        self._check_wsus()
        self._check_uptime()
        self._check_backup()
        self._check_bitlocker()
        self._check_tpm()
        self._check_secure_boot()
        self._check_printnightmare()
        self._check_dns_zone_transfer()
        return self.findings

    def _check_eol(self):
        sys_info = self._get_section("system_info", {})
        os_ver = sys_info.get("os_version", "")
        build = sys_info.get("os_build", 0)
        try:
            build = int(build)
        except (ValueError, TypeError):
            build = 0

        eol_entry = None
        major_minor = ".".join(os_ver.split(".")[:2]) if os_ver else ""
        if major_minor in _WIN_EOL:
            eol_entry = _WIN_EOL[major_minor]
        elif build in _WIN10_BUILD_EOL:
            eol_entry = _WIN10_BUILD_EOL[build]
        else:
            for b in sorted(_WIN10_BUILD_EOL.keys()):
                if build >= b:
                    eol_entry = _WIN10_BUILD_EOL[b]

        if eol_entry:
            try:
                eol_date = datetime.strptime(eol_entry["eol"], "%Y-%m-%d").replace(
                    tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > eol_date:
                    os_name = eol_entry["name"]
                    self._add_finding(
                        "DR-SYS-001",
                        "EOL Software: End-of-Life Windows Version",
                        "HIGH",
                        f"The system is running {os_name} (build {build}) which reached "
                        f"end of life on {eol_entry['eol']}. No further security updates "
                        f"are available from Microsoft.",
                        "Running an unsupported operating system means known vulnerabilities "
                        "will never be patched, leaving the system exposed to publicly "
                        "disclosed exploits. Attackers actively target EOL systems.",
                        "Upgrade to a currently supported version of Windows. If immediate "
                        "upgrade is not possible, isolate the system from the network and "
                        "implement compensating controls.",
                        output=f"OS: {os_name}\nBuild: {build}\nEOL: {eol_entry['eol']}",
                        remediation_effort="Major",
                        cwe=["CWE-1104"],
                    )
            except (ValueError, TypeError):
                pass

    def _check_updates(self):
        updates = self._get_section("windows_update", {})
        pending = updates.get("pending_updates", [])
        if not isinstance(pending, list):
            pending = []
        critical = [u for u in pending
                    if isinstance(u, dict)
                    and "critical" in u.get("categories", "").lower()]
        if len(pending) >= 5 or len(critical) >= 1:
            risk = "HIGH" if critical else "MEDIUM"
            self._add_finding(
                "DR-SYS-002",
                "Patch Management: Missing Critical Updates",
                risk,
                f"The system has {len(pending)} pending Windows updates, including "
                f"{len(critical)} critical security updates.",
                "Missing security updates leave the system vulnerable to known exploits. "
                "Attackers frequently target unpatched systems using publicly available "
                "exploit code.",
                "Apply all pending Windows updates immediately. Configure automatic "
                "updates or establish a regular patching schedule.",
                output=f"Pending: {len(pending)}\nCritical: {len(critical)}",
                remediation_effort="Moderate",
            )

    def _check_update_service(self):
        updates = self._get_section("windows_update", {})
        svc_status = updates.get("service_status", "")
        if isinstance(svc_status, str) and svc_status.lower() in ("stopped", "disabled"):
            self._add_finding(
                "DR-SYS-003",
                "Patch Management: Windows Update Disabled",
                "MEDIUM",
                "The Windows Update service is disabled or stopped, preventing the "
                "system from receiving security patches.",
                "Without the update service running, the system cannot automatically "
                "download or install security patches, increasing exposure to known "
                "vulnerabilities over time.",
                "Enable and start the Windows Update service. Set the startup type to "
                "Automatic to ensure continuous patch management.",
                output=f"Service status: {svc_status}",
                remediation_effort="Easy",
            )

    def _check_wsus(self):
        updates = self._get_section("windows_update", {})
        wsus = updates.get("wsus_server", "")
        auto_update = updates.get("auto_update_enabled", True)
        if not wsus and not auto_update:
            self._add_finding(
                "DR-SYS-004",
                "Patch Management: WSUS Not Configured",
                "INFO",
                "No WSUS server is configured and automatic updates are not enabled. "
                "The system has no centralized update management.",
                "Without centralized update management, patches must be manually "
                "applied, which increases the risk of missed critical updates.",
                "Configure a WSUS server or enable Windows Update automatic updates. "
                "For enterprise environments, consider using SCCM or Intune for "
                "patch management.",
                remediation_effort="Moderate",
            )

    def _check_uptime(self):
        sys_info = self._get_section("system_info", {})
        uptime_days = sys_info.get("uptime_days", 0)
        try:
            uptime_days = float(uptime_days)
        except (ValueError, TypeError):
            return
        if uptime_days > 90:
            self._add_finding(
                "DR-SYS-005",
                "Patch Management: System Uptime Exceeds 90 Days",
                "LOW",
                f"The system has been running for {int(uptime_days)} days without a "
                f"reboot. Extended uptime may indicate that patches requiring a reboot "
                f"have not been applied.",
                "Many security patches require a reboot to take effect. Extended "
                "uptime suggests pending patches may not have been fully installed.",
                "Schedule a maintenance window to reboot the system and ensure all "
                "pending updates that require a restart are fully applied.",
                output=f"Uptime: {int(uptime_days)} days",
                remediation_effort="Easy",
            )

    def _check_backup(self):
        backup = self._get_section("windows_backup", {})
        if not backup:
            return
        configured = backup.get("configured", False)
        if not configured:
            self._add_finding(
                "DR-SYS-006",
                "Patch Management: No Backup Configured",
                "MEDIUM",
                "Windows Backup is not configured on this system. There is no local "
                "backup solution in place for disaster recovery.",
                "Without backups, data loss from ransomware, hardware failure, or "
                "accidental deletion cannot be recovered. This is especially critical "
                "for servers and systems handling sensitive data.",
                "Configure Windows Backup or implement a third-party backup solution. "
                "Ensure backups are stored off-system and tested regularly.",
                remediation_effort="Moderate",
            )
            return
        last_backup = backup.get("last_backup", "")
        if last_backup:
            try:
                lb = datetime.fromisoformat(last_backup.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - lb).days
                if age > 30:
                    self._add_finding(
                        "DR-SYS-007",
                        "Patch Management: Last Backup Over 30 Days",
                        "MEDIUM",
                        f"The last Windows Backup was performed {age} days ago. "
                        f"Backups should be performed regularly to ensure data "
                        f"recovery capability.",
                        "Stale backups may not contain recent data or configuration "
                        "changes, reducing their usefulness for disaster recovery.",
                        "Review and re-enable the backup schedule. Verify backup "
                        "integrity by performing a test restore.",
                        output=f"Last backup: {last_backup}\nAge: {age} days",
                        remediation_effort="Easy",
                    )
            except (ValueError, TypeError):
                pass

    def _check_bitlocker(self):
        bitlocker = self._get_section("bitlocker", {})
        if not bitlocker:
            return
        drives = bitlocker.get("drives", [])
        if not isinstance(drives, list):
            return
        unencrypted = [d for d in drives
                       if isinstance(d, dict)
                       and d.get("protection_status", "").lower() != "on"
                       and d.get("drive_type", "").lower() != "removable"]
        if unencrypted:
            drive_list = ", ".join(d.get("drive_letter", "?") for d in unencrypted)
            self._add_finding(
                "DR-SYS-008",
                "System Hardening: BitLocker Not Enabled",
                "MEDIUM",
                f"BitLocker full-disk encryption is not enabled on the following "
                f"drives: {drive_list}. Data at rest is not protected.",
                "Without disk encryption, an attacker with physical access can "
                "extract data from the hard drive, including credentials, sensitive "
                "files, and configuration data.",
                "Enable BitLocker on all fixed drives. Use TPM + PIN for the boot "
                "drive. Store recovery keys securely in Active Directory or a key "
                "management system.",
                output=f"Unencrypted drives: {drive_list}",
                remediation_effort="Moderate",
                nist_800_53=["SC-28"],
                pci_dss_4=["3.5.1"],
            )

    def _check_tpm(self):
        sys_info = self._get_section("system_info", {})
        tpm = sys_info.get("tpm", {})
        if not isinstance(tpm, dict):
            return
        present = tpm.get("present", True)
        ready = tpm.get("ready", True)
        if not present:
            self._add_finding(
                "DR-SYS-009",
                "System Hardening: TPM Not Available",
                "INFO",
                "No Trusted Platform Module (TPM) was detected on this system, or "
                "the TPM is present but not in a ready state.",
                "Without a TPM, hardware-backed security features like BitLocker "
                "TPM-based encryption, Credential Guard, and Measured Boot cannot "
                "be used.",
                "If hardware supports TPM, enable it in BIOS/UEFI settings. Ensure "
                "TPM firmware is updated to the latest version.",
                remediation_effort="Moderate",
            )
        elif not ready:
            self._add_finding(
                "DR-SYS-009",
                "System Hardening: TPM Not Available",
                "INFO",
                "A TPM is present but not in a ready state. TPM-dependent security "
                "features may not function correctly.",
                "An uninitialized TPM cannot provide hardware-backed key storage "
                "or attestation services.",
                "Initialize the TPM through Windows Security settings or the TPM "
                "Management Console (tpm.msc).",
                remediation_effort="Easy",
            )

    def _check_secure_boot(self):
        sys_info = self._get_section("system_info", {})
        secure_boot = sys_info.get("secure_boot", None)
        if secure_boot is False:
            self._add_finding(
                "DR-SYS-010",
                "System Hardening: Secure Boot Not Enabled",
                "MEDIUM",
                "UEFI Secure Boot is not enabled on this system. The boot process "
                "is not cryptographically validated.",
                "Without Secure Boot, bootkits and rootkits can modify the boot "
                "chain to persist below the operating system, evading all "
                "OS-level security controls.",
                "Enable Secure Boot in UEFI firmware settings. Ensure the system "
                "is booting in UEFI mode (not Legacy/CSM).",
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1542.003", "tactic": "Persistence",
                               "name": "Bootkit"}],
            )

    def _check_printnightmare(self):
        pc = self._get_section("print_config", {})
        if not isinstance(pc, dict) or not pc:
            return
        spooler = pc.get("spooler_status", {})
        if isinstance(spooler, dict) and spooler.get("status") != "Running":
            return
        pnp = pc.get("point_and_print", {})
        if not isinstance(pnp, dict):
            return
        restrict = pnp.get("RestrictDriverInstallationToAdministrators")
        if restrict is not None and int(restrict) == 0:
            self._add_finding(
                "DR-SYS-012", "Service Hardening: PrintNightmare Vulnerable", "CRITICAL",
                "The Print Spooler service is running with "
                "RestrictDriverInstallationToAdministrators disabled. This "
                "configuration is vulnerable to PrintNightmare (CVE-2021-34527).",
                "PrintNightmare allows remote code execution and local privilege "
                "escalation via the Print Spooler. An attacker can execute "
                "arbitrary code as SYSTEM by loading a malicious printer driver.",
                "Set RestrictDriverInstallationToAdministrators to 1 in "
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\"
                "PointAndPrint. Disable the Print Spooler if printing is not needed.",
                cves="CVE-2021-34527",
                remediation_effort="Easy",
                cwe=["CWE-269"],
                mitre_attack=[{"technique": "T1547.012", "tactic": "Persistence",
                               "name": "Print Processors"}],
                nist_800_53=["CM-6", "SI-2"],
                pci_dss_4=["6.3.3"],
            )
        no_warn = pnp.get("NoWarningNoElevationOnInstall")
        if no_warn is not None and int(no_warn) == 1:
            self._add_finding(
                "DR-SYS-012", "Service Hardening: PrintNightmare Vulnerable", "CRITICAL",
                "Point and Print NoWarningNoElevationOnInstall is enabled. "
                "Printer driver installation proceeds silently without elevation, "
                "leaving the system vulnerable to PrintNightmare.",
                "This setting allows any user to install printer drivers without "
                "an elevation prompt, enabling PrintNightmare exploitation for "
                "local privilege escalation to SYSTEM.",
                "Set NoWarningNoElevationOnInstall to 0 in HKLM\\SOFTWARE\\"
                "Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint.",
                cves="CVE-2021-34527",
                remediation_effort="Easy",
                cwe=["CWE-269"],
                mitre_attack=[{"technique": "T1547.012", "tactic": "Persistence",
                               "name": "Print Processors"}],
            )

    def _check_dns_zone_transfer(self):
        dns = self._get_section("dns_config", {})
        if not isinstance(dns, dict) or not dns:
            return
        if not dns.get("dns_service_running"):
            return
        zones = dns.get("zones", [])
        if not isinstance(zones, list):
            return
        vuln_zones = []
        for z in zones:
            if not isinstance(z, dict):
                continue
            xfer = z.get("secondary_servers", z.get("secure_secondaries"))
            if isinstance(xfer, int) and xfer == 0:
                vuln_zones.append(z.get("zone_name", "?"))
            elif isinstance(xfer, str) and xfer.lower() in ("any", "none"):
                if xfer.lower() == "any":
                    vuln_zones.append(z.get("zone_name", "?"))
        if vuln_zones:
            self._add_finding(
                "DR-SYS-013", "Network Hardening: DNS Zone Transfer Allowed", "MEDIUM",
                f"DNS zone transfers are allowed to any host for {len(vuln_zones)} "
                f"zone(s). This exposes the full DNS zone contents to any querier.",
                "Zone transfer data reveals internal hostnames, IP addresses, and "
                "network topology. Attackers use this for reconnaissance to "
                "identify targets and map the internal network.",
                "Restrict zone transfers to authorized secondary DNS servers only. "
                "Configure SecureSecondaries to 'Only to servers listed on the "
                "Name Servers tab' or specify allowed IP addresses.",
                output=f"Zones with unrestricted transfers:\n" +
                       "\n".join(vuln_zones[:10]),
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1590.002", "tactic": "Reconnaissance",
                               "name": "Gather Victim Network Information: DNS"}],
                nist_800_53=["SC-8", "AC-3"],
            )
