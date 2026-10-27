from analyzers.base import BaseAnalyzer


class HardeningAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_uac()
        self._check_smb()
        self._check_ntlm()
        self._check_wdigest()
        self._check_lsa()
        self._check_credential_guard()
        self._check_autorun()
        self._check_llmnr()
        self._check_wpad()
        self._check_powershell_logging()
        self._check_powershell_v2()
        self._check_defender()
        self._check_rdp_nla()
        self._check_dep()
        self._check_anonymous_pipes()
        self._check_null_sessions()
        self._check_audit_policy()
        self._check_print_spooler()
        self._check_applocker()
        self._check_hvci()
        self._check_credssp()
        self._check_amsi()
        self._check_dotnet_legacy()
        self._check_ps_clm()
        self._check_asr_rules()
        self._check_controlled_folder()
        self._check_network_protection()
        self._check_exploit_protection()
        self._check_smb_client_signing()
        self._check_anon_sam()
        self._check_builtin_admin_uac_bypass()
        self._check_blank_passwords()
        self._check_everyone_includes_anonymous()
        self._check_rdp_encryption()
        self._check_audit_subcategories()
        self._check_dangerous_user_rights()
        self._check_legacy_audit_override()
        self._check_smb_encryption()
        self._check_wef()
        self._check_removable_storage()
        self._check_expanded_audit_subcategories()
        self._check_defender_detailed()
        self._check_dns_client()
        self._check_cis_baseline()
        return self.findings

    def _reg(self, key, default=None):
        harden = self._get_section("registry_hardening", {})
        if not isinstance(harden, dict):
            return default
        return harden.get(key, default)

    def _check_uac(self):
        enable_lua = self._reg("EnableLUA")
        if enable_lua is not None and int(enable_lua) != 1:
            self._add_finding(
                "DR-HDN-001", "System Hardening: UAC Disabled", "HIGH",
                "User Account Control (UAC) is disabled. All processes run with "
                "full administrator privileges without prompting.",
                "With UAC disabled, malware and unauthorized software can execute "
                "with full administrative privileges, making privilege escalation "
                "trivial and system compromise more likely.",
                "Enable UAC by setting HKLM\\SOFTWARE\\Microsoft\\Windows\\"
                "CurrentVersion\\Policies\\System\\EnableLUA to 1 and rebooting.",
                output=f"EnableLUA: {enable_lua}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1548.002", "tactic": "Defense Evasion",
                               "name": "Bypass User Account Control"}],
            )
        consent = self._reg("ConsentPromptBehaviorAdmin")
        if consent is not None and int(consent) < 2:
            self._add_finding(
                "DR-HDN-002", "System Hardening: UAC Prompt Behavior Weak", "MEDIUM",
                f"UAC consent prompt behavior for administrators is set to {consent} "
                f"(auto-elevate without prompting), weakening UAC protections.",
                "A weak UAC prompt allows silent elevation of privileges, enabling "
                "malware to gain admin access without user awareness.",
                "Set ConsentPromptBehaviorAdmin to 2 (prompt for consent on secure "
                "desktop) or higher.",
                output=f"ConsentPromptBehaviorAdmin: {consent}",
                remediation_effort="Easy",
            )

    def _check_smb(self):
        smb1 = self._reg("SMB1")
        if smb1 is not None and int(smb1) != 0:
            self._add_finding(
                "DR-HDN-003", "Network Hardening: SMBv1 Protocol Enabled", "MEDIUM",
                "SMBv1 is enabled on this system. SMBv1 has known vulnerabilities "
                "including EternalBlue (MS17-010).",
                "SMBv1 is vulnerable to multiple remote code execution attacks. "
                "EternalBlue and related exploits have been used extensively in "
                "ransomware campaigns (WannaCry, NotPetya).",
                "Disable SMBv1 via PowerShell: Disable-WindowsOptionalFeature "
                "-Online -FeatureName SMB1Protocol. Verify no legacy devices "
                "require SMBv1 before disabling.",
                output=f"SMB1: {smb1}",
                remediation_effort="Easy",
                cwe=["CWE-757"],
                mitre_attack=[{"technique": "T1210", "tactic": "Lateral Movement",
                               "name": "Exploitation of Remote Services"}],
            )
        signing = self._reg("RequireSecuritySignature")
        if signing is not None and int(signing) != 1:
            self._add_finding(
                "DR-HDN-004", "System Hardening: SMB Signing Not Required", "MEDIUM",
                "SMB signing is not required, allowing potential man-in-the-middle "
                "attacks on SMB connections.",
                "Without required SMB signing, an attacker on the local network can "
                "perform relay attacks to capture and replay authentication, "
                "potentially gaining unauthorized access.",
                "Enable SMB signing: Set RequireSecuritySignature to 1 in "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters.",
                output=f"RequireSecuritySignature: {signing}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1557.001", "tactic": "Credential Access",
                               "name": "LLMNR/NBT-NS Poisoning and SMB Relay"}],
            )
        if signing is not None and int(signing) == 1:
            _patched = False
            wu = self._get_section("windows_update", {})
            build = self.os_info.get("os_build", 0)
            for entry in wu.get("update_history", []):
                if entry.get("result_code") != "Succeeded":
                    continue
                kb = entry.get("kb", "")
                if kb == "KB5124008":
                    _patched = True
                    break
                d = entry.get("date", "")
                if d and d >= "2026-09-08" and "Cumulative Update" in entry.get("title", ""):
                    _patched = True
                    break
            if not _patched:
                self._add_finding(
                    "DR-HDN-045",
                    "SMB Signing Bypass: Re-Authentication Identity Check Missing",
                    "HIGH",
                    "SMB signing is enforced but the server does not verify that a "
                    "re-authenticating session belongs to the same identity. An attacker "
                    "who opens a signed session with their own credentials can re-authenticate "
                    "it using a relayed privileged identity, retaining their signing key while "
                    "gaining the victim's privileges.",
                    "SMB signing alone does not prevent relay attacks on this host. An attacker "
                    "with network position and the ability to coerce authentication (LLMNR/mDNS "
                    "poisoning, PetitPotam, PrinterBug) can relay privileged credentials even "
                    "against signing-enforced targets. Domain Controllers are the highest-value "
                    "target for this technique.",
                    "Install KB5124008 (September 2026 cumulative update) or later. This update "
                    "adds a same-identity check on SMB session re-authentication. Verify with: "
                    "NetExec reauth_swap module or patchcheck.py from the reauthx toolkit.",
                    output=f"RequireSecuritySignature: {signing}\nKB5124008 installed: No\nOS build: {build}",
                    remediation_effort="Easy",
                    remediation_component="Network",
                    remediation_category="Access Control",
                    cwe=["CWE-287", "CWE-384"],
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    mitre_attack=[
                        {"technique": "T1557.001", "tactic": "Credential Access",
                         "name": "LLMNR/NBT-NS Poisoning and SMB Relay"},
                        {"technique": "T1187", "tactic": "Credential Access",
                         "name": "Forced Authentication"},
                    ],
                    nist_800_53=["AC-3", "IA-9", "SC-23"],
                    pci_dss_4=["2.2.7"],
                    service="smb",
                    confidence="Firm",
                )

    def _check_ntlm(self):
        lm_compat = self._reg("LmCompatibilityLevel")
        if lm_compat is not None and int(lm_compat) < 3:
            self._add_finding(
                "DR-HDN-005", "Authentication: NTLMv1 Authentication Allowed", "HIGH",
                f"LmCompatibilityLevel is set to {lm_compat}, allowing NTLMv1 "
                f"authentication. NTLMv1 hashes can be cracked trivially.",
                "NTLMv1 responses can be cracked in seconds using rainbow tables. "
                "An attacker capturing NTLMv1 authentication can recover plaintext "
                "credentials and move laterally.",
                "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only. "
                "Refuse LM & NTLM). Test compatibility before enforcing.",
                output=f"LmCompatibilityLevel: {lm_compat}",
                remediation_effort="Moderate",
                cwe=["CWE-328"],
            )
        no_lm = self._reg("NoLMHash")
        if no_lm is not None and int(no_lm) != 1:
            self._add_finding(
                "DR-HDN-006", "Authentication: LM Password Hashes Stored", "HIGH",
                "The system stores LAN Manager password hashes, which are trivially "
                "crackable (split into two 7-character DES keys).",
                "LM hashes can be cracked in minutes regardless of password "
                "complexity. An attacker extracting the SAM database can recover "
                "all user passwords.",
                "Set NoLMHash to 1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
                "Lsa. Users must change passwords after this setting is applied.",
                output=f"NoLMHash: {no_lm}",
                remediation_effort="Easy",
            )

    def _check_wdigest(self):
        wdigest = self._reg("UseLogonCredential")
        if wdigest is not None and int(wdigest) == 1:
            self._add_finding(
                "DR-HDN-008", "Credential Exposure: WDigest Plaintext Credentials", "CRITICAL",
                "WDigest authentication stores plaintext credentials in LSASS "
                "memory, allowing extraction with tools like Mimikatz.",
                "An attacker with local admin access can dump plaintext passwords "
                "from LSASS memory for every user who has logged in since boot, "
                "enabling immediate lateral movement.",
                "Set UseLogonCredential to 0 in HKLM\\SYSTEM\\CurrentControlSet\\"
                "Control\\SecurityProviders\\WDigest.",
                output=f"UseLogonCredential: {wdigest}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1003.001", "tactic": "Credential Access",
                               "name": "LSASS Memory"}],
            )

    def _check_lsa(self):
        ppl = self._reg("RunAsPPL")
        if ppl is not None and int(ppl) != 1:
            self._add_finding(
                "DR-HDN-009", "System Hardening: LSA Protection Not Enabled", "HIGH",
                "LSA Protection (RunAsPPL) is not enabled. LSASS process is not "
                "protected from code injection and memory dumping.",
                "Without LSA Protection, credential-dumping tools can freely read "
                "LSASS memory to extract passwords, hashes, and Kerberos tickets.",
                "Enable LSA Protection by setting RunAsPPL to 1 in "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
                output=f"RunAsPPL: {ppl}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1003.001", "tactic": "Credential Access",
                               "name": "LSASS Memory"}],
            )

    def _check_credential_guard(self):
        vbs = self._reg("EnableVirtualizationBasedSecurity")
        if vbs is not None and int(vbs) != 1:
            self._add_finding(
                "DR-HDN-010", "System Hardening: Credential Guard Not Enabled", "MEDIUM",
                "Virtualization-Based Security (Credential Guard) is not enabled. "
                "Derived credentials are not isolated from the OS.",
                "Without Credential Guard, NTLM hashes and Kerberos tickets in "
                "LSASS memory are accessible to credential-dumping tools.",
                "Enable Credential Guard via Group Policy: Computer Configuration > "
                "Administrative Templates > System > Device Guard > "
                "Turn On Virtualization Based Security.",
                output=f"EnableVirtualizationBasedSecurity: {vbs}",
                remediation_effort="Moderate",
            )

    def _check_autorun(self):
        autorun = self._reg("NoDriveTypeAutoRun")
        if autorun is not None and int(autorun) != 255:
            self._add_finding(
                "DR-HDN-007", "System Hardening: AutoRun Enabled", "MEDIUM",
                f"AutoRun is not fully disabled (NoDriveTypeAutoRun={autorun}). "
                f"Removable media can automatically execute code on insertion.",
                "An attacker can craft a USB drive or CD that auto-executes malware "
                "when inserted, bypassing user interaction requirements.",
                "Set NoDriveTypeAutoRun to 255 (0xFF) to disable AutoRun on all "
                "drive types.",
                output=f"NoDriveTypeAutoRun: {autorun}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1091", "tactic": "Initial Access",
                               "name": "Replication Through Removable Media"}],
            )

    def _check_llmnr(self):
        llmnr = self._reg("EnableMulticast")
        if llmnr is None or int(llmnr) != 0:
            self._add_finding(
                "DR-HDN-011", "Network Hardening: LLMNR Enabled", "HIGH",
                "Link-Local Multicast Name Resolution (LLMNR) is enabled, allowing "
                "name resolution poisoning attacks on the local network.",
                "An attacker can respond to LLMNR queries to redirect traffic and "
                "capture NetNTLM hashes using tools like Responder, enabling "
                "offline password cracking or relay attacks.",
                "Disable LLMNR via Group Policy: Computer Configuration > "
                "Administrative Templates > Network > DNS Client > "
                "Turn Off Multicast Name Resolution = Enabled.",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1557.001", "tactic": "Credential Access",
                               "name": "LLMNR/NBT-NS Poisoning and SMB Relay"}],
            )

    def _check_wpad(self):
        wpad = self._reg("WpadOverride")
        wins = self._reg("EnableWINS")
        if wpad is None and (wins is None or int(wins) != 0):
            features = self._get_section("registry_hardening", {})
            wpad_disabled = features.get("wpad_disabled", False)
            if not wpad_disabled:
                self._add_finding(
                    "DR-HDN-012", "Network Hardening: WPAD Enabled", "MEDIUM",
                    "Web Proxy Auto-Discovery (WPAD) is not disabled. The system "
                    "may automatically configure proxy settings from the network.",
                    "An attacker can exploit WPAD to redirect all HTTP traffic "
                    "through a malicious proxy, enabling credential interception "
                    "and content injection.",
                    "Disable WPAD by adding a DWORD WpadOverride=1 under "
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet "
                    "Settings\\Wpad and disabling the WinHttpAutoProxySvc service.",
                    remediation_effort="Easy",
                    mitre_attack=[{"technique": "T1557.001", "tactic": "Credential Access",
                                   "name": "LLMNR/NBT-NS Poisoning and SMB Relay"}],
                )

    def _check_powershell_logging(self):
        sb_log = self._reg("ScriptBlockLogging")
        if sb_log is not None and int(sb_log) != 1:
            self._add_finding(
                "DR-HDN-013", "Monitoring: PowerShell Script Block Logging Disabled", "MEDIUM",
                "PowerShell Script Block Logging is not enabled. Executed scripts "
                "are not recorded in the event log.",
                "Without script block logging, malicious PowerShell commands "
                "executed by attackers leave no forensic trace, hampering "
                "incident response and threat detection.",
                "Enable Script Block Logging via Group Policy: Computer "
                "Configuration > Administrative Templates > Windows Components > "
                "Windows PowerShell > Turn on PowerShell Script Block Logging.",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1059.001", "tactic": "Execution",
                               "name": "PowerShell"}],
            )
        mod_log = self._reg("ModuleLogging")
        if mod_log is not None and int(mod_log) != 1:
            self._add_finding(
                "DR-HDN-014", "Monitoring: PowerShell Module Logging Disabled", "LOW",
                "PowerShell Module Logging is not enabled. Module execution events "
                "are not recorded.",
                "Module logging provides visibility into which PowerShell modules "
                "are loaded and used, aiding in detection of attacker tools.",
                "Enable Module Logging via Group Policy under Windows Components > "
                "Windows PowerShell > Turn on Module Logging.",
                remediation_effort="Easy",
            )
        transcription = self._reg("Transcription")
        if transcription is not None and int(transcription) != 1:
            self._add_finding(
                "DR-HDN-015", "Monitoring: PowerShell Transcription Disabled", "LOW",
                "PowerShell transcription is not enabled. Console input and output "
                "are not being captured to transcript files.",
                "Transcription captures the full input/output of every PowerShell "
                "session, providing detailed forensic evidence of attacker activity.",
                "Enable transcription via Group Policy: Windows Components > "
                "Windows PowerShell > Turn on PowerShell Transcription.",
                remediation_effort="Easy",
            )

    def _check_powershell_v2(self):
        features = self._get_section("registry_hardening", {})
        ps_v2 = features.get("powershell_v2_available", None)
        if ps_v2 is True:
            self._add_finding(
                "DR-HDN-016", "System Hardening: PowerShell v2 Engine Available", "MEDIUM",
                "The PowerShell v2 engine is available on this system. Attackers "
                "can use -Version 2 to bypass modern logging and AMSI.",
                "PowerShell v2 does not support Script Block Logging, Module "
                "Logging, or AMSI (Antimalware Scan Interface), allowing "
                "attackers to run scripts undetected.",
                "Remove the PowerShell v2 engine: Disable-WindowsOptionalFeature "
                "-Online -FeatureName MicrosoftWindowsPowerShellV2Root.",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1059.001", "tactic": "Execution",
                               "name": "PowerShell"}],
            )

    def _check_defender(self):
        defender = self._get_section("registry_hardening", {})
        disabled = defender.get("defender_disabled", None)
        if disabled is True:
            self._add_finding(
                "DR-HDN-017", "Endpoint Protection: Windows Defender Disabled", "HIGH",
                "Windows Defender antimalware is disabled on this system.",
                "Without active antimalware protection, the system has no "
                "defense against known malware, ransomware, and commodity "
                "threat tools.",
                "Enable Windows Defender via Group Policy or Windows Security "
                "settings. Ensure no conflicting third-party AV is installed.",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1562.001", "tactic": "Defense Evasion",
                               "name": "Disable or Modify Tools"}],
            )
        exclusions = defender.get("defender_exclusions", [])
        if isinstance(exclusions, list) and len(exclusions) > 0:
            exc_list = "\n".join(str(e) for e in exclusions[:10])
            self._add_finding(
                "DR-HDN-018", "Endpoint Protection: Defender Exclusions Present", "MEDIUM",
                f"Windows Defender has {len(exclusions)} exclusion(s) configured. "
                f"Excluded paths, processes, or extensions bypass scanning.",
                "Attackers commonly drop malware in excluded paths. Excessive "
                "exclusions reduce antimalware coverage and are a known "
                "persistence technique.",
                "Review and minimize Defender exclusions. Remove any that are "
                "not strictly necessary for application compatibility.",
                output=f"Exclusion count: {len(exclusions)}\n{exc_list}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1562.001", "tactic": "Defense Evasion",
                               "name": "Disable or Modify Tools"}],
            )
        rtp = defender.get("real_time_protection", None)
        if rtp is False:
            self._add_finding(
                "DR-HDN-019", "Endpoint Protection: Defender Real-Time Protection Off", "HIGH",
                "Windows Defender real-time protection is disabled. Files are not "
                "scanned on access.",
                "Without real-time protection, malware can execute without being "
                "intercepted, and malicious files can be written to disk without "
                "detection.",
                "Enable real-time protection in Windows Security > Virus & threat "
                "protection > Manage settings.",
                remediation_effort="Easy",
            )

    def _check_rdp_nla(self):
        nla = self._reg("UserAuthentication")
        if nla is not None and int(nla) != 1:
            rdp_enabled = self._reg("fDenyTSConnections")
            if rdp_enabled is not None and int(rdp_enabled) == 0:
                self._add_finding(
                    "DR-HDN-020", "Remote Desktop: RDP Without NLA", "HIGH",
                    "Remote Desktop is enabled without Network Level Authentication "
                    "(NLA). Users can reach the login screen without authenticating.",
                    "Without NLA, attackers can interact with the RDP login screen "
                    "directly, enabling brute force attacks and exploitation of "
                    "RDP vulnerabilities (e.g., BlueKeep).",
                    "Enable NLA: Set UserAuthentication to 1 under "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
                    "WinStations\\RDP-Tcp.",
                    output=f"UserAuthentication: {nla}",
                    remediation_effort="Easy",
                    mitre_attack=[{"technique": "T1021.001", "tactic": "Lateral Movement",
                                   "name": "Remote Desktop Protocol"}],
                )

    def _check_dep(self):
        dep = self._reg("nx_policy")
        if dep is not None and str(dep) not in ("3", "AlwaysOn"):
            self._add_finding(
                "DR-HDN-021", "System Hardening: DEP Not System-Wide", "MEDIUM",
                f"Data Execution Prevention (DEP) is not set to AlwaysOn (current: "
                f"{dep}). Some processes may execute code from non-executable memory.",
                "Without system-wide DEP, buffer overflow exploits can execute "
                "shellcode from the stack or heap, which DEP would otherwise prevent.",
                "Enable DEP for all programs: bcdedit /set nx AlwaysOn. Test "
                "application compatibility before enforcing.",
                output=f"DEP policy: {dep}",
                remediation_effort="Moderate",
            )

    def _check_anonymous_pipes(self):
        pipes = self._reg("NullSessionPipes")
        if pipes and isinstance(pipes, (list, str)):
            pipe_list = pipes if isinstance(pipes, list) else [p.strip() for p in pipes.split(",") if p.strip()]
            if pipe_list:
                self._add_finding(
                    "DR-HDN-022", "Access Control: Anonymous Named Pipe Access", "HIGH",
                    f"The following named pipes are accessible anonymously: "
                    f"{', '.join(pipe_list)}.",
                    "Anonymous named pipe access can allow unauthenticated "
                    "information disclosure or be leveraged for relay attacks "
                    "and privilege escalation.",
                    "Remove all entries from NullSessionPipes in "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\"
                    "Parameters unless specifically required.",
                    output=f"NullSessionPipes: {', '.join(pipe_list)}",
                    remediation_effort="Moderate",
                )

    def _check_null_sessions(self):
        restrict = self._reg("RestrictAnonymous")
        if restrict is not None and int(restrict) == 0:
            self._add_finding(
                "DR-HDN-023", "Access Control: Null Session Access", "HIGH",
                "Anonymous/null session access is permitted (RestrictAnonymous=0). "
                "Unauthenticated users can enumerate shares, users, and groups.",
                "Null session enumeration reveals user lists, group memberships, "
                "and share names, providing attackers with reconnaissance data "
                "for targeted attacks.",
                "Set RestrictAnonymous to 1 or 2 in HKLM\\SYSTEM\\"
                "CurrentControlSet\\Control\\Lsa.",
                output=f"RestrictAnonymous: {restrict}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1087", "tactic": "Discovery",
                               "name": "Account Discovery"}],
            )

    def _check_audit_policy(self):
        audit = self._get_section("registry_hardening", {}).get("audit_policy", {})
        if not isinstance(audit, dict):
            return
        insufficient = []
        critical_policies = {
            "Logon": "Success,Failure",
            "Account Logon": "Success,Failure",
            "Account Management": "Success,Failure",
            "Object Access": "Success,Failure",
            "Policy Change": "Success,Failure",
            "Privilege Use": "Success,Failure",
        }
        for policy, expected in critical_policies.items():
            current = audit.get(policy, "")
            if isinstance(current, dict):
                vals = [str(v).lower() for v in current.values()]
                if all(v == "no auditing" for v in vals):
                    insufficient.append(f"{policy}: All subcategories — No Auditing")
                continue
            if not current or str(current).lower() == "no auditing":
                insufficient.append(f"{policy}: {current or 'Not configured'}")
        if insufficient:
            self._add_finding(
                "DR-HDN-024", "Policy: Audit Policy Insufficient", "MEDIUM",
                f"{len(insufficient)} critical audit categories are not configured "
                f"for both success and failure auditing.",
                "Insufficient audit policy means security-relevant events are not "
                "logged, severely limiting forensic investigation capability and "
                "threat detection.",
                "Configure Advanced Audit Policy via Group Policy to enable "
                "Success and Failure auditing for all critical categories.",
                output="\n".join(insufficient),
                remediation_effort="Easy",
                nist_800_53=["AU-2", "AU-3"],
            )

    def _check_print_spooler(self):
        services = self._get_section("services", [])
        if not isinstance(services, list):
            return
        for svc in services:
            if not isinstance(svc, dict):
                continue
            name = svc.get("name", "").lower()
            if name == "spooler" and svc.get("status", "").lower() == "running":
                is_dc = self._is_domain_controller()
                risk = "HIGH" if is_dc else "MEDIUM"
                desc = (
                    "The Print Spooler service is running on this "
                    f"{'domain controller' if is_dc else 'server'}. "
                    "PrintNightmare (CVE-2021-34527) and related vulnerabilities "
                    "allow remote code execution via the spooler."
                )
                self._add_finding(
                    "DR-HDN-025", "Service Hardening: Print Spooler Running", risk,
                    desc,
                    "The Print Spooler service has been the target of multiple "
                    "critical vulnerabilities. On domain controllers, exploitation "
                    "can lead to full domain compromise.",
                    "Disable the Print Spooler service on servers that do not need "
                    "printing: Stop-Service Spooler; Set-Service Spooler -StartupType "
                    "Disabled.",
                    remediation_effort="Easy",
                    cwe=["CWE-269"],
                    mitre_attack=[{"technique": "T1210", "tactic": "Lateral Movement",
                                   "name": "Exploitation of Remote Services"}],
                )
                break

    def _defender(self, key, default=None):
        section = self._get_section("defender_detailed", {})
        if not isinstance(section, dict):
            return default
        return section.get(key, default)

    def _ps_cfg(self, key, default=None):
        section = self._get_section("powershell_config", {})
        if not isinstance(section, dict):
            return default
        return section.get(key, default)

    def _check_applocker(self):
        applocker = self._reg("AppLocker")
        wdac = self._reg("WDAC")
        if applocker is None and wdac is None:
            self._add_finding(
                "DR-HDN-026", "Endpoint Protection: Application Whitelisting Not Configured", "MEDIUM",
                "Neither AppLocker nor Windows Defender Application Control (WDAC) "
                "is configured on this system.",
                "Without application whitelisting, any executable can run, including "
                "malware, living-off-the-land binaries, and unauthorized software.",
                "Configure AppLocker or WDAC policies to restrict executable, script, "
                "and DLL execution to approved applications.",
                remediation_effort="Significant",
                mitre_attack=[{"technique": "T1059", "tactic": "Execution",
                               "name": "Command and Scripting Interpreter"}],
                nist_800_53=["CM-7"],
            )

    def _check_hvci(self):
        hvci = self._reg("HypervisorEnforcedCodeIntegrity")
        if hvci is not None and int(hvci) != 1:
            self._add_finding(
                "DR-HDN-027", "System Hardening: HVCI Not Enabled", "MEDIUM",
                "Hypervisor-protected Code Integrity (HVCI) is not enabled.",
                "Without HVCI, kernel-mode code integrity is enforced only by the "
                "kernel itself, which can be bypassed by kernel exploits.",
                "Enable HVCI via Group Policy or Device Guard settings. Requires "
                "VBS-compatible hardware (UEFI, Secure Boot, TPM 2.0).",
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1553", "tactic": "Defense Evasion",
                               "name": "Subvert Trust Controls"}],
            )

    def _check_credssp(self):
        allow_def = self._reg("AllowDefaultCredentials")
        if allow_def is not None and int(allow_def) == 1:
            self._add_finding(
                "DR-HDN-028", "System Hardening: CredSSP Delegation Enabled", "MEDIUM",
                "CredSSP credential delegation is enabled, allowing credentials "
                "to be forwarded to remote servers.",
                "CredSSP delegation exposes credentials to the remote host. If that "
                "host is compromised, the attacker captures the delegated credentials.",
                "Disable CredSSP delegation unless required. Use constrained "
                "delegation or Kerberos Resource-Based Constrained Delegation instead.",
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1550.001", "tactic": "Lateral Movement",
                               "name": "Application Access Token"}],
            )

    def _check_amsi(self):
        providers = self._ps_cfg("amsi_providers")
        if isinstance(providers, list) and len(providers) == 0:
            self._add_finding(
                "DR-HDN-029", "Endpoint Protection: AMSI Not Registered", "MEDIUM",
                "No Antimalware Scan Interface (AMSI) providers are registered.",
                "Without AMSI, PowerShell scripts, VBScript, JScript, and other "
                "AMSI-integrated components cannot be scanned for malicious content "
                "at runtime, allowing obfuscated malware to execute undetected.",
                "Ensure Windows Defender or a third-party AV with AMSI support is "
                "installed and its AMSI provider is registered.",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1562.001", "tactic": "Defense Evasion",
                               "name": "Disable or Modify Tools"}],
                nist_800_53=["SI-3"],
            )

    def _check_dotnet_legacy(self):
        versions = self._ps_cfg("dotnet_versions", [])
        legacy = [v for v in versions if isinstance(v, dict)
                  and str(v.get("version", "")).startswith(("2.", "3."))]
        if legacy:
            ver_list = ", ".join(str(v.get("version", "")) for v in legacy[:5])
            self._add_finding(
                "DR-HDN-030", "System Hardening: .NET Framework v2/v3.5 Installed", "LOW",
                f"Legacy .NET Framework versions are installed: {ver_list}. "
                f"These older runtimes lack modern security mitigations.",
                ".NET 2.0/3.5 can be abused to run PowerShell v2 and bypass "
                "security features like AMSI and Script Block Logging.",
                "Remove .NET Framework 2.0/3.5 if not required: "
                "Disable-WindowsOptionalFeature -Online -FeatureName NetFx3.",
                output=ver_list,
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1059.001", "tactic": "Execution",
                               "name": "PowerShell"}],
            )

    def _check_ps_clm(self):
        lang_mode = self._ps_cfg("language_mode", "")
        if isinstance(lang_mode, str) and "FullLanguage" in lang_mode:
            self._add_finding(
                "DR-HDN-031", "System Hardening: PS Constrained Language Not Enforced", "MEDIUM",
                "PowerShell is running in FullLanguage mode, allowing unrestricted "
                "access to .NET types, COM objects, and all PowerShell features.",
                "FullLanguage mode allows attackers to use PowerShell as a full-featured "
                "attack framework with access to .NET reflection, type creation, "
                "and arbitrary code execution capabilities.",
                "Deploy WDAC or AppLocker policies to enforce Constrained Language "
                "Mode for non-administrative users.",
                remediation_effort="Significant",
                mitre_attack=[{"technique": "T1059.001", "tactic": "Execution",
                               "name": "PowerShell"}],
                nist_800_53=["CM-7"],
            )

    def _check_asr_rules(self):
        asr = self._defender("asr_rules")
        if asr is None or (isinstance(asr, dict) and not asr.get("ids")):
            self._add_finding(
                "DR-HDN-032", "System Hardening: ASR Rules Not Configured", "MEDIUM",
                "No Attack Surface Reduction (ASR) rules are configured in "
                "Windows Defender.",
                "ASR rules block common attack techniques such as Office macro "
                "execution, credential stealing from LSASS, and executable content "
                "from email. Without them, these attack vectors remain open.",
                "Configure ASR rules via Group Policy or Intune. Start with audit "
                "mode, then move to block mode after verifying no business impact.",
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1059", "tactic": "Execution",
                               "name": "Command and Scripting Interpreter"}],
                nist_800_53=["CM-7", "SI-3"],
            )

    def _check_controlled_folder(self):
        cfa = self._defender("controlled_folder_access")
        if isinstance(cfa, dict) and not cfa.get("enabled"):
            self._add_finding(
                "DR-HDN-033", "Endpoint Protection: Controlled Folder Access Not Enabled", "LOW",
                "Windows Defender Controlled Folder Access is not enabled.",
                "Controlled Folder Access protects documents and files from "
                "unauthorized modification by ransomware and other malicious "
                "applications.",
                "Enable Controlled Folder Access via Group Policy, Intune, or "
                "PowerShell: Set-MpPreference -EnableControlledFolderAccess Enabled.",
                remediation_effort="Easy",
                nist_800_53=["SC-7"],
            )

    def _check_network_protection(self):
        np = self._defender("network_protection")
        if np is not None and int(np) != 1:
            self._add_finding(
                "DR-HDN-034", "Endpoint Protection: Network Protection Not Enabled", "LOW",
                "Windows Defender Network Protection is not enabled.",
                "Network Protection blocks outbound connections to known malicious "
                "domains and IP addresses, reducing the effectiveness of phishing "
                "and C2 communications.",
                "Enable Network Protection: Set-MpPreference "
                "-EnableNetworkProtection Enabled.",
                remediation_effort="Easy",
                nist_800_53=["SC-7"],
            )

    def _check_exploit_protection(self):
        ep = self._defender("exploit_protection")
        if ep is None or (isinstance(ep, dict) and not ep):
            self._add_finding(
                "DR-HDN-035", "Endpoint Protection: Exploit Protection Not Configured", "MEDIUM",
                "Windows Exploit Protection (process mitigations) is not configured.",
                "Exploit Protection provides mitigations such as DEP, ASLR, CFG, "
                "and EAF at the per-process level. Without configuration, only "
                "system defaults apply.",
                "Configure Exploit Protection via Group Policy or the Windows "
                "Security app. Apply recommended mitigations for high-risk "
                "applications (browsers, Office, Adobe Reader).",
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1068", "tactic": "Privilege Escalation",
                               "name": "Exploitation for Privilege Escalation"}],
                nist_800_53=["SI-16"],
            )

    def _check_smb_client_signing(self):
        val = self._reg("SMBClient_RequireSecuritySignature")
        if val is not None and int(val) != 1:
            self._add_finding(
                "DR-HDN-036",
                "Network Hardening: SMB Client Signing Not Required", "MEDIUM",
                "Outbound SMB connections from this host do not require packet "
                "signing. An attacker on the local network can intercept and "
                "relay SMB authentication to other targets.",
                "Without client-side signing, NTLM relay attacks are possible. "
                "An attacker poisons name resolution (LLMNR/NBT-NS), intercepts "
                "this machine's outbound SMB authentication, and relays it to "
                "another host to execute commands or access shares.",
                "Set RequireSecuritySignature to 1 under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters.",
                output=f"SMBClient_RequireSecuritySignature: {val}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1557.001", "tactic": "Credential Access",
                               "name": "LLMNR/NBT-NS Poisoning and SMB Relay"}],
                nist_800_53=["SC-8", "SC-23"],
            )

    def _check_anon_sam(self):
        val = self._reg("RestrictAnonymousSAM")
        if val is not None and int(val) != 1:
            self._add_finding(
                "DR-HDN-037",
                "Access Control: Anonymous SAM Account Enumeration Allowed",
                "MEDIUM",
                "Unauthenticated users can enumerate local user accounts through "
                "the SAM database (RestrictAnonymousSAM is not enabled).",
                "An attacker can retrieve the full list of local user accounts "
                "without any credentials. This provides a target list for "
                "password spraying and brute force attacks.",
                "Set RestrictAnonymousSAM to 1 in "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
                output=f"RestrictAnonymousSAM: {val}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1087.001", "tactic": "Discovery",
                               "name": "Local Account Discovery"}],
                nist_800_53=["AC-3", "AC-14"],
            )

    def _check_builtin_admin_uac_bypass(self):
        fat = self._reg("FilterAdministratorToken")
        lua = self._reg("EnableLUA")
        if lua is not None and int(lua) == 1 and (fat is None or int(fat) == 0):
            self._add_finding(
                "DR-HDN-038",
                "System Hardening: Built-in Administrator Exempt from UAC",
                "MEDIUM",
                "The built-in Administrator account (RID 500) runs all processes "
                "with full elevated privileges without UAC prompts. "
                "FilterAdministratorToken is not enabled.",
                "Any process launched by the RID-500 Administrator account "
                "runs with unrestricted administrative privileges. If an "
                "attacker obtains this account's credentials, post-exploitation "
                "is immediate with no elevation prompt barrier.",
                "Set FilterAdministratorToken to 1 under "
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.",
                output=f"FilterAdministratorToken: {fat}",
                remediation_effort="Easy",
                nist_800_53=["AC-6", "CM-6"],
            )

    def _check_blank_passwords(self):
        val = self._reg("LimitBlankPasswordUse")
        if val is not None and int(val) == 0:
            self._add_finding(
                "DR-HDN-039",
                "Authentication: Blank Passwords Permitted for Network Logon",
                "HIGH",
                "Accounts with empty passwords can authenticate over the network "
                "(SMB, RDP, WinRM). LimitBlankPasswordUse is disabled.",
                "An attacker who discovers any account with no password can "
                "authenticate remotely. On domain controllers this grants access "
                "to SYSVOL, NETLOGON, and potentially administrative shares.",
                "Set LimitBlankPasswordUse to 1 in "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
                output=f"LimitBlankPasswordUse: {val}",
                remediation_effort="Easy",
                cwe=["CWE-521"],
                mitre_attack=[{"technique": "T1078.001", "tactic": "Initial Access",
                               "name": "Default Accounts"}],
                nist_800_53=["IA-5", "AC-7"],
            )

    def _check_everyone_includes_anonymous(self):
        val = self._reg("EveryoneIncludesAnonymous")
        if val is not None and int(val) == 1:
            self._add_finding(
                "DR-HDN-040",
                "Access Control: Anonymous Users Included in Everyone Group",
                "HIGH",
                "The Everyone security group includes anonymous (unauthenticated) "
                "connections. Any resource with Everyone permissions is accessible "
                "without credentials.",
                "Shares, files, and objects granted to Everyone become accessible "
                "to null-session connections. This effectively removes the "
                "authentication boundary for any Everyone-permissioned resource.",
                "Set EveryoneIncludesAnonymous to 0 in "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
                output=f"EveryoneIncludesAnonymous: {val}",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1087", "tactic": "Discovery",
                               "name": "Account Discovery"}],
                nist_800_53=["AC-3", "AC-14"],
            )

    def _check_rdp_encryption(self):
        rdp_enabled = self._reg("fDenyTSConnections")
        if rdp_enabled is None or int(rdp_enabled) != 0:
            return
        enc = self._reg("MinEncryptionLevel")
        sec_layer = self._reg("SecurityLayer")
        issues = []
        if enc is not None and int(enc) < 3:
            issues.append(f"MinEncryptionLevel={enc} (should be 3=High)")
        if sec_layer is not None and int(sec_layer) == 0:
            issues.append(f"SecurityLayer=0 (RDP Security Layer — no TLS)")
        if issues:
            self._add_finding(
                "DR-HDN-041",
                "Remote Desktop: Weak RDP Transport Encryption", "HIGH",
                "Remote Desktop is configured with weak or legacy transport "
                "encryption. Sessions can be intercepted or downgraded.",
                "SecurityLayer=0 uses legacy RDP encryption (RC4-based, no server "
                "certificate validation). Low MinEncryptionLevel allows 56-bit or "
                "40-bit session keys. An on-path attacker can intercept keystrokes, "
                "screen content, and credentials.",
                "Set SecurityLayer to 2 (TLS) and MinEncryptionLevel to 3 (High) "
                "under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
                "WinStations\\RDP-Tcp.",
                output="\n".join(issues),
                remediation_effort="Easy",
                cwe=["CWE-326"],
                mitre_attack=[{"technique": "T1021.001", "tactic": "Lateral Movement",
                               "name": "Remote Desktop Protocol"}],
                nist_800_53=["SC-8", "SC-23"],
            )

    def _check_audit_subcategories(self):
        audit = self._get_section("registry_hardening", {}).get("audit_policy", {})
        if not isinstance(audit, dict):
            return
        critical_subs = {
            ("Logon/Logoff", "Logon"): "Success and Failure",
            ("Account Management", "User Account Management"): "Success and Failure",
            ("Account Logon", "Credential Validation"): "Success and Failure",
            ("Detailed Tracking", "Process Creation"): "Success",
            ("DS Access", "Directory Service Access"): "Success and Failure",
            ("Policy Change", "Audit Policy Change"): "Success and Failure",
            ("Privilege Use", "Sensitive Privilege Use"): "Success and Failure",
        }
        gaps = []
        for (cat, sub), required in critical_subs.items():
            cat_data = audit.get(cat, {})
            if not isinstance(cat_data, dict):
                continue
            actual = cat_data.get(sub, "No Auditing")
            if actual == "No Auditing" or actual == "":
                gaps.append(f"{cat} > {sub}: {actual} (need {required})")
        if len(gaps) >= 3:
            self._add_finding(
                "DR-HDN-042",
                "Monitoring: Critical Audit Subcategories Disabled", "MEDIUM",
                f"{len(gaps)} security-critical audit subcategories are not "
                f"configured. Events in these categories are not being logged.",
                "Without subcategory auditing for logon events, credential "
                "validation, account management, and process creation, the "
                "system cannot detect brute force attacks, pass-the-hash, "
                "unauthorized account changes, or malicious process execution.",
                "Enable Advanced Audit Policy via Group Policy for at minimum: "
                "Logon, User Account Management, Credential Validation, Process "
                "Creation, and Audit Policy Change.",
                output="\n".join(gaps),
                remediation_effort="Easy",
                nist_800_53=["AU-2", "AU-3", "AU-12"],
            )

    def _check_dangerous_user_rights(self):
        sp = self._get_section("security_policy", {})
        if not isinstance(sp, dict):
            return
        ura = sp.get("user_rights_assignment", {})
        if not isinstance(ura, dict):
            return
        _SAFE_SIDS = {
            "*s-1-5-18", "*s-1-5-19", "*s-1-5-20",
            "*s-1-5-32-544",
        }
        dangerous = []
        _HIGH_RISK_RIGHTS = {
            "SeDebugPrivilege": "Debug programs — can dump LSASS",
            "SeTakeOwnershipPrivilege": "Take ownership of objects",
            "SeLoadDriverPrivilege": "Load kernel drivers",
            "SeBackupPrivilege": "Bypass ACLs to read any file",
            "SeRestorePrivilege": "Bypass ACLs to write any file",
            "SeTcbPrivilege": "Act as part of the operating system",
            "SeAssignPrimaryTokenPrivilege": "Replace a process-level token",
            "SeImpersonatePrivilege": "Impersonate a client after authentication",
        }
        for right, desc in _HIGH_RISK_RIGHTS.items():
            assigned = ura.get(right, "")
            if not assigned:
                continue
            principals = [p.strip() for p in assigned.split(",") if p.strip()]
            non_standard = [p for p in principals if p.lower() not in _SAFE_SIDS]
            if non_standard:
                dangerous.append(f"{right}: {', '.join(non_standard)} — {desc}")
        if dangerous:
            self._add_finding(
                "DR-HDN-043",
                "Privilege Escalation: Sensitive User Rights Assigned to Non-Default Accounts",
                "HIGH",
                f"{len(dangerous)} sensitive user right(s) are assigned to "
                f"accounts beyond the operating system defaults. These rights "
                f"enable credential theft, kernel-level access, or file system "
                f"bypass.",
                "SeDebugPrivilege allows dumping LSASS memory to extract all "
                "cached credentials. SeLoadDriverPrivilege allows loading a "
                "malicious kernel driver. SeBackupPrivilege allows reading any "
                "file on the system regardless of ACLs, including SAM and "
                "SYSTEM registry hives.",
                "Review User Rights Assignment in Group Policy (Computer "
                "Configuration > Security Settings > Local Policies > User "
                "Rights Assignment). Remove non-essential accounts from "
                "sensitive privileges. Only SYSTEM, LOCAL SERVICE, and "
                "Administrators should hold these rights.",
                output="\n".join(dangerous[:10]),
                remediation_effort="Moderate",
                cwe=["CWE-269", "CWE-250"],
                mitre_attack=[{"technique": "T1134", "tactic": "Privilege Escalation",
                               "name": "Access Token Manipulation"}],
                nist_800_53=["AC-6", "CM-6"],
            )

    def _check_legacy_audit_override(self):
        val = self._reg("SCENoApplyLegacyAuditPolicy")
        if val is not None and int(val) != 1:
            self._add_finding(
                "DR-HDN-044",
                "Monitoring: Advanced Audit Policy Overridden by Legacy Settings",
                "MEDIUM",
                "Advanced Audit Policy subcategory settings are being silently "
                "overridden by legacy basic audit policy. Granular audit "
                "configurations may not be taking effect.",
                "Without SCENoApplyLegacyAuditPolicy enabled, basic audit "
                "policy (Success/Failure per category) takes precedence over "
                "Advanced Audit Policy subcategory settings. Administrators "
                "who configure granular auditing may not realize their "
                "settings are being ignored.",
                "Set SCENoApplyLegacyAuditPolicy to 1 under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa and use only "
                "Advanced Audit Policy Configuration in Group Policy.",
                output=f"SCENoApplyLegacyAuditPolicy: {val}",
                remediation_effort="Easy",
                nist_800_53=["AU-2", "AU-12"],
            )

    # ------------------------------------------------------------------ #
    # DR-HDN-046  SMB Encryption
    # ------------------------------------------------------------------ #
    def _check_smb_encryption(self):
        reg = self._get_section("registry_hardening", {})
        smb = reg.get("smb_server", {}) if isinstance(reg, dict) else {}
        encrypt = smb.get("EncryptData") if isinstance(smb, dict) else None
        reject = smb.get("RejectUnencryptedAccess") if isinstance(smb, dict) else None
        if encrypt is None:
            encrypt = self._reg("SMBServer_EncryptData")
        if reject is None:
            reject = self._reg("SMBServer_RejectUnencryptedAccess")
        if encrypt is not None and int(encrypt) != 1:
            self._add_finding(
                "DR-HDN-046",
                "Network Hardening: SMB Encryption Not Enabled", "MEDIUM",
                "SMB traffic encryption is not enabled on the server. All file "
                "share and IPC traffic is transmitted in cleartext on the wire.",
                "Without SMB encryption, an attacker with network access can "
                "capture file contents, credentials in transit, and sensitive "
                "data from shared folders using passive sniffing.",
                "Enable SMB encryption: Set-SmbServerConfiguration "
                "-EncryptData $true. For per-share encryption: "
                "Set-SmbShare -Name <share> -EncryptData $true.",
                output=f"EncryptData: {encrypt}",
                remediation_effort="Easy",
                remediation_category="Network Security",
                mitre_attack=[{"technique": "T1040", "tactic": "Credential Access",
                               "name": "Network Sniffing"}],
                nist_800_53=["SC-8", "SC-13"],
            )
        if reject is not None and int(reject) != 1 and encrypt is not None and int(encrypt) == 1:
            self._add_finding(
                "DR-HDN-047",
                "Network Hardening: SMB Unencrypted Access Not Rejected", "LOW",
                "SMB encryption is enabled but the server does not reject "
                "connections from clients that do not support encryption.",
                "Clients that do not support SMB3 encryption can still connect "
                "with unencrypted SMB2/SMB3, negating the encryption policy "
                "for those sessions.",
                "Enable RejectUnencryptedAccess: Set-SmbServerConfiguration "
                "-RejectUnencryptedAccess $true. Verify all clients support "
                "SMB3 encryption before enabling.",
                output=f"EncryptData: {encrypt}, RejectUnencryptedAccess: {reject}",
                remediation_effort="Easy",
                remediation_category="Network Security",
                nist_800_53=["SC-8"],
            )

    # ------------------------------------------------------------------ #
    # DR-HDN-048  Windows Event Forwarding
    # ------------------------------------------------------------------ #
    def _check_wef(self):
        wef = self._get_section("wef_config", {})
        if not isinstance(wef, dict):
            return
        service_status = wef.get("wec_service_status", wef.get("service_status", ""))
        subscriptions = wef.get("subscriptions", [])
        if not service_status:
            return
        if service_status.lower() != "running":
            self._add_finding(
                "DR-HDN-048",
                "Monitoring: Windows Event Forwarding Not Active", "MEDIUM",
                "The Windows Event Collector (WEC) service is not running. "
                "Event forwarding subscriptions cannot receive events.",
                "Without WEF, security events remain on individual endpoints "
                "and are lost when disk space runs out or when an attacker "
                "clears local logs. Centralised collection is critical for "
                "SIEM-based detection and incident response.",
                "Enable WEC: wecutil qc. Configure subscriptions via Group "
                "Policy (Computer Configuration > Administrative Templates > "
                "Windows Components > Event Forwarding).",
                output=f"WEC service: {service_status}",
                remediation_effort="Moderate",
                remediation_category="Monitoring",
                nist_800_53=["AU-4", "AU-6", "SI-4"],
                nist_csf2=["DE.CM-1"],
            )
        elif isinstance(subscriptions, list) and len(subscriptions) == 0:
            self._add_finding(
                "DR-HDN-049",
                "Monitoring: No WEF Subscriptions Configured", "LOW",
                "The Windows Event Collector service is running but no event "
                "subscriptions are configured.",
                "WEC is enabled but has no subscriptions to forward events "
                "to a collector. Security events are not being centralised.",
                "Create WEF subscriptions using wecutil cs <subscription.xml> "
                "or via Group Policy. Forward at minimum: Security log, "
                "Sysmon, PowerShell, and AppLocker events.",
                remediation_effort="Moderate",
                remediation_category="Monitoring",
                nist_800_53=["AU-4", "AU-6"],
            )

    # ------------------------------------------------------------------ #
    # DR-HDN-050  Removable Storage Policy
    # ------------------------------------------------------------------ #
    def _check_removable_storage(self):
        reg = self._get_section("registry_hardening", {})
        if not isinstance(reg, dict):
            return
        removable = reg.get("removable_storage_policy", reg.get("removable_storage", {}))
        if not isinstance(removable, dict):
            return
        deny_all = removable.get("deny_all_read", removable.get("Deny_All"))
        deny_write = removable.get("deny_all_write", removable.get("Deny_Write"))
        deny_read = removable.get("deny_all_read", removable.get("Deny_Read"))
        deny_execute = removable.get("Deny_Execute")
        if deny_all is not None and int(deny_all) == 1:
            return
        issues = []
        if deny_write is None or int(deny_write) != 1:
            issues.append("Write access: allowed")
        if deny_execute is None or int(deny_execute) != 1:
            issues.append("Execute access: allowed")
        if not issues:
            return
        self._add_finding(
            "DR-HDN-050",
            "System Hardening: Removable Storage Policy Not Restrictive",
            "MEDIUM",
            f"Removable storage access is not restricted. "
            f"{'; '.join(issues)}.",
            "Unrestricted removable storage allows data exfiltration via USB "
            "drives and introduces malware risk from infected media. Write "
            "access enables an insider to copy sensitive data; execute access "
            "enables auto-launched payloads.",
            "Configure Group Policy: Computer Configuration > Administrative "
            "Templates > System > Removable Storage Access. At minimum deny "
            "write and execute access to removable disks.",
            output=f"Deny_All: {deny_all}, Deny_Write: {deny_write}, "
                   f"Deny_Execute: {deny_execute}, Deny_Read: {deny_read}",
            remediation_effort="Easy",
            remediation_category="Access Control",
            mitre_attack=[{"technique": "T1091", "tactic": "Initial Access",
                           "name": "Replication Through Removable Media"},
                          {"technique": "T1052.001", "tactic": "Exfiltration",
                           "name": "Exfiltration over USB"}],
            nist_800_53=["MP-7", "SC-41"],
            pci_dss_4=["2.2.7"],
        )

    # ------------------------------------------------------------------ #
    # DR-HDN-051-053  Expanded Audit Subcategories
    # ------------------------------------------------------------------ #
    def _check_expanded_audit_subcategories(self):
        audit = self._get_section("registry_hardening", {}).get("audit_policy", {})
        if not isinstance(audit, dict):
            return
        _EXTRA_SUBS = {
            ("Logon/Logoff", "Special Logon"): ("Success", "DR-HDN-051",
                "Monitoring: Special Logon Events Not Audited"),
            ("Logon/Logoff", "Account Lockout"): ("Failure", "DR-HDN-052",
                "Monitoring: Account Lockout Events Not Audited"),
            ("Object Access", "Removable Storage"): ("Success,Failure", "DR-HDN-053",
                "Monitoring: Removable Storage Access Not Audited"),
        }
        for (cat, sub), (needed, cat_id, title) in _EXTRA_SUBS.items():
            cat_data = audit.get(cat, {})
            if not isinstance(cat_data, dict):
                continue
            actual = cat_data.get(sub, "No Auditing")
            if actual and actual != "No Auditing":
                continue
            self._add_finding(
                cat_id, title, "LOW",
                f"The audit subcategory '{cat} > {sub}' is set to "
                f"'{actual}'. Recommended: {needed}.",
                f"Without auditing {sub} events, the security team lacks "
                f"visibility into this activity category, which may hinder "
                f"forensic investigation and threat detection.",
                f"Enable '{sub}' auditing via: auditpol /set /subcategory:"
                f'"{sub}" /success:enable /failure:enable.',
                output=f"{cat} > {sub}: {actual} (need {needed})",
                remediation_effort="Easy",
                remediation_category="Monitoring",
                nist_800_53=["AU-2", "AU-12"],
            )

    # ------------------------------------------------------------------ #
    # DR-HDN-054-058  Defender Detailed Checks
    # ------------------------------------------------------------------ #
    def _check_defender_detailed(self):
        dd = self._get_section("defender_detailed", {})
        if not isinstance(dd, dict) or not dd:
            return
        tamper = dd.get("tamper_protection")
        if tamper is not None and not tamper:
            self._add_finding(
                "DR-HDN-054",
                "Endpoint Protection: Defender Tamper Protection Disabled",
                "HIGH",
                "Windows Defender Tamper Protection is disabled. Malware or "
                "an attacker can disable Defender protections programmatically.",
                "Without Tamper Protection, an attacker with admin access can "
                "disable Defender via PowerShell, registry edits, or the "
                "sc command. Ransomware routinely disables AV before encrypting.",
                "Enable Tamper Protection via the Windows Security app or "
                "Intune. It cannot be enabled via Group Policy by design.",
                remediation_effort="Easy",
                remediation_category="Endpoint Protection",
                mitre_attack=[{"technique": "T1562.001", "tactic": "Defense Evasion",
                               "name": "Disable or Modify Tools"}],
                nist_800_53=["SI-3", "SI-4"],
            )
        cloud = dd.get("cloud_protection")
        if cloud is not None and not cloud:
            self._add_finding(
                "DR-HDN-055",
                "Endpoint Protection: Defender Cloud Protection Disabled",
                "MEDIUM",
                "Defender cloud-delivered protection is disabled. The endpoint "
                "relies solely on local signature definitions.",
                "Cloud protection provides rapid response to zero-day threats "
                "through cloud-based machine learning. Without it, detection "
                "depends on local definitions which may be hours behind.",
                "Enable cloud protection: Set-MpPreference "
                "-MAPSReporting Advanced.",
                remediation_effort="Easy",
                remediation_category="Endpoint Protection",
                nist_800_53=["SI-3"],
            )
        def_age = dd.get("definition_age_days")
        if def_age is not None:
            try:
                age = int(def_age)
            except (ValueError, TypeError):
                age = 0
            if age > 7:
                risk = "HIGH" if age > 14 else "MEDIUM"
                self._add_finding(
                    "DR-HDN-056",
                    "Endpoint Protection: Defender Definitions Outdated",
                    risk,
                    f"Antimalware definitions are {age} day(s) old. "
                    f"Current threats may not be detected.",
                    "Outdated antivirus definitions miss newly discovered "
                    "malware signatures. Threat actors routinely test payloads "
                    "against current definitions, so stale definitions "
                    "significantly reduce detection rates.",
                    "Update definitions: Update-MpSignature. Investigate why "
                    "automatic updates are failing.",
                    output=f"Definition age: {age} days",
                    remediation_effort="Easy",
                    remediation_category="Endpoint Protection",
                    nist_800_53=["SI-3"],
                )
        av_products = dd.get("av_products", [])
        if isinstance(av_products, list):
            disabled_av = [a for a in av_products
                           if isinstance(a, dict)
                           and not a.get("enabled", True)]
            if disabled_av:
                names = ", ".join(a.get("name", "?") for a in disabled_av[:5])
                self._add_finding(
                    "DR-HDN-057",
                    "Endpoint Protection: Antivirus Product Disabled",
                    "HIGH",
                    f"Installed antivirus product(s) are disabled: {names}.",
                    "A disabled antivirus product provides zero protection. "
                    "This may indicate tampering by malware or an attacker.",
                    f"Re-enable {names}. Investigate why it was disabled.",
                    output=f"Disabled AV: {names}",
                    remediation_effort="Easy",
                    remediation_category="Endpoint Protection",
                    mitre_attack=[{"technique": "T1562.001",
                                   "tactic": "Defense Evasion",
                                   "name": "Disable or Modify Tools"}],
                    nist_800_53=["SI-3"],
                )
        rtp_detail = dd.get("realtime_protection_detail", {})
        if isinstance(rtp_detail, dict):
            behavior = rtp_detail.get("behavior_monitoring")
            ioav = rtp_detail.get("ioav_protection")
            on_access = rtp_detail.get("on_access_protection")
            parts = []
            if behavior is not None and not behavior:
                parts.append("Behavior monitoring: OFF")
            if ioav is not None and not ioav:
                parts.append("IOAV protection: OFF")
            if on_access is not None and not on_access:
                parts.append("On-access protection: OFF")
            if parts:
                self._add_finding(
                    "DR-HDN-058",
                    "Endpoint Protection: Defender Sub-Protections Disabled",
                    "MEDIUM",
                    f"One or more Defender real-time sub-protections are "
                    f"disabled: {'; '.join(parts)}.",
                    "Disabling behaviour monitoring, IOAV, or on-access "
                    "protection weakens the overall Defender posture even "
                    "when real-time protection shows as enabled.",
                    "Re-enable all sub-protections via PowerShell: "
                    "Set-MpPreference -DisableBehaviorMonitoring $false "
                    "-DisableIOAVProtection $false "
                    "-DisableRealtimeMonitoring $false.",
                    output="\n".join(parts),
                    remediation_effort="Easy",
                    remediation_category="Endpoint Protection",
                    nist_800_53=["SI-3"],
                )

    # ------------------------------------------------------------------ #
    # DR-HDN-059  DNS Client Security
    # ------------------------------------------------------------------ #
    def _check_dns_client(self):
        reg = self._get_section("registry_hardening", {})
        dns = reg.get("dns_client", {}) if isinstance(reg, dict) else {}
        if not isinstance(dns, dict) or not dns:
            return
        doh_policy = dns.get("doh_policy")
        doh_gpo = dns.get("doh_policy_gpo")
        doh_https = dns.get("dns_over_https")
        doh = doh_policy is not None and int(doh_policy or 0) >= 1
        doh = doh or (doh_gpo is not None and int(doh_gpo or 0) >= 1)
        doh = doh or (doh_https is not None and int(doh_https or 0) >= 1)
        dot = False
        dnssec_val = False
        issues = []
        if doh is not None and not doh and dot is not None and not dot:
            issues.append("Neither DNS-over-HTTPS nor DNS-over-TLS is enabled")
        if dnssec_val is not None and not dnssec_val:
            issues.append("DNSSEC validation is not enabled")
        if not issues:
            return
        self._add_finding(
            "DR-HDN-059",
            "Network Hardening: DNS Client Security Not Configured",
            "LOW",
            f"DNS client security gaps: {'; '.join(issues)}.",
            "Without encrypted DNS (DoH/DoT), all DNS queries are visible "
            "to network observers, leaking browsing activity and internal "
            "hostnames. Without DNSSEC validation, DNS responses can be "
            "spoofed to redirect traffic to attacker-controlled servers.",
            "Enable DNS-over-HTTPS in Windows 11+: Settings > Network > "
            "DNS server assignment > Encrypted preferred. For older systems, "
            "deploy a local encrypted DNS proxy.",
            output="\n".join(issues),
            remediation_effort="Moderate",
            remediation_category="Network Security",
            mitre_attack=[{"technique": "T1557", "tactic": "Credential Access",
                           "name": "Adversary-in-the-Middle"}],
            nist_800_53=["SC-8", "SC-20"],
        )

    # ------------------------------------------------------------------ #
    # DR-HDN-060  CIS Baseline Comparison
    # ------------------------------------------------------------------ #
    def _check_cis_baseline(self):
        reg = self._get_section("registry_hardening", {})
        if not isinstance(reg, dict):
            return
        sp = self._get_section("security_policy", {})
        if not isinstance(sp, dict):
            sp = {}
        ss = reg.get("screen_saver", {}) if isinstance(reg, dict) else {}
        if not isinstance(ss, dict):
            ss = {}
        _CIS_CHECKS = [
            ("screen_saver_timeout", ss.get("timeout_seconds", reg.get("ScreenSaverTimeout")),
             lambda v: v is not None and int(v) <= 900,
             "Screen saver timeout > 15 minutes or not set"),
            ("screen_saver_active", ss.get("active", reg.get("ScreenSaverActive")),
             lambda v: v is not None and str(v) == "1",
             "Screen saver not enforced"),
            ("no_connect", reg.get("NoConnectedUser"),
             lambda v: v is not None and int(v) >= 1,
             "Microsoft account connections not restricted"),
            ("safe_dll_search", reg.get("SafeDllSearchMode"),
             lambda v: v is None or int(v) == 1,
             "Safe DLL search order disabled"),
            ("ie_security_zone", reg.get("IEHardenAdmin"),
             lambda v: v is not None and int(v) == 1,
             "IE Enhanced Security for admins not enabled (server only)"),
        ]
        password_policy = sp.get("password_policy", {})
        if isinstance(password_policy, dict):
            min_len = password_policy.get("MinimumPasswordLength")
            if min_len is not None:
                try:
                    ml = int(min_len)
                except (ValueError, TypeError):
                    ml = 0
                if ml < 14:
                    _CIS_CHECKS.append(
                        ("min_pw_len", min_len,
                         lambda v: False,
                         f"Minimum password length is {ml} (CIS: >= 14)"))
            max_age = password_policy.get("MaximumPasswordAge")
            if max_age is not None:
                try:
                    ma = int(max_age)
                except (ValueError, TypeError):
                    ma = 0
                if ma > 365 or ma == 0:
                    _CIS_CHECKS.append(
                        ("max_pw_age", max_age,
                         lambda v: False,
                         f"Maximum password age is {ma} days (CIS: <= 365, non-zero)"))
            complexity = password_policy.get("PasswordComplexity")
            if complexity is not None and int(complexity) != 1:
                _CIS_CHECKS.append(
                    ("pw_complexity", complexity,
                     lambda v: False,
                     "Password complexity requirements not enforced"))
        lockout_policy = sp.get("lockout_policy", {})
        if isinstance(lockout_policy, dict):
            threshold = lockout_policy.get("LockoutBadCount")
            if threshold is not None:
                try:
                    lt = int(threshold)
                except (ValueError, TypeError):
                    lt = 0
                if lt == 0 or lt > 5:
                    _CIS_CHECKS.append(
                        ("lockout_threshold", threshold,
                         lambda v: False,
                         f"Account lockout threshold is {lt} (CIS: 1-5)"))
        failures = []
        for name, val, check_fn, msg in _CIS_CHECKS:
            try:
                if not check_fn(val):
                    failures.append(msg)
            except (ValueError, TypeError):
                failures.append(msg)
        if self._is_server():
            ie_check = reg.get("IEHardenAdmin")
        else:
            failures = [f for f in failures
                        if "IE Enhanced Security" not in f]
        if len(failures) < 3:
            return
        self._add_finding(
            "DR-HDN-060",
            "Compliance: CIS Benchmark Baseline Deviations",
            "MEDIUM",
            f"{len(failures)} setting(s) deviate from the CIS Windows "
            f"benchmark baseline.",
            "CIS benchmarks represent industry-consensus hardening standards. "
            "Multiple deviations indicate the system has not been hardened "
            "according to best practices, increasing the overall attack surface.",
            "Apply the CIS Windows benchmark using Group Policy or a "
            "configuration management tool. Start with Level 1 settings, "
            "then evaluate Level 2 settings for applicability.",
            output="\n".join(failures[:15]),
            remediation_effort="Significant",
            remediation_category="Compliance",
            nist_800_53=["CM-6", "CM-7"],
            nist_csf2=["PR.IP-1"],
            pci_dss_4=["2.2.1"],
        )
