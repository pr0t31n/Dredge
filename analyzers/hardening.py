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
            if not current or current.lower() == "no auditing":
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
