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
                "DR-HDN-001", "UAC Disabled", "HIGH",
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
                "DR-HDN-002", "UAC Prompt Behavior Weak", "MEDIUM",
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
                "DR-HDN-003", "SMBv1 Protocol Enabled", "MEDIUM",
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
                "DR-HDN-004", "SMB Signing Not Required", "MEDIUM",
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
                "DR-HDN-005", "NTLMv1 Authentication Allowed", "HIGH",
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
                "DR-HDN-006", "LM Password Hashes Stored", "HIGH",
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
                "DR-HDN-008", "WDigest Plaintext Credentials Enabled", "CRITICAL",
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
                "DR-HDN-009", "LSA Protection Not Enabled", "HIGH",
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
                "DR-HDN-010", "Credential Guard Not Enabled", "MEDIUM",
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
                "DR-HDN-007", "AutoRun Enabled", "MEDIUM",
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
                "DR-HDN-011", "LLMNR Enabled", "MEDIUM",
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
                    "DR-HDN-012", "WPAD Enabled", "MEDIUM",
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
                "DR-HDN-013", "PowerShell Script Block Logging Disabled", "MEDIUM",
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
                "DR-HDN-014", "PowerShell Module Logging Disabled", "LOW",
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
                "DR-HDN-015", "PowerShell Transcription Disabled", "LOW",
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
                "DR-HDN-016", "PowerShell v2 Engine Available", "MEDIUM",
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
                "DR-HDN-017", "Windows Defender Disabled", "HIGH",
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
                "DR-HDN-018", "Windows Defender Exclusions Present", "MEDIUM",
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
                "DR-HDN-019", "Windows Defender Real-Time Protection Off", "HIGH",
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
                    "DR-HDN-020", "Remote Desktop Without NLA", "HIGH",
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
                "DR-HDN-021", "DEP Not Enabled System-Wide", "MEDIUM",
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
                    "DR-HDN-022", "Anonymous Access to Named Pipes", "HIGH",
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
                "DR-HDN-023", "Null Session Access Allowed", "HIGH",
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
                "DR-HDN-024", "Audit Policy Insufficient", "MEDIUM",
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
                    "DR-HDN-025", "Print Spooler Running on Server", risk,
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
