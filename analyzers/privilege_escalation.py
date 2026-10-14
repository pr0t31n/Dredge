from analyzers.base import BaseAnalyzer


class PrivilegeEscalationAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_always_install_elevated()
        self._check_modifiable_service_binaries()
        self._check_dll_hijacking()
        self._check_token_privileges()
        self._check_unquoted_service_paths()
        self._check_named_pipes()
        return self.findings

    def _priv(self, key, default=None):
        section = self._get_section("privilege_escalation", {})
        if not isinstance(section, dict):
            return default
        return section.get(key, default)

    def _check_always_install_elevated(self):
        hklm = self._priv("always_install_elevated_hklm")
        hkcu = self._priv("always_install_elevated_hkcu")
        if hklm is not None and hkcu is not None:
            if int(hklm) == 1 and int(hkcu) == 1:
                self._add_finding(
                    "DR-PRIV-001", "Privilege Escalation: AlwaysInstallElevated Enabled", "HIGH",
                    "Both HKLM and HKCU AlwaysInstallElevated registry keys are "
                    "set to 1. This allows any user to install MSI packages with "
                    "SYSTEM-level privileges.",
                    "An attacker with low-privilege access can craft a malicious "
                    "MSI package that executes arbitrary code as SYSTEM. This is "
                    "a well-known privilege escalation vector exploitable with "
                    "msfvenom or manual MSI crafting.",
                    "Set AlwaysInstallElevated to 0 in both "
                    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer and "
                    "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer.",
                    output=f"HKLM AlwaysInstallElevated: {hklm}, "
                           f"HKCU AlwaysInstallElevated: {hkcu}",
                    remediation_effort="Easy",
                    remediation_category="Configuration",
                    cwe=["CWE-269"],
                    cvss_score=7.8,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    mitre_attack=[{"technique": "T1546.016", "tactic": "Privilege Escalation",
                                   "name": "Installer Packages"}],
                    nist_800_53=["CM-6", "AC-6"],
                    pci_dss_4=["2.2.1"],
                )

    def _check_modifiable_service_binaries(self):
        services = self._priv("modifiable_services", [])
        if not services:
            return
        for svc in services:
            if not isinstance(svc, dict):
                continue
            name = svc.get("name", "Unknown")
            path = svc.get("binary_path", "")
            account = svc.get("start_account", "")
            self._add_finding(
                "DR-PRIV-002", "Privilege Escalation: Modifiable Service Binary", "HIGH",
                f"Service '{name}' has a binary path that is writable by the "
                f"current user. An attacker can replace the service binary to "
                f"execute code with the service's privileges.",
                f"The service runs as '{account or 'unknown account'}'. By "
                f"replacing the service binary, an attacker gains code execution "
                f"at the service's privilege level, which is often SYSTEM.",
                f"Fix the file ACL on '{path}' to restrict write access to "
                f"administrators only. Ensure service binaries reside in "
                f"protected directories (e.g., C:\\Windows\\, C:\\Program Files\\).",
                output=f"Service: {name}, Path: {path}, Account: {account}",
                affected=f"{self.hostname} — service: {name}",
                remediation_effort="Moderate",
                remediation_category="Access Control",
                cwe=["CWE-732"],
                mitre_attack=[{"technique": "T1574.010", "tactic": "Privilege Escalation",
                               "name": "Services File Permissions Weakness"}],
                nist_800_53=["AC-6", "CM-5"],
            )

    def _check_dll_hijacking(self):
        writable_dirs = self._priv("writable_path_dirs", [])
        if not writable_dirs:
            return
        dir_list = ", ".join(
            d.get("path", str(d)) if isinstance(d, dict) else str(d)
            for d in writable_dirs[:10]
        )
        self._add_finding(
            "DR-PRIV-003", "Privilege Escalation: DLL Search Order Hijacking", "MEDIUM",
            f"{len(writable_dirs)} directory(ies) in the system PATH are writable "
            f"by the current user. Placing a malicious DLL in these directories "
            f"can hijack DLL loading for applications and services.",
            "DLL search order hijacking allows an attacker to place a malicious "
            "DLL in a writable PATH directory. When an application searches for "
            "a DLL, it may load the attacker's version first, executing arbitrary "
            "code with the application's privileges.",
            "Remove writable directories from the system PATH or fix their ACLs "
            "to prevent non-admin writes. Ensure applications use absolute DLL "
            "paths and enable SafeDllSearchMode.",
            output=f"Writable PATH dirs: {dir_list}",
            remediation_effort="Moderate",
            remediation_category="Access Control",
            cwe=["CWE-427"],
            mitre_attack=[{"technique": "T1574.001", "tactic": "Privilege Escalation",
                           "name": "DLL Search Order Hijacking"}],
            nist_800_53=["CM-5", "CM-6"],
        )

    def _check_token_privileges(self):
        privs = self._priv("token_privileges", [])
        if not privs:
            return
        dangerous = {
            "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
            "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
            "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege",
            "SeCreateTokenPrivilege",
        }
        found = []
        for p in privs:
            name = p.get("privilege", p) if isinstance(p, dict) else str(p)
            status = p.get("status", "Enabled") if isinstance(p, dict) else "Enabled"
            if name in dangerous and status.lower() != "disabled":
                found.append(name)
        if not found:
            return
        priv_list = ", ".join(found)
        self._add_finding(
            "DR-PRIV-004", "Privilege Escalation: Dangerous Token Privileges", "HIGH",
            f"The current process holds {len(found)} dangerous privilege(s): "
            f"{priv_list}. These privileges can be abused for privilege escalation "
            f"to SYSTEM.",
            "SeImpersonatePrivilege enables potato-family attacks (JuicyPotato, "
            "PrintSpoofer, GodPotato) for SYSTEM escalation. SeDebugPrivilege "
            "allows process injection into any process. SeBackupPrivilege enables "
            "reading any file regardless of ACLs. SeLoadDriverPrivilege allows "
            "loading arbitrary kernel drivers.",
            "Remove unnecessary privileges from user and service accounts. Follow "
            "the principle of least privilege. Use Group Policy to restrict "
            "privilege assignments.",
            output=f"Dangerous privileges: {priv_list}",
            remediation_effort="Moderate",
            remediation_category="Access Control",
            cwe=["CWE-250"],
            mitre_attack=[{"technique": "T1134", "tactic": "Privilege Escalation",
                           "name": "Access Token Manipulation"}],
            nist_800_53=["AC-6"],
        )

    def _check_unquoted_service_paths(self):
        services = self._priv("unquoted_service_paths", [])
        if not services:
            return
        for svc in services:
            if not isinstance(svc, dict):
                continue
            name = svc.get("name", "Unknown")
            path = svc.get("binary_path", "")
            writable_dir = svc.get("writable_intermediate", "")
            self._add_finding(
                "DR-PRIV-005", "Privilege Escalation: Unquoted Service Path", "MEDIUM",
                f"Service '{name}' has an unquoted binary path containing spaces: "
                f"'{path}'. An intermediate directory in this path is writable, "
                f"allowing binary planting.",
                "Unquoted service paths with spaces cause Windows to attempt "
                "loading executables at each space boundary. If an attacker can "
                "write to an intermediate directory, they can plant a binary that "
                "runs with the service's privileges.",
                f"Quote the service binary path in the registry. Fix the command: "
                f"sc config \"{name}\" binpath= \"\\\"{path}\\\"\"",
                output=f"Service: {name}, Path: {path}, "
                       f"Writable dir: {writable_dir}",
                affected=f"{self.hostname} — service: {name}",
                remediation_effort="Easy",
                remediation_category="Configuration",
                cwe=["CWE-428"],
                mitre_attack=[{"technique": "T1574.009", "tactic": "Privilege Escalation",
                               "name": "Path Interception by Unquoted Path"}],
                nist_800_53=["CM-6"],
            )

    def _check_named_pipes(self):
        pipes = self._priv("permissive_named_pipes", [])
        if not pipes:
            return
        pipe_names = ", ".join(
            p.get("name", str(p)) if isinstance(p, dict) else str(p)
            for p in pipes[:10]
        )
        self._add_finding(
            "DR-PRIV-006", "Access Control: Named Pipe Permission Weakness", "MEDIUM",
            f"{len(pipes)} named pipe(s) have permissive ACLs allowing "
            f"non-administrative access. Permissive named pipes can be exploited "
            f"for impersonation attacks.",
            "Named pipes with overly permissive ACLs can be used for "
            "impersonation-based privilege escalation. An attacker can connect "
            "to the pipe and impersonate the pipe server's security context.",
            "Restrict named pipe ACLs to only the required users and groups. "
            "Audit named pipe permissions regularly. Consider using "
            "RestrictRemoteClients to limit named pipe access.",
            output=f"Permissive pipes: {pipe_names}",
            remediation_effort="Moderate",
            remediation_category="Access Control",
            cwe=["CWE-732"],
            mitre_attack=[{"technique": "T1134", "tactic": "Privilege Escalation",
                           "name": "Access Token Manipulation"}],
            nist_800_53=["AC-6"],
        )
