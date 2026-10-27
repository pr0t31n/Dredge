import re
from analyzers.base import BaseAnalyzer

_LOLBIN_EXECUTABLES = {
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "cmd", "cmd.exe", "wscript", "wscript.exe",
    "cscript", "cscript.exe", "mshta", "mshta.exe",
    "rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe",
    "certutil", "certutil.exe", "bitsadmin", "bitsadmin.exe",
    "msiexec", "msiexec.exe",
}

_SUSPICIOUS_ARG_PATTERNS = re.compile(
    r"-enc\b|-encodedcommand\b|-e\s|"
    r"https?://|\\\\\\\\|"
    r"base64|downloadstring|downloadfile|downloaddata|"
    r"invoke-expression|iex\b|invoke-webrequest|"
    r"bypass|-nop\b|-noni\b|-windowstyle\s+hidden|"
    r"webclient|start-bitstransfer|net\.webclient|"
    r"frombase64string",
    re.IGNORECASE,
)

_USER_WRITABLE_PATHS_RE = re.compile(
    r"\\users\\|\\temp\\|\\tmp\\|\\appdata\\|\\programdata\\|"
    r"\\downloads\\|\\desktop\\|\\public\\|"
    r"c:\\temp\\|c:\\tmp\\",
    re.IGNORECASE,
)


class PersistenceAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_wmi_subscriptions()
        self._check_com_hijacking()
        self._check_appinit_dlls()
        self._check_ifeo()
        self._check_accessibility_features()
        self._check_print_monitors()
        self._check_sysmon()
        self._check_lsa_packages()
        self._check_scheduled_tasks()
        return self.findings

    def _pers(self, key, default=None):
        section = self._get_section("persistence_mechanisms", {})
        if not isinstance(section, dict):
            return default
        return section.get(key, default)

    def _check_wmi_subscriptions(self):
        subs = self._pers("wmi_subscriptions", [])
        if not subs:
            return
        for sub in subs:
            if not isinstance(sub, dict):
                continue
            filter_name = sub.get("filter_name", "Unknown")
            consumer_name = sub.get("consumer_name", "Unknown")
            consumer_type = sub.get("consumer_type", "")
            command = sub.get("command_line_template",
                              sub.get("script_text", ""))
            self._add_finding(
                "DR-PERS-001", "Persistence: WMI Event Subscription", "HIGH",
                f"WMI event subscription detected: filter '{filter_name}' bound "
                f"to consumer '{consumer_name}' ({consumer_type}). WMI "
                f"subscriptions survive reboots and execute without user "
                f"interaction.",
                "WMI event subscriptions are a fileless persistence mechanism "
                "that executes code in response to system events (login, process "
                "start, timer). They are difficult to detect and survive reboots, "
                "making them a favorite for advanced threat actors.",
                "Remove unauthorized WMI event subscriptions using PowerShell: "
                "Get-WmiObject -Namespace root/subscription -Class "
                "__EventFilter | Remove-WmiObject. Investigate the subscription "
                "purpose before removal.",
                output=f"Filter: {filter_name}, Consumer: {consumer_name} "
                       f"({consumer_type}), Command: {command[:200]}",
                remediation_effort="Moderate",
                remediation_category="Configuration",
                mitre_attack=[{"technique": "T1546.003", "tactic": "Persistence",
                               "name": "Windows Management Instrumentation Event Subscription"}],
                nist_800_53=["SI-4", "CM-7"],
            )

    def _check_com_hijacking(self):
        hijacks = self._pers("com_hijacks", [])
        if not hijacks:
            return
        for h in hijacks:
            if not isinstance(h, dict):
                continue
            clsid = h.get("clsid", "Unknown")
            hkcu_path = h.get("hkcu_dll", "")
            hklm_path = h.get("hklm_dll", "")
            self._add_finding(
                "DR-PERS-002", "Persistence: COM Object Hijacking", "MEDIUM",
                f"COM object CLSID {clsid} has an HKCU InprocServer32 entry "
                f"({hkcu_path}) that overrides the system HKLM entry "
                f"({hklm_path}). This is a common persistence technique.",
                "COM hijacking allows an attacker to redirect legitimate COM "
                "object loading to a malicious DLL. The DLL executes in the "
                "context of any application that instantiates the hijacked COM "
                "object, often with elevated privileges.",
                f"Remove the HKCU COM override at HKCU\\SOFTWARE\\Classes\\CLSID\\"
                f"{clsid}\\InprocServer32. Investigate the DLL at '{hkcu_path}' "
                f"for malicious content.",
                output=f"CLSID: {clsid}, HKCU DLL: {hkcu_path}, "
                       f"HKLM DLL: {hklm_path}",
                remediation_effort="Easy",
                remediation_category="Configuration",
                mitre_attack=[{"technique": "T1546.015", "tactic": "Persistence",
                               "name": "Component Object Model Hijacking"}],
                nist_800_53=["SI-4"],
            )

    def _check_appinit_dlls(self):
        appinit = self._pers("appinit_dlls", {})
        if not appinit:
            return
        dll_value = appinit.get("value", "")
        load_enabled = appinit.get("load_appinit_dlls", 0)
        if not dll_value or not int(load_enabled):
            return
        self._add_finding(
            "DR-PERS-003", "Persistence: AppInit_DLLs Configured", "HIGH",
            f"AppInit_DLLs is configured with value '{dll_value}' and "
            f"LoadAppInit_DLLs is enabled. These DLLs are loaded into every "
            f"user-mode process that loads user32.dll.",
            "AppInit_DLLs provides code injection into virtually all GUI "
            "applications on the system. This is a powerful persistence and "
            "credential harvesting mechanism. It can intercept API calls, log "
            "keystrokes, and inject into security tools.",
            "Clear the AppInit_DLLs value and set LoadAppInit_DLLs to 0 in "
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows. "
            "Enable Secure Boot which disables AppInit_DLLs loading.",
            output=f"AppInit_DLLs: {dll_value}, LoadAppInit_DLLs: {load_enabled}",
            remediation_effort="Easy",
            remediation_category="Configuration",
            cwe=["CWE-427"],
            mitre_attack=[{"technique": "T1546.010", "tactic": "Persistence",
                           "name": "AppInit DLLs"}],
            nist_800_53=["SI-4", "CM-7"],
        )

    def _check_ifeo(self):
        ifeo_entries = self._pers("ifeo_debuggers", [])
        if not ifeo_entries:
            return
        for entry in ifeo_entries:
            if not isinstance(entry, dict):
                continue
            target = entry.get("target_exe", "Unknown")
            debugger = entry.get("debugger", "Unknown")
            self._add_finding(
                "DR-PERS-004",
                "Persistence: IFEO Debugger Set", "HIGH",
                f"IFEO debugger set for '{target}': the debugger '{debugger}' "
                f"will execute instead of (or before) the target binary. This "
                f"is a known persistence and defense evasion technique.",
                "IFEO debugger entries redirect process execution. An attacker "
                "can set a debugger for common utilities (cmd.exe, notepad.exe, "
                "sethc.exe) to execute malware whenever those programs are "
                "launched, or to block security tools from running.",
                f"Remove the Debugger value from "
                f"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                f"Image File Execution Options\\{target}. Investigate the "
                f"debugger binary '{debugger}' for malicious activity.",
                output=f"Target: {target}, Debugger: {debugger}",
                remediation_effort="Easy",
                remediation_category="Configuration",
                mitre_attack=[{"technique": "T1546.012", "tactic": "Persistence",
                               "name": "Image File Execution Options Injection"}],
                nist_800_53=["SI-4", "CM-7"],
            )

    def _check_accessibility_features(self):
        a11y = self._pers("accessibility_binaries", [])
        if not a11y:
            return
        modified = [b for b in a11y
                    if isinstance(b, dict) and b.get("modified")]
        if not modified:
            return
        for binary in modified:
            name = binary.get("name", "Unknown")
            mod_time = binary.get("last_modified", "")
            os_install = binary.get("os_install_date", "")
            self._add_finding(
                "DR-PERS-005",
                "Persistence: Accessibility Feature Modified", "CRITICAL",
                f"Accessibility binary '{name}' has a modification timestamp "
                f"({mod_time}) that differs from the OS installation date "
                f"({os_install}). This may indicate binary replacement for "
                f"pre-authentication backdoor access.",
                "Replacing accessibility binaries (sethc.exe, utilman.exe, "
                "osk.exe, narrator.exe, magnify.exe) allows an attacker to "
                "execute arbitrary commands at the Windows login screen by "
                "pressing Shift 5 times or launching Utility Manager. This "
                "provides SYSTEM-level access without authentication.",
                f"Restore '{name}' from a known-good backup or the Windows "
                f"installation media (sfc /scannow). Investigate the modified "
                f"binary. Enable Windows File Protection.",
                output=f"Binary: {name}, Modified: {mod_time}, "
                       f"OS Install: {os_install}",
                remediation_effort="Moderate",
                remediation_category="Configuration",
                cwe=["CWE-506"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                mitre_attack=[{"technique": "T1546.008", "tactic": "Persistence",
                               "name": "Accessibility Features"}],
                nist_800_53=["SI-7", "SI-4"],
            )

    def _check_print_monitors(self):
        monitors = self._pers("print_monitors", [])
        if not monitors:
            return
        default_monitors = {
            "appmon.dll", "localspl.dll", "tcpmon.dll", "usbmon.dll",
            "wsdmon.dll", "lprmon.dll", "apmonui.dll",
        }
        suspicious = [m for m in monitors
                      if isinstance(m, dict)
                      and m.get("dll", "").lower() not in default_monitors]
        if not suspicious:
            return
        for mon in suspicious:
            name = mon.get("name", "Unknown")
            dll = mon.get("dll", "Unknown")
            self._add_finding(
                "DR-PERS-006", "Persistence: Print Monitor DLL", "MEDIUM",
                f"Non-standard print monitor '{name}' registered with DLL "
                f"'{dll}'. Print monitor DLLs are loaded by the spooler "
                f"service (SYSTEM) at startup.",
                "Print monitor DLLs run as SYSTEM and are loaded automatically "
                "by the Print Spooler service. An attacker can register a "
                "malicious DLL as a print monitor to achieve persistence with "
                "SYSTEM privileges.",
                f"Verify the legitimacy of print monitor '{name}' and DLL "
                f"'{dll}'. Remove unauthorized monitors from "
                f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors.",
                output=f"Monitor: {name}, DLL: {dll}",
                remediation_effort="Easy",
                remediation_category="Configuration",
                mitre_attack=[{"technique": "T1547.010", "tactic": "Persistence",
                               "name": "Port Monitors"}],
                nist_800_53=["SI-4", "CM-7"],
            )

    def _check_sysmon(self):
        services = self._get_section("services", [])
        sysmon_found = False
        if isinstance(services, list):
            for svc in services:
                if isinstance(svc, dict):
                    name = svc.get("name", "").lower()
                    if name in ("sysmon", "sysmon64", "sysmondrv"):
                        sysmon_found = True
                        break
        if not sysmon_found:
            sysmon_info = self._pers("sysmon", {})
            if isinstance(sysmon_info, dict) and sysmon_info.get("installed"):
                sysmon_found = True
        if not sysmon_found:
            self._add_finding(
                "DR-SYS-011", "Monitoring: Sysmon Not Installed", "MEDIUM",
                "Sysmon (System Monitor) is not installed on this system. Sysmon "
                "provides detailed event logging for process creation, network "
                "connections, file changes, and registry modifications.",
                "Without Sysmon, critical telemetry for detecting adversary activity "
                "is missing. Process creation events with command lines, network "
                "connection logging, and driver/DLL loading events are essential for "
                "threat hunting and incident response.",
                "Install Sysmon from Microsoft Sysinternals with a comprehensive "
                "configuration (e.g., SwiftOnSecurity/sysmon-config or "
                "olafhartong/sysmon-modular). Configure log forwarding to a SIEM.",
                remediation_effort="Moderate",
                remediation_category="Monitoring",
                mitre_attack=[{"technique": "T1562.001", "tactic": "Defense Evasion",
                               "name": "Disable or Modify Tools"}],
                nist_800_53=["SI-4", "AU-12"],
                nist_csf2=["DE.CM-1"],
            )
            return

        sysmon_info = self._pers("sysmon", {})
        if not isinstance(sysmon_info, dict):
            return
        config_lines = sysmon_info.get("config")
        if not config_lines or not isinstance(config_lines, list):
            return
        config_text = "\n".join(str(line) for line in config_lines).lower()
        if not config_text.strip():
            return
        _CRITICAL_EVENTS = {
            "processcreate": "ProcessCreate (Event 1)",
            "networkconnect": "NetworkConnect (Event 3)",
            "createremotethread": "CreateRemoteThread (Event 8)",
            "processaccess": "ProcessAccess (Event 10)",
            "filecreate": "FileCreate (Event 11)",
            "registryevent": "RegistryEvent (Events 12/13/14)",
        }
        missing = []
        for keyword, label in _CRITICAL_EVENTS.items():
            if keyword not in config_text:
                missing.append(label)
        if len(missing) >= 3:
            self._add_finding(
                "DR-SYS-014",
                "Monitoring: Sysmon Configuration Incomplete",
                "MEDIUM",
                f"Sysmon is installed but {len(missing)} critical event "
                f"categories are not present in the active configuration.",
                "Sysmon is installed but not logging critical event categories "
                "needed for threat detection. Missing categories mean gaps in "
                "visibility for process creation, network connections, remote "
                "thread injection, or registry modifications — core telemetry "
                "for detecting adversary tradecraft.",
                "Update the Sysmon configuration to include all critical event "
                "types. Use a comprehensive config like SwiftOnSecurity/"
                "sysmon-config or olafhartong/sysmon-modular as a baseline. "
                "Deploy with: sysmon -c <config.xml>.",
                output="Missing event types:\n" + "\n".join(missing),
                remediation_effort="Easy",
                remediation_category="Monitoring",
                mitre_attack=[{"technique": "T1562.001", "tactic": "Defense Evasion",
                               "name": "Disable or Modify Tools"}],
                nist_800_53=["SI-4", "AU-12"],
                nist_csf2=["DE.CM-1"],
            )

    def _check_lsa_packages(self):
        lsa = self._pers("lsa_packages", {})
        if not lsa:
            return
        default_auth = {"msv1_0", "kerberos", "negotiate", "schannel",
                        "wdigest", "tspkg", "pku2u", "cloudap"}
        default_notify = {"scecli", "rassfm"}
        default_security = {"", "kerberos", "msv1_0", "negotiate",
                            "schannel", "wdigest", "tspkg", "pku2u"}
        auth_packages = lsa.get("authentication_packages", [])
        notify_packages = lsa.get("notification_packages", [])
        security_packages = lsa.get("security_packages", [])
        suspicious = []
        for pkg in auth_packages:
            p = pkg.lower().strip() if isinstance(pkg, str) else str(pkg).lower()
            if p and p not in default_auth:
                suspicious.append(f"Auth: {pkg}")
        for pkg in notify_packages:
            p = pkg.lower().strip() if isinstance(pkg, str) else str(pkg).lower()
            if p and p not in default_notify:
                suspicious.append(f"Notify: {pkg}")
        for pkg in security_packages:
            p = pkg.lower().strip() if isinstance(pkg, str) else str(pkg).lower()
            if p and p not in default_security:
                suspicious.append(f"Security: {pkg}")
        if not suspicious:
            return
        pkg_list = ", ".join(suspicious[:10])
        self._add_finding(
            "DR-PERS-008",
            "Persistence: LSA Authentication Package Modified", "HIGH",
            f"Non-default LSA package(s) detected: {pkg_list}. Custom LSA "
            f"packages can intercept all authentication events on the system.",
            "LSA authentication and notification packages are loaded by lsass.exe "
            "at boot time. A malicious package can capture all credentials as "
            "they are processed (plaintext passwords, NTLM hashes, Kerberos "
            "tickets). This is the mechanism used by tools like mimilib.dll.",
            "Audit LSA packages in "
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa. Remove any "
            "unauthorized packages. Enable LSA Protection (RunAsPPL) and "
            "Credential Guard to prevent unauthorized DLL loading.",
            output=f"Non-default packages: {pkg_list}",
            remediation_effort="Moderate",
            remediation_category="Configuration",
            cwe=["CWE-506"],
            mitre_attack=[{"technique": "T1547.002", "tactic": "Persistence",
                           "name": "Authentication Package"},
                          {"technique": "T1556.002", "tactic": "Credential Access",
                           "name": "Password Filter DLL"}],
            nist_800_53=["SI-4", "SI-7"],
        )

    # ------------------------------------------------------------------ #
    # DR-PERS-009  Suspicious Scheduled Tasks
    # ------------------------------------------------------------------ #
    def _check_scheduled_tasks(self):
        tasks = self._get_section("scheduled_tasks", [])
        if not isinstance(tasks, list) or not tasks:
            return
        count = 0
        for task in tasks:
            if not isinstance(task, dict):
                continue
            if count >= 10:
                break
            task_name = task.get("task_name", "Unknown")
            task_path = task.get("task_path", "")
            principal = task.get("principal_user", "")
            run_level = task.get("run_level", "")
            actions = task.get("actions", [])
            if not isinstance(actions, list):
                continue
            is_system = principal and principal.lower() in (
                "system", "nt authority\\system", "local system",
                "s-1-5-18")
            for action in actions:
                if not isinstance(action, dict):
                    continue
                exe = str(action.get("execute", "")).strip()
                args = str(action.get("arguments", "")).strip()
                exe_lower = exe.lower().replace("\\", "/").rsplit("/", 1)[-1]
                suspicious = False
                reason = ""
                if exe_lower in _LOLBIN_EXECUTABLES:
                    if _SUSPICIOUS_ARG_PATTERNS.search(args):
                        suspicious = True
                        reason = "LOLBin with suspicious arguments"
                if not suspicious and _USER_WRITABLE_PATHS_RE.search(exe):
                    suspicious = True
                    reason = "Executable in user-writable path"
                if not suspicious and is_system and task_path:
                    if not task_path.startswith("\\Microsoft\\Windows\\"):
                        if exe_lower in _LOLBIN_EXECUTABLES or _USER_WRITABLE_PATHS_RE.search(exe):
                            suspicious = True
                            reason = "SYSTEM task outside \\Microsoft\\Windows\\"
                        elif exe and not exe.lower().startswith(("c:\\windows\\", "%systemroot%")):
                            suspicious = True
                            reason = "SYSTEM task with non-system executable"
                if not suspicious:
                    continue
                risk = "HIGH" if is_system else "MEDIUM"
                args_display = args[:200] + "..." if len(args) > 200 else args
                self._add_finding(
                    "DR-PERS-009",
                    "Persistence: Suspicious Scheduled Task Detected",
                    risk,
                    f"Scheduled task '{task_name}' at '{task_path}' has a "
                    f"suspicious configuration: {reason}.",
                    "Scheduled tasks are a common persistence mechanism. "
                    "Attackers create tasks that execute via LOLBins "
                    "(powershell, cmd, mshta, rundll32) with encoded commands, "
                    "download cradles, or executables in user-writable paths. "
                    "Tasks running as SYSTEM provide the highest privilege level.",
                    f"Investigate task '{task_name}' and its action. If "
                    f"unauthorized, remove with: Unregister-ScheduledTask "
                    f"-TaskName '{task_name}' -Confirm:$false. Review all "
                    f"non-Microsoft scheduled tasks regularly.",
                    output=f"Task: {task_name}\nPath: {task_path}\n"
                           f"Execute: {exe}\nArguments: {args_display}\n"
                           f"Principal: {principal}\nRun level: {run_level}\n"
                           f"Reason: {reason}",
                    remediation_effort="Easy",
                    remediation_category="Configuration",
                    mitre_attack=[{"technique": "T1053.005", "tactic": "Persistence",
                                   "name": "Scheduled Task"}],
                    nist_800_53=["SI-4", "CM-7"],
                )
                count += 1
                break
