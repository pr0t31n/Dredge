import re
from analyzers.base import BaseAnalyzer

_TEMP_PATTERNS = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\local\\temp\\",
    r"\\windows\\temp\\",
    r"%temp%",
    r"%tmp%",
    r"/tmp/",
    r"/var/tmp/",
]
_TEMP_RE = re.compile("|".join(_TEMP_PATTERNS), re.IGNORECASE)

_USER_WRITABLE_PATHS = [
    r"\\users\\",
    r"\\appdata\\",
    r"\\downloads\\",
    r"\\desktop\\",
    r"\\documents\\",
    r"\\public\\",
    r"\\programdata\\",
    r"\\temp\\",
    r"\\tmp\\",
    r"c:\\temp\\",
    r"c:\\tmp\\",
]
_USER_WRITABLE_RE = re.compile("|".join(_USER_WRITABLE_PATHS), re.IGNORECASE)

_SYSTEM_USERS = {"nt authority\\system", "system", "local system",
                 "nt authority\\local service", "nt authority\\network service"}


class ProcessAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_malicious_processes()
        self._check_temp_processes()
        self._check_no_path_processes()
        self._check_system_from_user_path()
        return self.findings

    # ------------------------------------------------------------------ #
    # DR-PROC-001  Known malicious process detected
    # ------------------------------------------------------------------ #
    def _check_malicious_processes(self):
        if not self.ti:
            return
        procs = self._get_section("processes", [])
        if not isinstance(procs, list):
            return
        malicious = []
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            name = proc.get("name", proc.get("process_name", ""))
            path = proc.get("path", proc.get("executable_path", ""))
            check_val = path if path else name
            if not check_val:
                continue
            if self.ti.is_known_bad_process(check_val):
                info = self.ti.get_bad_process_info(check_val)
                pid = proc.get("pid", proc.get("process_id", "?"))
                user = proc.get("user", proc.get("username", "?"))
                threat_type = info.get("type", "unknown") if info else "unknown"
                description = info.get("description", "") if info else ""
                malicious.append({
                    "name": name,
                    "path": path,
                    "pid": pid,
                    "user": user,
                    "type": threat_type,
                    "desc": description,
                })
        if not malicious:
            return
        output_lines = []
        for m in malicious[:15]:
            line = f"PID {m['pid']}: {m['name']}"
            if m["path"]:
                line += f" ({m['path']})"
            line += f" [User: {m['user']}, Threat: {m['type']}]"
            if m["desc"]:
                line += f"\n  -> {m['desc']}"
            output_lines.append(line)
        output = "\n".join(output_lines)
        self._add_finding(
            "DR-PROC-001",
            "Process: Known Malicious Process Detected",
            "CRITICAL",
            f"{len(malicious)} running process(es) match known malicious "
            f"software signatures in the threat intelligence database. This "
            f"is a strong indicator of active system compromise.",
            "Known malicious processes indicate active malware execution. "
            "Depending on the malware type (RAT, keylogger, cryptominer, "
            "ransomware dropper), the attacker may have full remote access, "
            "be exfiltrating data, or preparing for destructive action. "
            "The system should be considered compromised.",
            "Immediately isolate the system from the network. Capture memory "
            "and disk images for forensic analysis before remediation. "
            "Identify the malware family and check for persistence mechanisms "
            "(scheduled tasks, services, registry run keys, WMI subscriptions). "
            "Re-image the system after forensics are complete. Do not simply "
            "kill the process — the malware likely has persistence.",
            output=output,
            remediation_effort="Major",
            cwe=["CWE-506"],
            mitre_attack=[
                {"technique": "T1059", "tactic": "Execution",
                 "name": "Command and Scripting Interpreter"},
                {"technique": "T1543", "tactic": "Persistence",
                 "name": "Create or Modify System Process"},
            ],
            nist_800_53=["SI-3", "IR-4"],
        )

    # ------------------------------------------------------------------ #
    # DR-PROC-002  Process running from temp directory
    # ------------------------------------------------------------------ #
    def _check_temp_processes(self):
        procs = self._get_section("processes", [])
        if not isinstance(procs, list):
            return
        temp_procs = []
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            path = proc.get("path", proc.get("executable_path", ""))
            if not path:
                continue
            if _TEMP_RE.search(path):
                name = proc.get("name", proc.get("process_name", ""))
                pid = proc.get("pid", proc.get("process_id", "?"))
                user = proc.get("user", proc.get("username", "?"))
                temp_procs.append(f"PID {pid}: {name} ({path}) [User: {user}]")
        if not temp_procs:
            return
        output = "\n".join(temp_procs[:15])
        self._add_finding(
            "DR-PROC-002",
            "Process: Running from Temporary Directory",
            "HIGH",
            f"{len(temp_procs)} process(es) are executing from temporary "
            f"directories. Legitimate software rarely runs from temp folders; "
            f"this pattern is a strong indicator of malware, dropper activity, "
            f"or exploitation payload execution.",
            "Malware commonly stages and executes from temporary directories "
            "because they are user-writable, loosely monitored, and files "
            "there are expected to be transient. Ransomware droppers, "
            "fileless malware stagers, and post-exploitation payloads "
            "frequently use %TEMP%, %TMP%, or C:\\Windows\\Temp as their "
            "execution path.",
            "Investigate each process: check file hash against VirusTotal, "
            "examine parent process chain, check for associated network "
            "connections. Implement AppLocker or WDAC policies to block "
            "executable execution from temp directories. Enable Windows "
            "Defender ASR rule 'Block executable content from email client "
            "and webmail'.",
            output=output,
            remediation_effort="Moderate",
            cwe=["CWE-427"],
            mitre_attack=[
                {"technique": "T1204", "tactic": "Execution",
                 "name": "User Execution"},
                {"technique": "T1036.005", "tactic": "Defense Evasion",
                 "name": "Match Legitimate Name or Location"},
            ],
            nist_800_53=["CM-7", "SI-3"],
        )

    # ------------------------------------------------------------------ #
    # DR-PROC-003  Process with no executable path
    # ------------------------------------------------------------------ #
    def _check_no_path_processes(self):
        procs = self._get_section("processes", [])
        if not isinstance(procs, list):
            return
        _KNOWN_PATHLESS = {"system", "idle", "system idle process",
                           "registry", "memory compression",
                           "secure system", "smss.exe", "[system process]"}
        no_path = []
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            path = proc.get("path", proc.get("executable_path", ""))
            name = proc.get("name", proc.get("process_name", ""))
            if path:
                continue
            if name.lower().rstrip(".exe") in _KNOWN_PATHLESS:
                continue
            if name.lower() in _KNOWN_PATHLESS:
                continue
            pid = proc.get("pid", proc.get("process_id", "?"))
            user = proc.get("user", proc.get("username", "?"))
            ppid = proc.get("parent_pid", proc.get("ppid", "?"))
            no_path.append(f"PID {pid}: {name} [User: {user}, PPID: {ppid}]")
        if not no_path:
            return
        output = "\n".join(no_path[:15])
        self._add_finding(
            "DR-PROC-003",
            "Process: No Executable Path",
            "MEDIUM",
            f"{len(no_path)} running process(es) have no associated executable "
            f"path on disk. This may indicate fileless malware, process "
            f"hollowing, or a process whose binary was deleted after execution.",
            "Processes without a disk-backed executable path can indicate "
            "fileless malware executing entirely from memory, process "
            "hollowing (where a legitimate process is replaced in memory "
            "with malicious code), or an attacker who deleted the binary "
            "after launching it to hinder forensic analysis.",
            "Investigate each process: capture a memory dump for forensic "
            "analysis, check the parent process chain for suspicious "
            "lineage (e.g., cmd.exe spawned by Word), examine loaded DLLs "
            "and handles. Implement Sysmon with process creation logging "
            "(Event ID 1) to capture full command lines and parent process "
            "details.",
            output=output,
            remediation_effort="Moderate",
            cwe=["CWE-506"],
            mitre_attack=[
                {"technique": "T1055", "tactic": "Defense Evasion",
                 "name": "Process Injection"},
                {"technique": "T1620", "tactic": "Defense Evasion",
                 "name": "Reflective Code Loading"},
            ],
            nist_800_53=["SI-3", "SI-4"],
        )

    # ------------------------------------------------------------------ #
    # DR-PROC-004  Process running as SYSTEM from user-writable path
    # ------------------------------------------------------------------ #
    def _check_system_from_user_path(self):
        procs = self._get_section("processes", [])
        if not isinstance(procs, list):
            return
        suspicious = []
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            user = str(proc.get("user", proc.get("username", ""))).lower()
            if user not in _SYSTEM_USERS:
                continue
            path = proc.get("path", proc.get("executable_path", ""))
            if not path:
                continue
            if _USER_WRITABLE_RE.search(path):
                name = proc.get("name", proc.get("process_name", ""))
                pid = proc.get("pid", proc.get("process_id", "?"))
                suspicious.append(
                    f"PID {pid}: {name} ({path}) [Running as: {user}]")
        if not suspicious:
            return
        output = "\n".join(suspicious[:15])
        self._add_finding(
            "DR-PROC-004",
            "Process: SYSTEM Process in User-Writable Path",
            "CRITICAL",
            f"{len(suspicious)} process(es) are running as SYSTEM from "
            f"user-writable locations. Legitimate SYSTEM processes run from "
            f"protected directories (System32, Program Files). A SYSTEM "
            f"process in a user-writable path is a strong indicator of "
            f"privilege escalation or malware with elevated privileges.",
            "A process running as SYSTEM from a user-writable directory "
            "indicates successful privilege escalation. The attacker has "
            "achieved the highest local privilege level and can: install "
            "rootkits, create backdoor accounts, modify security settings, "
            "access any file on the system, pivot to other systems using "
            "machine account credentials, and tamper with security logs.",
            "Immediately investigate: capture memory and disk forensics, "
            "identify the privilege escalation vector (service binary "
            "hijacking, DLL search order hijacking, unquoted service path, "
            "etc.). Fix the underlying vulnerability. Deploy WDAC/AppLocker "
            "to prevent execution from user-writable paths. Audit service "
            "binaries for insecure permissions.",
            output=output,
            remediation_effort="Significant",
            cwe=["CWE-269", "CWE-427"],
            mitre_attack=[
                {"technique": "T1574.001", "tactic": "Privilege Escalation",
                 "name": "DLL Search Order Hijacking"},
                {"technique": "T1574.010", "tactic": "Persistence",
                 "name": "Services File Permissions Weakness"},
            ],
            nist_800_53=["CM-5", "AC-6"],
        )
