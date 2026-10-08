from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from analyzers.base import BaseAnalyzer

_SUSPICIOUS_PS_KEYWORDS = [
    "invoke-expression", "iex(", "iex ", "downloadstring", "downloadfile",
    "downloaddata", "webclient", "invoke-webrequest", "start-bitstransfer",
    "net.webclient", "invoke-mimikatz", "invoke-shellcode",
    "invoke-reflectivepeinjection", "invoke-powershelltcp",
    "-encodedcommand", "-enc ", "-e ", "frombase64string",
    "convertto-securestring", "invoke-command", "enter-pssession",
    "new-psdrive", "invoke-wmimethod", "invoke-cimmethod",
    "set-mppreference -disablerealtimemonitoring",
    "add-mppreference -exclusionpath",
    "bypass", "hidden", "-nop", "-noni", "-windowstyle hidden",
    "amsiutils", "amsiinitfailed", "reflection.assembly",
]

_PS_FP_KEYWORDS = [
    "update-help", "get-help", "get-command", "write-host",
    "write-output", "set-executionpolicy",
]


class EventLogAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_brute_force()
        self._check_account_lockouts()
        self._check_log_cleared()
        self._check_suspicious_powershell()
        self._check_new_services()
        self._check_user_created()
        return self.findings

    def _check_brute_force(self):
        events = self._get_section("event_logs", {})
        security = events.get("security", [])
        if not isinstance(security, list):
            return

        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)
        source_failures = defaultdict(int)

        for entry in security:
            if not isinstance(entry, dict):
                continue
            event_id = entry.get("event_id")
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                continue
            if event_id not in (4625, 529, 530, 531, 532, 533, 534, 535, 536, 537, 539):
                continue

            ts = entry.get("time", "")
            if ts:
                try:
                    event_time = datetime.fromisoformat(
                        ts.replace("Z", "+00:00"))
                    if event_time < seven_days_ago:
                        continue
                except (ValueError, TypeError):
                    pass

            source = entry.get("source_ip", "") or entry.get(
                "workstation", "") or entry.get("source", "unknown")
            source_failures[source] += 1

        brute_sources = {src: cnt for src, cnt in source_failures.items()
                         if cnt > 10}
        if brute_sources:
            top = sorted(brute_sources.items(), key=lambda x: -x[1])[:10]
            output_lines = [f"{src}: {cnt} failures" for src, cnt in top]
            total = sum(brute_sources.values())
            self._add_finding(
                "DR-EVT-001",
                "Brute Force Attack Detected",
                "HIGH",
                f"Brute-force login activity detected from {len(brute_sources)} "
                f"source(s) with a total of {total} failed authentication attempts "
                f"in the past 7 days. Sources with more than 10 failures indicate "
                f"automated credential guessing.",
                "Sustained brute-force attacks may eventually succeed, especially "
                "against accounts with weak or reused passwords. Successful "
                "compromise grants the attacker interactive access to the system.",
                "Implement account lockout policies, enable multi-factor "
                "authentication, and block offending source IPs at the firewall. "
                "Investigate targeted accounts for compromise indicators.",
                output="\n".join(output_lines),
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1110", "tactic": "Credential Access",
                               "name": "Brute Force"}],
                nist_800_53=["AC-7", "SI-4"],
            )

    def _check_account_lockouts(self):
        events = self._get_section("event_logs", {})
        security = events.get("security", [])
        if not isinstance(security, list):
            return

        lockouts = []
        for entry in security:
            if not isinstance(entry, dict):
                continue
            event_id = entry.get("event_id")
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                continue
            if event_id in (4740, 644):
                account = entry.get("target_account", "") or entry.get(
                    "account", "unknown")
                lockouts.append(account)

        if lockouts:
            account_counts = Counter(lockouts)
            top = account_counts.most_common(10)
            output_lines = [f"{acct}: {cnt} lockout(s)" for acct, cnt in top]
            self._add_finding(
                "DR-EVT-002",
                "Account Lockouts Detected",
                "MEDIUM",
                f"{len(lockouts)} account lockout event(s) detected across "
                f"{len(account_counts)} account(s). Repeated lockouts may indicate "
                f"brute-force attacks or misconfigured service accounts.",
                "Account lockouts from brute-force attempts confirm active credential "
                "attacks. Service account lockouts can cause application outages.",
                "Investigate the source of lockouts. For user accounts, verify no "
                "credential compromise occurred. For service accounts, check for "
                "stale cached credentials in scheduled tasks, services, or mapped "
                "drives.",
                output="\n".join(output_lines),
                remediation_effort="Moderate",
                nist_800_53=["AC-7", "SI-4"],
            )

    def _check_log_cleared(self):
        events = self._get_section("event_logs", {})
        security = events.get("security", [])
        system = events.get("system", [])
        all_events = []
        if isinstance(security, list):
            all_events.extend(security)
        if isinstance(system, list):
            all_events.extend(system)

        cleared = []
        for entry in all_events:
            if not isinstance(entry, dict):
                continue
            event_id = entry.get("event_id")
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                continue
            if event_id in (1102, 104, 517):
                user = entry.get("user", "") or entry.get(
                    "account", "unknown")
                ts = entry.get("time", "unknown")
                log_name = entry.get("log_name", "Security")
                cleared.append(f"{log_name} log cleared by {user} at {ts}")

        if cleared:
            output = "\n".join(cleared[:10])
            self._add_finding(
                "DR-EVT-003",
                "Security Log Cleared — Evidence Tampering",
                "CRITICAL",
                f"{len(cleared)} event log clearing event(s) detected. Clearing "
                f"security logs destroys forensic evidence and is a strong indicator "
                f"of attacker activity or insider threat.",
                "Cleared security logs eliminate the audit trail of authentication "
                "events, privilege escalation, and policy changes, preventing "
                "incident investigation and regulatory compliance verification.",
                "Investigate the account that cleared the logs for compromise. "
                "Configure event log forwarding to a SIEM to preserve logs "
                "centrally. Restrict log management permissions to dedicated "
                "admin accounts. Enable 'Audit Other Object Access Events' GPO.",
                output=output,
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1070.001", "tactic": "Defense Evasion",
                               "name": "Clear Windows Event Logs"}],
                nist_800_53=["AU-9", "SI-4"],
            )

    def _check_suspicious_powershell(self):
        events = self._get_section("event_logs", {})
        ps_events = events.get("powershell", [])
        if not isinstance(ps_events, list):
            ps_events = []

        ps_operational = events.get("powershell_operational", [])
        if isinstance(ps_operational, list):
            ps_events.extend(ps_operational)

        suspicious = []
        for entry in ps_events:
            if not isinstance(entry, dict):
                continue
            script_block = entry.get("script_block", "") or entry.get(
                "command", "") or entry.get("message", "")
            if not script_block:
                continue
            script_lower = script_block.lower()

            if any(fp in script_lower for fp in _PS_FP_KEYWORDS):
                continue

            for keyword in _SUSPICIOUS_PS_KEYWORDS:
                if keyword in script_lower:
                    ts = entry.get("time", "unknown")
                    user = entry.get("user", "unknown")
                    snippet = script_block[:200].replace("\n", " ")
                    suspicious.append(f"[{ts}] {user}: {snippet}")
                    break

        if suspicious:
            output = "\n".join(suspicious[:10])
            if len(suspicious) > 10:
                output += f"\n... and {len(suspicious) - 10} more"
            self._add_finding(
                "DR-EVT-004",
                "Suspicious PowerShell Activity in Event Logs",
                "HIGH",
                f"{len(suspicious)} PowerShell event(s) contain suspicious patterns "
                f"such as encoded commands, download cradles, AMSI bypass attempts, "
                f"or known offensive tool invocations.",
                "Suspicious PowerShell activity may indicate post-exploitation "
                "activity, malware execution, or attacker reconnaissance. PowerShell "
                "is the most commonly abused living-off-the-land tool on Windows.",
                "Investigate each suspicious PowerShell event. Check the executing "
                "user and originating process. Enable PowerShell ScriptBlock Logging, "
                "Transcription, and Constrained Language Mode. Consider deploying "
                "AppLocker or WDAC to restrict PowerShell usage.",
                output=output,
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1059.001", "tactic": "Execution",
                               "name": "PowerShell"}],
                nist_800_53=["SI-4", "AU-12"],
            )

    def _check_new_services(self):
        events = self._get_section("event_logs", {})
        system = events.get("system", [])
        if not isinstance(system, list):
            return

        new_services = []
        for entry in system:
            if not isinstance(entry, dict):
                continue
            event_id = entry.get("event_id")
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                continue
            if event_id in (7045, 4697):
                svc_name = entry.get("service_name", "") or entry.get(
                    "name", "unknown")
                svc_path = entry.get("image_path", "") or entry.get(
                    "path", "unknown")
                ts = entry.get("time", "unknown")
                account = entry.get("account", "") or entry.get(
                    "user", "unknown")
                new_services.append(
                    f"[{ts}] {svc_name} -> {svc_path} (account: {account})")

        if new_services:
            output = "\n".join(new_services[:15])
            risk = "MEDIUM" if len(new_services) <= 3 else "HIGH"
            self._add_finding(
                "DR-EVT-005",
                "New Service Installations Detected",
                risk,
                f"{len(new_services)} new service installation(s) recorded in event "
                f"logs. Service installations are a common persistence mechanism "
                f"used by malware and attackers.",
                "Attackers install malicious services to maintain persistent access "
                "that survives reboots. Services run with elevated privileges and "
                "can be configured to start automatically.",
                "Review each new service installation for legitimacy. Verify the "
                "service executable path, signing status, and the account used for "
                "installation. Remove unauthorized services.",
                output=output,
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1543.003", "tactic": "Persistence",
                               "name": "Windows Service"}],
                nist_800_53=["SI-4", "CM-3"],
            )

    def _check_user_created(self):
        events = self._get_section("event_logs", {})
        security = events.get("security", [])
        if not isinstance(security, list):
            return

        created_users = []
        for entry in security:
            if not isinstance(entry, dict):
                continue
            event_id = entry.get("event_id")
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                continue
            if event_id in (4720, 624):
                new_account = entry.get("target_account", "") or entry.get(
                    "new_account", "unknown")
                created_by = entry.get("subject_account", "") or entry.get(
                    "user", "unknown")
                ts = entry.get("time", "unknown")
                created_users.append(
                    f"[{ts}] '{new_account}' created by '{created_by}'")

        if created_users:
            output = "\n".join(created_users[:10])
            self._add_finding(
                "DR-EVT-006",
                "User Account Created",
                "MEDIUM",
                f"{len(created_users)} user account creation event(s) detected in "
                f"security event logs. Account creation outside of normal provisioning "
                f"workflows may indicate persistence or unauthorized access.",
                "Attackers create local accounts to maintain persistent access. "
                "Unauthorized accounts may be added to privileged groups to escalate "
                "privileges.",
                "Verify each account creation was authorized through the proper "
                "provisioning workflow. Remove unauthorized accounts. Monitor for "
                "group membership changes (Event ID 4732) on newly created accounts.",
                output=output,
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1136.001", "tactic": "Persistence",
                               "name": "Local Account"}],
                nist_800_53=["AC-2", "SI-4"],
            )
