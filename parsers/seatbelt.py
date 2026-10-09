import uuid
import datetime
import json
import os

_DANGEROUS_PRIVS = {
    "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
    "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege",
}


class SeatbeltParser:
    def __init__(self, file_path, hostname="", ip=""):
        self.file_path = file_path
        self.hostname = hostname
        self.ip = ip
        self.findings = []

    def _add_finding(self, catalogue_id, title, risk, description, impact,
                     remediation, **kwargs):
        finding = {
            "id": str(uuid.uuid4()),
            "tool": "dredge",
            "catalogue_id": catalogue_id,
            "title": title,
            "datetime": datetime.datetime.now().isoformat(),
            "ip": self.ip,
            "port": kwargs.get("port", 0),
            "hostname": self.hostname,
            "risk": risk,
            "command": kwargs.get("command", ""),
            "description": description,
            "impact": impact,
            "sources": kwargs.get("sources", "dredge"),
            "affected": kwargs.get("affected", self.hostname or self.ip),
            "remediation": remediation,
            "exploitdb": kwargs.get("exploitdb", False),
            "metasploit": kwargs.get("metasploit", False),
            "exploit_details": kwargs.get("exploit_details", []),
            "scope": kwargs.get("scope", "endpoint"),
            "output": kwargs.get("output", ""),
            "output_file": kwargs.get("output_file", ""),
            "cves": kwargs.get("cves", ""),
            "service": kwargs.get("service", ""),
            "owasp": kwargs.get("owasp", ""),
            "nist": kwargs.get("nist", ""),
            "cwe": kwargs.get("cwe", []),
            "cvss_score": kwargs.get("cvss_score", None),
            "cvss_vector": kwargs.get("cvss_vector", ""),
            "confidence": kwargs.get("confidence", "Certain"),
            "remediation_effort": kwargs.get("remediation_effort", ""),
            "remediation_component": kwargs.get("remediation_component", ""),
            "remediation_category": kwargs.get("remediation_category", ""),
            "mitre_attack": kwargs.get("mitre_attack", []),
            "nist_800_53": kwargs.get("nist_800_53", []),
            "nist_csf2": kwargs.get("nist_csf2", []),
            "pci_dss_4": kwargs.get("pci_dss_4", []),
        }
        self.findings.append(finding)

    def parse(self):
        if not os.path.isfile(self.file_path):
            return self.findings
        try:
            with open(self.file_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return self.findings

        if not isinstance(data, list):
            return self.findings

        commands = {}
        for entry in data:
            cmd = entry.get("Command", "")
            results = entry.get("Data", entry.get("Results", []))
            if cmd:
                commands[cmd] = results

        self._parse_cred_enum(commands.get("CredEnum", []))
        self._parse_windows_vault(commands.get("WindowsVault", []))
        self._parse_putty(commands.get("PuttySessions", []),
                          commands.get("PuttyHostKeys", []))
        self._parse_rdp_saved(commands.get("RDPSavedConnections", []))
        self._parse_interesting_files(commands.get("InterestingFiles", []))
        self._parse_token_privs(commands.get("TokenPrivileges", []))
        self._parse_wmi_persistence(
            commands.get("WMIEventFilter", []),
            commands.get("WMIEventConsumer", []),
            commands.get("WMIEventSubscription", []))
        self._parse_uac(commands.get("UACSystemPolicies", []))
        self._parse_security_packages(commands.get("SecurityPackages", []))
        self._parse_amsi(commands.get("AMSIProviders", []))
        self._parse_applocker(commands.get("AppLocker", []))
        self._parse_sysmon(commands.get("Sysmon", []))
        self._parse_defender(commands.get("WindowsDefender", []))
        self._parse_lsa(commands.get("LSASettings", []))
        self._parse_ps_events(commands.get("PowerShellEvents", []))
        self._parse_dotnet(commands.get("DotNet", []))
        self._parse_firewall(commands.get("FirewallRules", []))
        self._parse_autoruns(commands.get("AutoRuns", []))

        return self.findings

    # ── CredEnum ────────────────────────────────────────────────────────
    def _parse_cred_enum(self, results):
        if not results:
            return
        cred_list = []
        for r in results:
            target = r.get("Target", r.get("Resource", ""))
            if target:
                cred_list.append(target)
        if cred_list:
            self._add_finding(
                "DR-CRED-006",
                "Stored Credentials in Credential Manager",
                "MEDIUM",
                f"{len(cred_list)} credential(s) found in Windows Credential Manager.",
                "Stored credentials can be extracted by an attacker with local "
                "access, providing lateral movement or privilege escalation paths.",
                "Review stored credentials and remove unnecessary entries. Use "
                "managed service accounts where possible.",
                output="\n".join(cred_list[:20]),
            )

    # ── WindowsVault ────────────────────────────────────────────────────
    def _parse_windows_vault(self, results):
        if not results:
            return
        entries = []
        for r in results:
            resource = r.get("Resource", r.get("Identity", ""))
            if resource:
                entries.append(resource)
        if entries:
            self._add_finding(
                "DR-CRED-006",
                "Windows Vault Credentials Found",
                "MEDIUM",
                f"{len(entries)} credential(s) stored in Windows Vault.",
                "Windows Vault credentials can be extracted by attackers with "
                "local access for credential theft and lateral movement.",
                "Audit Windows Vault entries and remove unnecessary stored credentials.",
                output="\n".join(entries[:20]),
            )

    # ── PuTTY ───────────────────────────────────────────────────────────
    def _parse_putty(self, sessions, hostkeys):
        items = []
        for s in sessions:
            name = s.get("SessionName", s.get("Name", ""))
            if name:
                items.append(f"Session: {name}")
        for h in hostkeys:
            host = h.get("Host", h.get("Key", ""))
            if host:
                items.append(f"HostKey: {host}")
        if items:
            self._add_finding(
                "DR-CRED-002",
                "Saved PuTTY Sessions Found",
                "LOW",
                f"{len(items)} PuTTY session(s)/host key(s) found in the registry.",
                "Saved PuTTY sessions may contain stored credentials or reveal "
                "infrastructure the host connects to.",
                "Remove unnecessary saved sessions. Use SSH key authentication "
                "with passphrase protection instead of stored passwords.",
                output="\n".join(items[:20]),
            )

    # ── RDP Saved ───────────────────────────────────────────────────────
    def _parse_rdp_saved(self, results):
        if not results:
            return
        hosts = []
        for r in results:
            host = r.get("Host", r.get("Server", ""))
            if host:
                hosts.append(host)
        if hosts:
            self._add_finding(
                "DR-CRED-002",
                "Saved RDP Connections Found",
                "LOW",
                f"{len(hosts)} saved RDP connection(s) found.",
                "Saved RDP connections reveal target infrastructure and may have "
                "cached credentials.",
                "Clear saved RDP connections and use a credential manager with "
                "proper access controls.",
                output="\n".join(hosts[:20]),
            )

    # ── InterestingFiles ────────────────────────────────────────────────
    def _parse_interesting_files(self, results):
        if not results:
            return
        files = []
        for r in results:
            path = r.get("Path", r.get("FileName", ""))
            if path:
                files.append(path)
        if files:
            self._add_finding(
                "DR-CRED-003",
                "Credential Files Found on Disk",
                "MEDIUM",
                f"{len(files)} potentially sensitive file(s) found on disk.",
                "Files containing credentials, configuration data, or secrets "
                "left on disk can be harvested by attackers for privilege "
                "escalation or lateral movement.",
                "Remove or secure sensitive files. Move credentials to a "
                "secrets manager or encrypted vault.",
                output="\n".join(files[:20]),
            )

    # ── TokenPrivileges ─────────────────────────────────────────────────
    def _parse_token_privs(self, results):
        if not results:
            return
        dangerous = []
        for r in results:
            priv = r.get("Privilege", r.get("Name", ""))
            if priv in _DANGEROUS_PRIVS:
                dangerous.append(priv)
        if dangerous:
            self._add_finding(
                "DR-PRIV-004",
                "Dangerous Token Privileges Assigned",
                "HIGH",
                f"Current process holds {len(dangerous)} dangerous privilege(s): "
                f"{', '.join(dangerous)}.",
                "Dangerous token privileges such as SeImpersonatePrivilege can be "
                "abused for privilege escalation via potato attacks or similar.",
                "Remove unnecessary privileges from service accounts. Use Group "
                "Managed Service Accounts (gMSA) with minimal required privileges.",
                output="\n".join(dangerous),
                mitre_attack=[{"technique": "T1134.001",
                               "tactic": "Privilege Escalation",
                               "name": "Token Impersonation/Theft"}],
            )

    # ── WMI Persistence ─────────────────────────────────────────────────
    def _parse_wmi_persistence(self, filters, consumers, subscriptions=None):
        items = []
        for f in filters:
            name = f.get("Name", f.get("FilterName", ""))
            query = f.get("Query", f.get("EventQuery", ""))
            if name:
                items.append(f"Filter: {name} | Query: {query[:120]}")
        for c in consumers:
            name = c.get("Name", c.get("ConsumerName", ""))
            cmd = c.get("CommandLineTemplate", c.get("ScriptText", ""))
            if name:
                items.append(f"Consumer: {name} | Action: {str(cmd)[:120]}")
        if subscriptions:
            for s in subscriptions:
                name = s.get("Name", s.get("SubscriptionName", ""))
                if name and name not in [i.split("|")[0] for i in items]:
                    items.append(f"Subscription: {name}")
        if items:
            self._add_finding(
                "DR-PERS-001",
                "WMI Event Subscriptions Found",
                "HIGH",
                f"{len(items)} WMI event subscription component(s) found.",
                "WMI event subscriptions are a common persistence mechanism "
                "used by advanced threat actors to maintain access.",
                "Review all WMI event subscriptions and remove unauthorized "
                "entries. Use Get-WMIObject -Namespace root/subscription.",
                output="\n".join(items[:15]),
                mitre_attack=[{"technique": "T1546.003",
                               "tactic": "Persistence",
                               "name": "WMI Event Subscription"}],
            )

    # ── UACSystemPolicies ───────────────────────────────────────────────
    def _parse_uac(self, results):
        if not results:
            return
        for r in results:
            enable_lua = r.get("EnableLUA", r.get("enableLUA"))
            if enable_lua is not None and int(enable_lua) != 1:
                self._add_finding(
                    "DR-HDN-001",
                    "UAC Disabled",
                    "HIGH",
                    "User Account Control (UAC) is disabled on this system.",
                    "With UAC disabled, malware can execute with full "
                    "administrative privileges without prompting.",
                    "Enable UAC by setting EnableLUA to 1 and rebooting.",
                    output=f"EnableLUA: {enable_lua}",
                )
                break

    # ── SecurityPackages ────────────────────────────────────────────────
    def _parse_security_packages(self, results):
        if not results:
            return
        suspicious_pkgs = []
        known_packages = {
            "negotiate", "kerberos", "ntlm", "schannel", "wdigest",
            "tspkg", "pku2u", "msv1_0", "cloudap", "negoextender",
        }
        for r in results:
            name = r.get("Name", r.get("Package", ""))
            if not name:
                continue
            if name.lower() not in known_packages:
                suspicious_pkgs.append(name)
        if suspicious_pkgs:
            self._add_finding(
                "DR-PERS-008",
                "Suspicious Security Support Providers Installed",
                "HIGH",
                f"{len(suspicious_pkgs)} non-standard Security Support Provider(s) "
                f"detected: {', '.join(suspicious_pkgs)}.",
                "Malicious SSPs can intercept credentials during authentication. "
                "Adversaries install custom SSPs for persistent credential "
                "harvesting (e.g. mimilib.dll).",
                "Investigate all non-standard SSPs. Remove unauthorized entries "
                "from HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages.",
                output="\n".join(suspicious_pkgs[:15]),
                mitre_attack=[{"technique": "T1547.005",
                               "tactic": "Persistence",
                               "name": "Security Support Provider"}],
            )

    # ── AMSIProviders ───────────────────────────────────────────────────
    def _parse_amsi(self, results):
        if not isinstance(results, list):
            results = [results] if results else []
        has_providers = False
        for r in results:
            if isinstance(r, dict) and r:
                has_providers = True
                break
            if isinstance(r, str) and r.strip():
                has_providers = True
                break
        if not has_providers:
            self._add_finding(
                "DR-HDN-029",
                "No AMSI Providers Registered",
                "MEDIUM",
                "No Antimalware Scan Interface (AMSI) providers are registered "
                "on this system.",
                "Without AMSI providers, script-based attacks (PowerShell, VBA, "
                "JScript) cannot be inspected at runtime, allowing malicious "
                "scripts to execute without detection.",
                "Ensure an AMSI-compatible antimalware solution is installed and "
                "its AMSI provider is properly registered.",
            )

    # ── AppLocker ───────────────────────────────────────────────────────
    def _parse_applocker(self, results):
        if not isinstance(results, list):
            results = [results] if results else []
        configured = False
        for r in results:
            if isinstance(r, dict):
                mode = r.get("EnforcementMode", r.get("RuleMode", ""))
                rules = r.get("Rules", r.get("RuleCount", 0))
                if mode and str(mode).lower() not in ("notconfigured", "0", ""):
                    configured = True
                    break
                if isinstance(rules, (list, int)):
                    count = len(rules) if isinstance(rules, list) else rules
                    if count > 0:
                        configured = True
                        break
        if not configured:
            self._add_finding(
                "DR-HDN-026",
                "AppLocker Not Configured",
                "MEDIUM",
                "AppLocker application control policies are not configured or "
                "not enforced on this system.",
                "Without AppLocker, any executable, script, or DLL can run "
                "regardless of publisher or path, enabling malware execution "
                "and unauthorized software use.",
                "Configure AppLocker in Enforce mode with default deny rules "
                "for executables, scripts, and DLLs. Start with Audit mode to "
                "identify required applications.",
            )

    # ── Sysmon ──────────────────────────────────────────────────────────
    def _parse_sysmon(self, results):
        if not results:
            self._add_finding(
                "DR-SYS-011",
                "Sysmon Not Installed",
                "MEDIUM",
                "Sysmon (System Monitor) is not installed or not detected.",
                "Without Sysmon, critical endpoint telemetry such as process "
                "creation, network connections, and file changes is not captured, "
                "severely limiting detection and forensic capabilities.",
                "Install and configure Sysmon with a community-maintained "
                "configuration such as SwiftOnSecurity/sysmon-config.",
            )

    # ── Defender ────────────────────────────────────────────────────────
    def _parse_defender(self, results):
        if not results:
            return
        for r in results:
            exclusions = r.get("PathExclusions", [])
            if not exclusions:
                exclusions = r.get("ExclusionPath", [])
            if exclusions:
                self._add_finding(
                    "DR-HDN-019",
                    "Windows Defender Exclusions Configured",
                    "INFO",
                    f"{len(exclusions)} Defender exclusion path(s) configured.",
                    "Defender exclusions create blind spots that malware can "
                    "exploit by placing payloads in excluded paths.",
                    "Review and minimize Defender exclusions. Remove any "
                    "exclusions that are no longer necessary.",
                    output="\n".join(str(e) for e in exclusions[:15]),
                )
                break

    # ── LSASettings ─────────────────────────────────────────────────────
    def _parse_lsa(self, results):
        if not results:
            return
        for r in results:
            run_as_ppl = r.get("RunAsPPL", r.get("LsaCfgFlags"))
            if run_as_ppl is not None and int(run_as_ppl) == 0:
                self._add_finding(
                    "DR-HDN-007",
                    "LSA Protection Not Enabled",
                    "MEDIUM",
                    "LSA is not running as a Protected Process Light (PPL).",
                    "Without LSA protection, credential dumping tools like "
                    "Mimikatz can extract credentials from LSASS memory.",
                    "Enable LSA protection by setting RunAsPPL to 1 in "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
                    output=f"RunAsPPL: {run_as_ppl}",
                )
                break

    # ── PowerShellEvents ────────────────────────────────────────────────
    def _parse_ps_events(self, results):
        if not results:
            return
        suspicious_keywords = [
            "invoke-mimikatz", "invoke-expression", "downloadstring",
            "invoke-webrequest", "encodedcommand", "-enc ", "bypass",
            "invoke-shellcode", "invoke-obfuscation", "amsibypass",
        ]
        suspicious = []
        for r in results:
            cmd = str(r.get("CommandLine", r.get("ScriptBlockText", ""))).lower()
            for kw in suspicious_keywords:
                if kw in cmd:
                    suspicious.append(
                        r.get("CommandLine", r.get("ScriptBlockText", ""))[:200])
                    break
        if suspicious:
            self._add_finding(
                "DR-EVT-004",
                "Suspicious PowerShell Activity Detected",
                "HIGH",
                f"{len(suspicious)} suspicious PowerShell command(s) detected "
                f"in event logs.",
                "Suspicious PowerShell commands may indicate an active compromise "
                "or post-exploitation activity.",
                "Investigate the suspicious commands immediately. Enable "
                "PowerShell script block logging and constrained language mode.",
                output="\n---\n".join(suspicious[:10]),
            )

    # ── DotNet ──────────────────────────────────────────────────────────
    def _parse_dotnet(self, results):
        if not results:
            return
        for r in results:
            versions = r.get("InstalledVersions", r.get("Versions", []))
            if isinstance(versions, list):
                for v in versions:
                    v_str = str(v)
                    if (v_str.startswith("2.") or v_str.startswith("3.0")
                            or v_str.startswith("3.5")):
                        self._add_finding(
                            "DR-HDN-030",
                            ".NET Framework v2/3.x Installed",
                            "LOW",
                            f".NET Framework legacy version {v_str} is installed.",
                            "Legacy .NET versions can be leveraged to bypass AMSI "
                            "and other security controls that only apply to .NET 4+.",
                            "Uninstall legacy .NET Framework versions if not "
                            "required by business applications.",
                            output=f"Version: {v_str}",
                        )
                        return

    # ── FirewallRules ───────────────────────────────────────────────────
    def _parse_firewall(self, results):
        if not results:
            return
        disabled_profiles = set()
        for r in results:
            profile = r.get("Profile", r.get("Profiles", ""))
            enabled = r.get("Enabled", r.get("Active", True))
            if isinstance(profile, str) and not enabled:
                disabled_profiles.add(profile)
        if disabled_profiles:
            self._add_finding(
                "DR-NET-002",
                "Windows Firewall Profile Disabled",
                "HIGH",
                f"Firewall disabled for profile(s): {', '.join(disabled_profiles)}.",
                "A disabled firewall leaves the system exposed to network-based "
                "attacks without filtering.",
                "Enable Windows Firewall for all profiles (Domain, Private, Public).",
                output=f"Disabled profiles: {', '.join(disabled_profiles)}",
            )

    # ── AutoRuns ────────────────────────────────────────────────────────
    def _parse_autoruns(self, results):
        if not results:
            return
        suspicious = []
        suspect_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                         "\\downloads\\", "\\public\\"]
        for r in results:
            path = str(r.get("Path", r.get("ImagePath", ""))).lower()
            name = r.get("Name", r.get("Entry", ""))
            for sp in suspect_paths:
                if sp in path:
                    suspicious.append(
                        f"{name}: {r.get('Path', r.get('ImagePath', ''))}")
                    break
        if suspicious:
            self._add_finding(
                "DR-PERS-006",
                "Suspicious AutoRun Entries",
                "MEDIUM",
                f"{len(suspicious)} autorun entrie(s) reference suspicious paths.",
                "AutoRun entries pointing to temporary or user-writable "
                "directories may indicate persistence by malware.",
                "Investigate each suspicious autorun entry. Remove unauthorized "
                "entries and scan referenced executables.",
                output="\n".join(suspicious[:15]),
                mitre_attack=[{"technique": "T1547.001",
                               "tactic": "Persistence",
                               "name": "Registry Run Keys / Startup Folder"}],
            )
