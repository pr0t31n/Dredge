# Dredge — Windows Endpoint Security Auditor

Two-component tool for auditing Windows desktop and server security posture:

1. **PowerShell Collector** (`dredge_collect.ps1`) — runs on the target Windows machine, gathers 26 categories of security-relevant data, outputs a single JSON file.
2. **Python Analyzer** (`dredge.py`) — parses the collection JSON, runs 13 analysis modules, generates 100+ security findings mapped to CIS Benchmarks, DISA STIGs, and NIST frameworks.


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/dredge)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Requirements

- **Collector**: PowerShell 5.1+ (Windows 7 SP1 through Windows Server 2025)
- **Analyzer**: Python 3.10+, Linux/macOS/Windows
- **Remote mode**: pywinrm (installed via `requirements.txt`)

## Installation

```bash
cd /opt/pr0t31n/Dredge
python3 install.py
```

## Quick Start

### Option 1: Import Mode (recommended)

1. Copy `dredge_collect.ps1` and `dredge_collect.bat` to the target Windows machine.
2. Run the collector (as Administrator for full data):
   ```cmd
   dredge_collect.bat
   ```
3. Transfer the output JSON (`dredge_collection_<hostname>_<timestamp>.json`) to the analysis machine.
4. Run the analyzer:
   ```bash
   python3 dredge.py --collection /path/to/dredge_collection_HOST_20261008.json \
                      --output-dir /path/to/output \
                      --client ACME
   ```

### Option 2: Remote Mode (WinRM)

```bash
python3 dredge.py --winrm-host 10.0.0.50 \
                   --winrm-user Administrator \
                   --winrm-pass 'P@ssw0rd' \
                   --output-dir /path/to/output \
                   --client ACME
```

### Option 3: Crucible v2 Managed

Add Dredge to a Crucible project with "Endpoint Security" scope. Configure collection file path or WinRM credentials in the tool settings panel.

## PowerShell Collector Modules (26)

| Module | Data Collected |
|--------|---------------|
| SystemInfo | OS version, build, edition, architecture, domain, hardware, TPM |
| WindowsUpdate | Update history, pending updates, WSUS config, service status |
| InstalledSoftware | Registry enumeration (HKLM + HKCU + Wow6432Node) |
| NetworkConfig | Adapters, IPs, DNS, routes, ARP, proxy |
| OpenPorts | TCP/UDP listeners mapped to processes |
| ActiveConnections | Established connections with remote IP, process, user |
| Firewall | Profile status, all rules, log config |
| Processes | Running processes with path, cmdline, hash, owner |
| Services | All services with startup type, account, binary path |
| ScheduledTasks | Tasks with actions, triggers, principal, run history |
| UserAccounts | Local users, groups, memberships, password policy |
| SecurityPolicy | Audit policy, user rights, security options |
| RegistryHardening | 40+ security registry keys (UAC, SMB, NTLM, WDigest, etc.) |
| ActiveDirectory | Domain, forest, DCs, trusts, SPNs, delegation, LDAP config |
| Certificates | Machine + user stores: expired, weak, self-signed |
| Shares | Network shares and permissions |
| BrowserChrome | Extensions, proxy, security settings, bookmarks |
| BrowserEdge | Same as Chrome (Chromium-based) |
| BrowserFirefox | Extensions, proxy, bookmarks |
| ServerSoftware | IIS, SQL Server, Exchange, DHCP/DNS, Hyper-V |
| RemoteManagement | RDP, WinRM, SSH, TeamViewer, AnyDesk, etc. |
| CloudSoftware | OneDrive, Azure AD Connect, AWS SSM, GCP agent |
| EventLogs | Security, System, PowerShell (last 7 days) |
| StartupItems | Registry Run keys, startup folders |
| BitLocker | Encryption status per drive |
| WindowsBackup | Backup config and schedule |

## Analyzer Modules (13)

| Module | Prefix | Findings | Key Checks |
|--------|--------|----------|------------|
| System | DR-SYS | 10 | EOL OS, missing updates, no backup, BitLocker |
| Hardening | DR-HDN | 25 | UAC, SMBv1, NTLM, WDigest, LSA, Defender |
| Network | DR-NET | 4 | Firewall disabled, high-risk ports, malicious IPs |
| Users | DR-USR | 6 | Weak password policy, excessive admins, guest account |
| Active Directory | DR-AD | 20 | Kerberoastable, delegation, stale accounts, GPP creds |
| Processes | DR-PRC | 8 | Malicious processes, unquoted paths, suspicious tasks |
| Browsers | DR-BRW | 8 | Malicious extensions, outdated browser, proxy |
| Remote Mgmt | DR-RMT | 5 | Unauthorized RMT, RDP without NLA |
| Server Software | DR-SRV | 4 | IIS default config, SQL weak auth |
| Event Logs | DR-EVT | 6 | Log cleared, brute force, suspicious PowerShell |
| Software | DR-SFT | 4 | EOL software, known vulnerable versions |
| Certificates | DR-CRT | 4 | Expired, weak, self-signed in trusted |
| Compliance | DR-CMP | 5 | CIS/STIG aggregate scores |

## Output Files

| File | Description |
|------|-------------|
| `meta.json` | Tool identity and engagement metadata |
| `findings.json` | All findings (pr0t31n universal schema v1.1) |
| `findings.csv` | CSV mirror of findings |
| `summary.json` | Aggregated statistics |
| `scan.log` | Human-readable timestamped log |
| `scan.log.json` | Machine-readable JSON log |
| `errors.log` | Error-level entries only |
| `endpoint_status.json` | System overview for Intelligence tab |
| `software_inventory.json` | Full software list |
| `ad_assessment.json` | Active Directory assessment data |
| `browser_audit.json` | Browser security details |
| `network_posture.json` | Network/firewall/connection summary |

## Threat Intelligence

- **Static lists**: Bundled known-bad processes, IPs, and browser extensions (offline-capable)
- **API enrichment** (optional): VirusTotal hash lookups, AbuseIPDB IP reputation
  ```bash
  python3 dredge.py --collection data.json --vt-api-key YOUR_VT_KEY --abuseipdb-key YOUR_AIPDB_KEY
  ```

## Compliance Frameworks

Findings are mapped to:
- CIS Benchmarks (Windows Desktop + Server)
- DISA STIGs (Windows general + Server)
- Microsoft Security Baselines
- NIST 800-53, 800-171, CSF 2.0
- PCI DSS 4.0
- ISO 27001/27002
- MITRE ATT&CK

## Crucible v2 Integration

- Scope type: `endpoint`
- Tool key: `DG`
- Intelligence tabs: Status, System Overview, Hardening Assessment, Software Inventory, Active Directory, Network Posture, Browser Security
- Protocol tokens: `__CRUCIBLE_STATUS__`, `__CRUCIBLE_LOG__`, `__CRUCIBLE_RESULT__`
