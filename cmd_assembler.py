"""
Dredge CMD Assembler — converts raw CMD collection directory into the same
JSON dict structure that dredge_collect.ps1 produces, so dredge.py's analyzers
can run unchanged.

Usage:
    from cmd_assembler import assemble
    data = assemble("/path/to/dredge_cmd_HOSTNAME_TIMESTAMP")
"""

import csv
import io
import json
import os
import re
from datetime import datetime
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════
#  Low-level format parsers
# ═══════════════════════════════════════════════════════════════════════════

def _read(path, encoding=None):
    p = Path(path)
    if not p.exists():
        return ""
    for enc in ([encoding] if encoding else []) + ["utf-8", "cp1252", "cp437", "latin-1"]:
        try:
            return p.read_text(encoding=enc, errors="replace")
        except Exception:
            continue
    return ""


def _read_or_none(base, *parts):
    p = Path(base, *parts)
    if not p.exists():
        return None
    return _read(p)


def _parse_wmic_list(text):
    records = []
    current = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line.strip():
            if current:
                records.append(current)
                current = {}
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            current[key.strip()] = val.strip()
    if current:
        records.append(current)
    return records


def _parse_wmic_csv(text):
    lines = text.strip().splitlines()
    if not lines:
        return []
    start = 0
    for i, line in enumerate(lines):
        if line.strip() and "," in line:
            start = i
            break
    if start >= len(lines):
        return []
    try:
        reader = csv.DictReader(lines[start:])
        rows = []
        for row in reader:
            cleaned = {}
            for k, v in row.items():
                if k is None:
                    continue
                k2 = k.strip().lstrip("\ufeff")
                if k2:
                    cleaned[k2] = (v or "").strip()
            if cleaned and any(v for v in cleaned.values()):
                rows.append(cleaned)
        return rows
    except Exception:
        return []


def _parse_reg_query(text):
    values = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        m = re.match(r"^\s+(\S+)\s+REG_\w+\s+(.*)", line)
        if m:
            values[m.group(1)] = m.group(2).strip()
    return values


def _parse_reg_value(text, value_name):
    vals = _parse_reg_query(text)
    return vals.get(value_name)


def _reg_dword_int(text, value_name, default=None):
    v = _parse_reg_value(text, value_name)
    if v is None:
        return default
    v = v.strip()
    try:
        if v.startswith("0x"):
            return int(v, 16)
        return int(v)
    except (ValueError, TypeError):
        return default


def _parse_sc_query(text):
    services = []
    current = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line.strip():
            if current:
                services.append(current)
                current = {}
            continue
        m = re.match(r"^\s*(SERVICE_NAME|DISPLAY_NAME|TYPE|STATE|START_TYPE|BINARY_PATH_NAME|SERVICE_START_NAME)\s*:\s*(.*)", line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            if key == "STATE":
                val = re.sub(r"^\d+\s+", "", val)
            if key == "START_TYPE":
                val = re.sub(r"^\d+\s+", "", val)
            current[key] = val
    if current:
        services.append(current)
    return services


def _parse_netstat(text):
    entries = []
    for line in text.splitlines():
        line = line.strip()
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue
        local = parts[1]
        foreign = parts[2]
        if proto == "TCP":
            state = parts[3] if len(parts) >= 4 else ""
            pid = parts[4] if len(parts) >= 5 else ""
        else:
            state = ""
            pid = parts[3] if len(parts) >= 4 else ""
        local_port = local.rsplit(":", 1)[-1] if ":" in local else ""
        remote_addr = foreign.rsplit(":", 1)[0] if ":" in foreign else foreign
        remote_port = foreign.rsplit(":", 1)[-1] if ":" in foreign else ""
        try:
            local_port = int(local_port)
        except (ValueError, TypeError):
            local_port = 0
        try:
            remote_port = int(remote_port)
        except (ValueError, TypeError):
            remote_port = 0
        try:
            pid = int(pid)
        except (ValueError, TypeError):
            pid = 0
        entries.append({
            "protocol": proto,
            "local_address": local,
            "local_port": local_port,
            "remote_address": remote_addr,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
        })
    return entries


def _parse_systeminfo(text):
    info = {}
    current_key = None
    for line in text.splitlines():
        line = line.rstrip("\r")
        if ":" in line and not line.startswith(" "):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            info[key] = val
            current_key = key
        elif current_key and line.startswith(" "):
            existing = info.get(current_key, "")
            info[current_key] = existing + "\n" + line.strip() if existing else line.strip()
    return info


def _parse_certutil_store(text, store_name):
    certs = []
    blocks = re.split(r"={10,}", text)
    for block in blocks:
        if not block.strip():
            continue
        cert = {"store": store_name}
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("Subject:"):
                cert["subject"] = line[8:].strip()
            elif line.startswith("Issuer:"):
                cert["issuer"] = line[7:].strip()
            elif line.startswith("NotAfter:") or line.startswith("Not After:"):
                cert["not_after"] = re.sub(r"^Not\s*After:\s*", "", line).strip()
            elif line.startswith("NotBefore:") or line.startswith("Not Before:"):
                cert["not_before"] = re.sub(r"^Not\s*Before:\s*", "", line).strip()
            elif "Cert Hash" in line and "sha1" in line.lower():
                m = re.search(r":\s*([0-9a-fA-F\s]+)", line)
                if m:
                    cert["thumbprint"] = m.group(1).replace(" ", "")
            elif "Signature Algorithm" in line:
                m = re.search(r":\s*(.+)", line)
                if m:
                    cert["signature_algorithm"] = m.group(1).strip()
            elif "Public Key Length" in line or "PublicKey Length" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    cert["key_size"] = int(m.group(1))
        if cert.get("subject"):
            cn_m = re.search(r"CN=([^,]+)", cert.get("subject", ""))
            if cn_m:
                cert["subject_cn"] = cn_m.group(1).strip()
            cn_m = re.search(r"CN=([^,]+)", cert.get("issuer", ""))
            if cn_m:
                cert["issuer_cn"] = cn_m.group(1).strip()
            if cert.get("subject") == cert.get("issuer"):
                cert["self_signed"] = True
            certs.append(cert)
    return certs


def _parse_wevtutil_text(text):
    events = []
    current = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line.strip():
            if current:
                events.append(current)
                current = {}
            continue
        m = re.match(r"^\s*(Event\[\d+\]|[\w\s]+):\s*(.*)", line)
        if m:
            key = m.group(1).strip().lower().replace(" ", "_")
            val = m.group(2).strip()
            if key == "event_id":
                try:
                    val = int(val)
                except ValueError:
                    pass
            elif key == "date":
                key = "time"
            current[key] = val
    if current:
        events.append(current)
    return events


def _parse_netsh_firewall(text):
    profiles = {}
    current_profile = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for pname in ("Domain", "Private", "Public"):
            if pname.lower() in line.lower() and "profile" in line.lower():
                current_profile = pname
                profiles[pname] = {}
                break
        if current_profile and ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if "state" == key:
                profiles[current_profile]["enabled"] = val.upper() == "ON"
            elif "firewall policy" in key:
                profiles[current_profile]["policy"] = val
    return profiles


def _parse_whoami_priv(text):
    privs = []
    in_table = False
    for line in text.splitlines():
        line = line.strip()
        if "Privilege Name" in line:
            in_table = True
            continue
        if in_table and line.startswith("==="):
            continue
        if in_table and line:
            parts = re.split(r"\s{2,}", line)
            if len(parts) >= 2:
                privs.append({
                    "privilege": parts[0].strip(),
                    "description": parts[1].strip() if len(parts) > 1 else "",
                    "status": parts[2].strip() if len(parts) > 2 else "Enabled",
                })
    return privs


def _parse_net_accounts(text):
    info = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return info


# ═══════════════════════════════════════════════════════════════════════════
#  Section assemblers — each returns the dict matching what the PS1 puts
#  under that section key in the output JSON
# ═══════════════════════════════════════════════════════════════════════════

def _assemble_system_info(d):
    result = {}
    sysinfo = _parse_systeminfo(_read(d / "systeminfo.txt"))
    os_rec = _parse_wmic_list(_read(d / "wmic_os.txt"))
    cs_rec = _parse_wmic_list(_read(d / "wmic_computersystem.txt"))
    bios_rec = _parse_wmic_list(_read(d / "wmic_bios.txt"))
    os_d = os_rec[0] if os_rec else {}
    cs_d = cs_rec[0] if cs_rec else {}
    result["os_name"] = os_d.get("Caption", sysinfo.get("OS Name", ""))
    result["os_version"] = os_d.get("Version", sysinfo.get("OS Version", ""))
    try:
        result["os_build"] = int(os_d.get("BuildNumber", "0"))
    except ValueError:
        result["os_build"] = 0
    result["os_product_type"] = os_d.get("ProductType", "")
    result["domain_role"] = cs_d.get("DomainRole", "")
    result["is_domain_joined"] = cs_d.get("PartOfDomain", "").lower() == "true"
    result["hostname"] = cs_d.get("Name", os_d.get("CSName", ""))
    result["domain"] = cs_d.get("Domain", "")
    last_boot = os_d.get("LastBootUpTime", "")
    if last_boot:
        try:
            boot_dt = datetime.strptime(last_boot[:14], "%Y%m%d%H%M%S")
            delta = datetime.now() - boot_dt
            result["uptime_days"] = delta.days
        except (ValueError, TypeError):
            result["uptime_days"] = 0
    else:
        result["uptime_days"] = 0
    bios_d = bios_rec[0] if bios_rec else {}
    result["bios_version"] = bios_d.get("SMBIOSBIOSVersion", "")
    result["secure_boot"] = False
    bcdedit = _read(d / "bcdedit.txt")
    if bcdedit:
        for line in bcdedit.splitlines():
            if "secureboot" in line.lower() and "yes" in line.lower():
                result["secure_boot"] = True
    result["tpm"] = {}
    return result


def _assemble_updates(d):
    result = {}
    qfe = _parse_wmic_csv(_read(d / "qfe_list.csv"))
    result["installed_updates"] = qfe
    result["pending_updates"] = 0
    sc_text = _read(d / "wuauserv_status.txt")
    sc_entries = _parse_sc_query(sc_text)
    svc = sc_entries[0] if sc_entries else {}
    result["service_status"] = svc.get("STATE", "")
    wsus = _parse_reg_query(_read(d / "wsus_policy.txt"))
    result["wsus_server"] = wsus.get("WUServer", "")
    return result


def _assemble_installed_software(d):
    sw_list = []
    seen = set()
    csv_rows = _parse_wmic_csv(_read(d / "wmic_product.csv"))
    for row in csv_rows:
        name = row.get("Name", "")
        if not name or name in seen:
            continue
        seen.add(name)
        sw_list.append({
            "name": name,
            "version": row.get("Version", ""),
            "vendor": row.get("Vendor", ""),
            "install_date": row.get("InstallDate", ""),
        })
    for reg_file in ("uninstall_hklm.txt", "uninstall_hklm_wow64.txt", "uninstall_hkcu.txt"):
        text = _read(d / reg_file)
        if not text:
            continue
        current_name = ""
        current_version = ""
        for line in text.splitlines():
            line = line.rstrip("\r")
            if line.startswith("HKLM\\") or line.startswith("HKCU\\"):
                if current_name and current_name not in seen:
                    seen.add(current_name)
                    sw_list.append({"name": current_name, "version": current_version})
                current_name = ""
                current_version = ""
            m = re.match(r"^\s+DisplayName\s+REG_SZ\s+(.*)", line)
            if m:
                current_name = m.group(1).strip()
            m = re.match(r"^\s+DisplayVersion\s+REG_SZ\s+(.*)", line)
            if m:
                current_version = m.group(1).strip()
        if current_name and current_name not in seen:
            seen.add(current_name)
            sw_list.append({"name": current_name, "version": current_version})
    return sw_list


def _assemble_network_config(d):
    result = {}
    wmic_nics = _parse_wmic_list(_read(d / "wmic_nicconfig.txt"))
    adapters = []
    dns_servers = []
    for nic in wmic_nics:
        adapter = {
            "description": nic.get("Description", ""),
            "ip_address": nic.get("IPAddress", ""),
            "subnet": nic.get("IPSubnet", ""),
            "gateway": nic.get("DefaultIPGateway", ""),
            "dhcp_enabled": nic.get("DHCPEnabled", "").lower() == "true",
            "mac_address": nic.get("MACAddress", ""),
        }
        dns = nic.get("DNSServerSearchOrder", "")
        if dns:
            for s in re.findall(r"[\d.]+", dns):
                if s not in dns_servers:
                    dns_servers.append(s)
        nb = nic.get("TcpipNetbiosOptions", "")
        if nb == "0" or nb == "1":
            adapter["netbios_over_tcpip"] = True
        elif nb == "2":
            adapter["netbios_over_tcpip"] = False
        adapters.append(adapter)
    result["adapters"] = adapters
    result["dns_servers"] = dns_servers
    proxy_text = _read(d / "proxy_settings.txt")
    proxy_vals = _parse_reg_query(proxy_text)
    proxy_enable = proxy_vals.get("ProxyEnable", "0")
    proxy_server = proxy_vals.get("ProxyServer", "")
    pac_url = proxy_vals.get("AutoConfigURL", "")
    if proxy_enable == "0x1" or proxy_enable == "1":
        result["proxy"] = {"enabled": True, "server": proxy_server, "pac_url": pac_url}
    elif pac_url:
        result["proxy"] = {"enabled": True, "server": "", "pac_url": pac_url}
    else:
        result["proxy"] = {}
    result["domain"] = ""
    ipconfig = _read(d / "ipconfig.txt")
    for line in ipconfig.splitlines():
        if "Primary Dns Suffix" in line and ":" in line:
            result["domain"] = line.split(":", 1)[1].strip()
            break
        if "Connection-specific DNS Suffix" in line and ":" in line:
            val = line.split(":", 1)[1].strip()
            if val and not result.get("domain"):
                result["domain"] = val
    nbtstat = _read(d / "nbtstat_n.txt")
    if nbtstat:
        result["netbios_over_tcpip"] = bool(re.search(r"<\w+>", nbtstat))
    return result


def _assemble_open_ports(d):
    text = _read(d / "netstat_ano.txt")
    entries = _parse_netstat(text)
    ports = []
    seen = set()
    for e in entries:
        if e["state"] in ("LISTENING", ""):
            key = (e["protocol"], e["local_port"])
            if key not in seen:
                seen.add(key)
                ports.append({
                    "port": e["local_port"],
                    "state": e["state"] or "LISTENING",
                    "process": e["pid"],
                    "protocol": e["protocol"],
                })
    return ports


def _assemble_active_connections(d):
    text = _read(d / "tcp_connections.txt")
    entries = _parse_netstat(text)
    conns = []
    for e in entries:
        if e["state"] == "ESTABLISHED":
            conns.append({
                "remote_address": e["remote_address"],
                "remote_port": e["remote_port"],
                "local_port": e["local_port"],
                "process": e["pid"],
                "protocol": e["protocol"],
                "state": e["state"],
            })
    return conns


def _assemble_firewall(d):
    text = _read(d / "profiles.txt")
    profiles = _parse_netsh_firewall(text)
    state_text = _read(d / "state.txt")
    if state_text and not profiles:
        profiles = _parse_netsh_firewall(state_text)
    return {"profiles": profiles}


def _assemble_processes(d):
    rows = _parse_wmic_csv(_read(d / "process_detail.csv"))
    if not rows:
        rows = _parse_wmic_csv(_read(d / "wmic_process.csv"))
    procs = []
    for row in rows:
        name = row.get("Name", "")
        if not name:
            continue
        try:
            pid = int(row.get("ProcessId", 0))
        except (ValueError, TypeError):
            pid = 0
        try:
            ppid = int(row.get("ParentProcessId", 0))
        except (ValueError, TypeError):
            ppid = 0
        procs.append({
            "name": name,
            "pid": pid,
            "parent_pid": ppid,
            "executable_path": row.get("ExecutablePath", ""),
            "path": row.get("ExecutablePath", ""),
            "command_line": row.get("CommandLine", ""),
            "username": "",
        })
    return procs


def _assemble_services(d):
    rows = _parse_wmic_csv(_read(d / "service_summary.csv"))
    svcs = []
    for row in rows:
        name = row.get("Name", "")
        if not name:
            continue
        svcs.append({
            "name": name,
            "display_name": row.get("DisplayName", ""),
            "status": row.get("State", ""),
            "start_type": row.get("StartMode", ""),
            "start_account": row.get("StartName", ""),
            "binary_path": row.get("PathName", ""),
        })
    if not svcs:
        sc_entries = _parse_sc_query(_read(d / "sc_query_all.txt"))
        for e in sc_entries:
            svcs.append({
                "name": e.get("SERVICE_NAME", ""),
                "display_name": e.get("DISPLAY_NAME", ""),
                "status": e.get("STATE", ""),
                "start_type": e.get("START_TYPE", ""),
                "start_account": e.get("SERVICE_START_NAME", ""),
                "binary_path": e.get("BINARY_PATH_NAME", ""),
            })
    return svcs


def _assemble_scheduled_tasks(d):
    rows = _parse_wmic_csv(_read(d / "schtasks_verbose.csv"))
    return rows


def _assemble_user_accounts(d):
    result = {}
    wmic_users = _parse_wmic_csv(_read(d / "wmic_useraccount.csv"))
    local_users = []
    for u in wmic_users:
        local_users.append({
            "name": u.get("Name", ""),
            "sid": u.get("SID", ""),
            "enabled": u.get("Disabled", "").lower() != "true",
            "password_never_expires": u.get("PasswordExpires", "").lower() != "true",
            "description": u.get("Description", ""),
            "full_name": u.get("FullName", ""),
        })
    result["local_users"] = local_users
    admins_text = _read(d / "local_admins.txt")
    admin_members = []
    in_members = False
    for line in admins_text.splitlines():
        line = line.strip()
        if line.startswith("---"):
            in_members = True
            continue
        if in_members and line and "completed successfully" not in line.lower():
            admin_members.append(line)
    result["administrators_group"] = admin_members
    return result


def _assemble_security_policy(d):
    result = {}
    na = _parse_net_accounts(_read(d / "net_accounts.txt"))
    pw_policy = {}
    pw_policy["minimum_password_length"] = na.get("Minimum password length", "")
    pw_policy["maximum_password_age"] = na.get("Maximum password age (days)", "")
    pw_policy["minimum_password_age"] = na.get("Minimum password age (days)", "")
    pw_policy["password_history_count"] = na.get("Length of password history maintained", "")
    result["password_policy"] = pw_policy
    lockout = {}
    lockout["lockout_threshold"] = na.get("Lockout threshold", "")
    lockout["lockout_duration"] = na.get("Lockout duration (minutes)", "")
    lockout["lockout_observation_window"] = na.get("Lockout observation window (minutes)", "")
    result["lockout_policy"] = lockout
    return result


def _assemble_registry_hardening(d):
    result = {}
    uac = _parse_reg_query(_read(d / "uac.txt"))
    result["EnableLUA"] = _to_int(uac.get("EnableLUA"))
    result["ConsentPromptBehaviorAdmin"] = _to_int(uac.get("ConsentPromptBehaviorAdmin"))
    lsa = _parse_reg_query(_read(d / "lsa.txt"))
    result["LmCompatibilityLevel"] = _to_int(lsa.get("LmCompatibilityLevel"))
    result["NoLMHash"] = _to_int(lsa.get("NoLMHash"))
    result["RunAsPPL"] = _to_int(lsa.get("RunAsPPL"))
    result["RestrictAnonymous"] = _to_int(lsa.get("RestrictAnonymous"))
    smb_server = _parse_reg_query(_read(d / "smb_server.txt"))
    result["SMB1"] = _to_int(smb_server.get("SMB1", smb_server.get("EnableSMB1Protocol")))
    result["RequireSecuritySignature"] = _to_int(smb_server.get("RequireSecuritySignature"))
    result["NullSessionPipes"] = smb_server.get("NullSessionPipes", "")
    wdigest = _parse_reg_query(_read(d / "wdigest.txt"))
    result["UseLogonCredential"] = _to_int(wdigest.get("UseLogonCredential"))
    dg = _parse_reg_query(_read(d / "device_guard.txt"))
    result["EnableVirtualizationBasedSecurity"] = _to_int(dg.get("EnableVirtualizationBasedSecurity"))
    result["HypervisorEnforcedCodeIntegrity"] = _to_int(dg.get("HypervisorEnforcedCodeIntegrity"))
    cg = _parse_reg_query(_read(d / "credential_guard.txt"))
    result["LsaCfgFlags"] = _to_int(cg.get("LsaCfgFlags"))
    autorun = _parse_reg_query(_read(d / "autorun.txt"))
    result["NoDriveTypeAutoRun"] = _to_int(autorun.get("NoDriveTypeAutoRun"))
    ps_log = _parse_reg_query(_read(d / "powershell_logging.txt"))
    result["ScriptBlockLogging"] = _to_int(ps_log.get("EnableScriptBlockLogging"))
    result["ModuleLogging"] = _to_int(ps_log.get("EnableModuleLogging"))
    result["Transcription"] = _to_int(ps_log.get("EnableTranscripting"))
    llmnr = _parse_reg_query(_read(d / "llmnr.txt"))
    result["EnableMulticast"] = _to_int(llmnr.get("EnableMulticast"))
    wpad = _parse_reg_query(_read(d / "wpad.txt"))
    wpad_start = _to_int(wpad.get("Start"))
    result["WpadOverride"] = wpad_start == 4 if wpad_start is not None else None
    mem = _parse_reg_query(_read(d / "memory_mgmt.txt"))
    result["nx_policy"] = mem.get("MoveImages", "")
    rdp_ts = _parse_reg_query(_read(d / "rdp_ts.txt"))
    result["fDenyTSConnections"] = _to_int(rdp_ts.get("fDenyTSConnections"))
    rdp_tcp = _parse_reg_query(_read(d / "rdp_tcp.txt"))
    result["UserAuthentication"] = _to_int(rdp_tcp.get("UserAuthentication"))
    defender_policy = _parse_reg_query(_read(d / "defender_policy.txt"))
    result["defender_disabled"] = _to_int(defender_policy.get("DisableAntiSpyware"))
    defender_config = _parse_reg_query(_read(d / "defender_config.txt"))
    result["real_time_protection"] = _to_int(defender_config.get("DisableRealtimeMonitoring"))
    result["defender_exclusions"] = []
    auditpol = _read(d / "auditpol.txt") if (d / "auditpol.txt").exists() else ""
    if auditpol:
        result["audit_policy"] = auditpol
    return result


def _to_int(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    v = str(v).strip()
    try:
        if v.startswith("0x"):
            return int(v, 16)
        return int(v)
    except (ValueError, TypeError):
        return None


def _assemble_active_directory(d):
    result = {}
    dclist = _read(d / "dclist.txt")
    if "ERROR" in dclist.upper() and "not found" in dclist.lower():
        return result
    result["domain_controllers"] = []
    da_text = _read(d / "domain_admins.txt")
    da_members = _parse_net_group_members(da_text)
    result["domain_admins"] = da_members
    ea_text = _read(d / "enterprise_admins.txt")
    result["enterprise_admins"] = _parse_net_group_members(ea_text)
    ldap_server = _parse_reg_query(_read(d / "ldap_signing_server.txt"))
    ldap_client = _parse_reg_query(_read(d / "ldap_signing_client.txt"))
    ldap_cb = _parse_reg_query(_read(d / "ldap_channel_binding.txt"))
    result["ldap_signing"] = {
        "server": _to_int(ldap_server.get("LDAPServerIntegrity")),
        "client": _to_int(ldap_client.get("LDAPClientIntegrity")),
        "channel_binding": _to_int(ldap_cb.get("LdapEnforceChannelBinding")),
    }
    trusts_text = _read(d / "domain_trusts.txt")
    result["trusts_raw"] = trusts_text
    return result


def _parse_net_group_members(text):
    members = []
    in_members = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("---"):
            in_members = True
            continue
        if in_members and line and "completed successfully" not in line.lower():
            for name in line.split():
                if name:
                    members.append(name)
    return members


def _assemble_certificates(d):
    certs = []
    for store, filename in [
        ("My", "store_my.txt"),
        ("Root", "store_root.txt"),
        ("CA", "store_ca.txt"),
        ("User-My", "store_user_my.txt"),
        ("User-Root", "store_user_root.txt"),
        ("User-CA", "store_user_ca.txt"),
    ]:
        text = _read(d / filename)
        if text:
            certs.extend(_parse_certutil_store(text, store))
    return certs


def _assemble_shares(d):
    rows = _parse_wmic_csv(_read(d / "wmic_share.csv"))
    return rows


def _assemble_browser(d):
    result = {}
    for reg_file in d.iterdir():
        if reg_file.suffix == ".txt":
            text = _read(reg_file)
            if "ProxyServer" in text or "ProxyEnable" in text:
                vals = _parse_reg_query(text)
                if vals.get("ProxyServer"):
                    result["proxy"] = vals.get("ProxyServer", "")
    return result


def _assemble_server_software(d):
    result = {}
    iis_text = _read(d / "iis.txt")
    iis_vals = _parse_reg_query(iis_text)
    if iis_vals:
        result["iis"] = {
            "installed": True,
            "version": iis_vals.get("VersionString", ""),
            "sites": [],
        }
        sites_text = _read(d / "iis_sites.txt")
        if sites_text:
            for line in sites_text.splitlines():
                line = line.strip()
                if line:
                    m = re.match(r'^SITE "([^"]+)"', line)
                    name = m.group(1) if m else line
                    state = "started" if "state:Started" in line else ""
                    result["iis"]["sites"].append({"name": name, "state": state})
    sql_text = _read(d / "sql_server.txt")
    if sql_text and "ERROR" not in sql_text.upper():
        sql_vals = _parse_reg_query(sql_text)
        if sql_vals:
            result["sql_server"] = {
                "installed": True,
                "version": sql_vals.get("CurrentVersion", ""),
                "instance": sql_vals.get("InstalledInstances", "MSSQLSERVER"),
                "authentication_mode": "",
            }
    roles = []
    for svc_file, role in [
        ("dhcp_server.txt", "DHCP Server"),
        ("dns_server.txt", "DNS Server"),
        ("ad_ds.txt", "Active Directory Domain Services"),
        ("cert_svc.txt", "Active Directory Certificate Services"),
    ]:
        sc_text = _read(d / svc_file)
        if sc_text and "RUNNING" in sc_text:
            roles.append(role)
    result["installed_roles"] = roles
    return result


def _assemble_remote_management(d):
    result = {}
    rdp_config = _parse_reg_query(_read(d / "rdp_config.txt"))
    rdp_tcp = _parse_reg_query(_read(d / "rdp_tcp_config.txt"))
    deny_ts = _to_int(rdp_config.get("fDenyTSConnections"))
    nla = _to_int(rdp_tcp.get("UserAuthentication"))
    port = _to_int(rdp_tcp.get("PortNumber"))
    result["rdp"] = {
        "enabled": deny_ts == 0 if deny_ts is not None else False,
        "nla_required": nla == 1 if nla is not None else True,
        "port": port if port else 3389,
    }
    winrm_svc = _read(d / "winrm_service.txt")
    winrm_running = "RUNNING" in winrm_svc if winrm_svc else False
    winrm_cfg = _read(d / "winrm_config.txt")
    allow_unencrypted = False
    allow_basic = False
    if winrm_cfg:
        if re.search(r"AllowUnencrypted\s*=\s*true", winrm_cfg, re.IGNORECASE):
            allow_unencrypted = True
        if re.search(r"Basic\s*=\s*true", winrm_cfg, re.IGNORECASE):
            allow_basic = True
    result["winrm"] = {
        "running": winrm_running,
        "allow_unencrypted": allow_unencrypted,
        "allow_basic": allow_basic,
    }
    sshd_svc = _read(d / "sshd_service.txt")
    result["ssh"] = {
        "enabled": "RUNNING" in sshd_svc if sshd_svc else False,
        "port": 22,
        "password_authentication": True,
    }
    tools = []
    for tool_file, tool_name in [
        ("teamviewer.txt", "TeamViewer"),
        ("vnc.txt", "VNC"),
    ]:
        text = _read(d / tool_file)
        if text and "ERROR" not in text.upper():
            vals = _parse_reg_query(text)
            if vals:
                tools.append({"name": tool_name, "process": ""})
    result["tools"] = tools
    return result


def _assemble_cloud_software(d):
    return {}


def _assemble_event_logs(d):
    result = {}
    sec_text = _read(d / "security_recent.txt")
    result["security"] = _parse_wevtutil_text(sec_text) if sec_text else []
    sys_text = _read(d / "system_recent.txt")
    result["system"] = _parse_wevtutil_text(sys_text) if sys_text else []
    ps_text = _read(d / "powershell_operational.txt")
    result["powershell_operational"] = _parse_wevtutil_text(ps_text) if ps_text else []
    ps_classic = _read(d / "powershell_classic.txt")
    result["powershell"] = _parse_wevtutil_text(ps_classic) if ps_classic else []
    failed = _read(d / "failed_logons.txt")
    if failed:
        result["security"].extend(_parse_wevtutil_text(failed))
    acct = _read(d / "account_mgmt.txt")
    if acct:
        result["security"].extend(_parse_wevtutil_text(acct))
    return result


def _assemble_startup_items(d):
    items = []
    csv_rows = _parse_wmic_csv(_read(d / "wmic_startup.csv"))
    for row in csv_rows:
        name = row.get("Name", row.get("Caption", ""))
        cmd = row.get("Command", row.get("command", ""))
        loc = row.get("Location", row.get("location", ""))
        if name or cmd:
            items.append({"name": name, "command": cmd, "location": loc, "path": cmd})
    for reg_file in ("run_hklm.txt", "run_hkcu.txt", "runonce_hklm.txt",
                      "runonce_hkcu.txt", "run_hklm_wow64.txt"):
        text = _read(d / reg_file)
        if not text:
            continue
        vals = _parse_reg_query(text)
        for name, cmd in vals.items():
            if name and cmd:
                items.append({"name": name, "command": cmd, "location": reg_file, "path": cmd})
    return items


def _assemble_bitlocker(d):
    text = _read(d / "status.txt")
    drives = []
    current = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Volume") and ":" in line:
            if current:
                drives.append(current)
            current = {"volume": line}
        elif ":" in line and current:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            current[key] = val.strip()
    if current:
        drives.append(current)
    return {"drives": drives}


def _assemble_windows_backup(d):
    result = {}
    versions = _read(d / "versions.txt")
    result["configured"] = bool(versions and "ERROR" not in versions.upper() and versions.strip())
    result["last_backup"] = ""
    if versions:
        for line in versions.splitlines():
            if "Version identifier" in line or "Backup time" in line:
                _, _, val = line.partition(":")
                result["last_backup"] = val.strip()
    svc = _read(d / "wbengine_service.txt")
    result["service_running"] = "RUNNING" in svc if svc else False
    return result


def _assemble_credential_exposure(d):
    result = {}
    wifi_text = _read(d / "wifi_passwords.txt")
    profiles = []
    if wifi_text:
        current = {}
        for line in wifi_text.splitlines():
            line = line.strip()
            if "All User Profile" in line and ":" in line:
                if current:
                    profiles.append(current)
                current = {"profile_name": line.split(":", 1)[1].strip()}
            elif "Key Content" in line and ":" in line:
                current["key_content"] = line.split(":", 1)[1].strip()
        if current:
            profiles.append(current)
    result["wifi_profiles"] = profiles
    sens = _read(d / "sensitive_files.txt")
    cred_files = []
    if sens:
        for line in sens.splitlines():
            if line.startswith("FOUND:"):
                path = line[6:].strip()
                cred_files.append({
                    "found": True,
                    "path": path,
                    "filename": os.path.basename(path),
                    "has_cpassword": "groups.xml" in path.lower(),
                })
    result["credential_files"] = cred_files
    cmdkey = _read(d / "cmdkey_list.txt")
    vault_entries = []
    if cmdkey:
        for line in cmdkey.splitlines():
            line = line.strip()
            if line.startswith("Target:"):
                vault_entries.append({"target": line[7:].strip()})
    result["vault_entries"] = vault_entries
    cloud_text = _read_or_none(d.parent / "cloud_software", "cloud_cred_locations.txt")
    cloud_creds = []
    if cloud_text:
        for line in cloud_text.splitlines():
            if line.startswith("FOUND:"):
                path = line[6:].strip()
                provider = "aws" if "aws" in path.lower() else \
                           "azure" if "azure" in path.lower() else \
                           "gcp" if "gcloud" in path.lower() else "unknown"
                cloud_creds.append({"found": True, "path": path, "provider": provider})
    result["cloud_credentials"] = cloud_creds
    autologon = _parse_reg_query(_read(d / "autologon.txt"))
    if autologon.get("DefaultPassword"):
        cred_files.append({
            "found": True,
            "path": "Registry: DefaultPassword (Winlogon AutoLogon)",
            "filename": "autologon",
            "has_cpassword": False,
        })
    result["putty_sessions"] = []
    result["winscp_sessions"] = []
    result["filezilla_sessions"] = []
    result["rdp_connections"] = []
    result["dpapi"] = {}
    result["keepass_files"] = []
    result["ssh_keys"] = []
    return result


def _assemble_privilege_escalation(d):
    result = {}
    hklm = _parse_reg_query(_read(d / "always_install_elevated_hklm.txt"))
    hkcu = _parse_reg_query(_read(d / "always_install_elevated_hkcu.txt"))
    result["always_install_elevated_hklm"] = _to_int(hklm.get("AlwaysInstallElevated"))
    result["always_install_elevated_hkcu"] = _to_int(hkcu.get("AlwaysInstallElevated"))
    privs = _parse_whoami_priv(_read(d / "whoami_priv.txt"))
    result["token_privileges"] = privs
    svc_rows = _parse_wmic_csv(_read(d / "service_paths.csv"))
    unquoted = []
    for row in svc_rows:
        path = row.get("PathName", "")
        name = row.get("Name", "")
        if path and " " in path and not path.startswith('"') and not path.startswith("'"):
            if "\\program files" not in path.lower()[:20]:
                unquoted.append({
                    "name": name,
                    "binary_path": path,
                    "writable_intermediate": "",
                })
    result["unquoted_service_paths"] = unquoted
    path_text = _read(d / "system_path.txt").strip()
    writable_dirs = []
    if path_text:
        for p in path_text.split(";"):
            p = p.strip()
            if p and p.lower() not in ("c:\\windows\\system32", "c:\\windows",
                                        "c:\\windows\\system32\\wbem"):
                writable_dirs.append({"path": p})
    result["writable_path_dirs"] = writable_dirs
    result["modifiable_services"] = []
    result["permissive_named_pipes"] = []
    return result


def _assemble_defender_detailed(d):
    result = {}
    excl = _parse_reg_query(_read(d / "exclusions.txt"))
    result["exclusions"] = excl
    rtp = _parse_reg_query(_read(d / "realtime_protection.txt"))
    result["realtime_monitoring_disabled"] = _to_int(rtp.get("DisableRealtimeMonitoring"))
    av_text = _read(d / "av_products.txt")
    av_products = _parse_wmic_list(av_text)
    result["av_products"] = av_products
    return result


def _assemble_adcs(d):
    result = {}
    ping = _read(d / "ca_ping.txt")
    result["available"] = bool(ping and "ERROR" not in ping.upper())
    result["templates"] = []
    result["certificate_authorities"] = []
    editflags = _read(d / "editflags.txt")
    if editflags:
        if "EDITF_ATTRIBUTESUBJECTALTNAME2" in editflags.upper():
            result["certificate_authorities"].append({
                "name": "detected",
                "edit_flags": "EDITF_ATTRIBUTESUBJECTALTNAME2",
                "http_enrollment": False,
                "ntlm_enabled": True,
            })
    return result


def _assemble_persistence_mechanisms(d):
    result = {}
    wmi_filter = _read(d / "wmi_eventfilter.txt")
    wmi_cmd = _read(d / "wmi_cmdconsumer.txt")
    wmi_script = _read(d / "wmi_scriptconsumer.txt")
    subs = []
    filters = _parse_wmic_list(wmi_filter) if wmi_filter else []
    cmd_consumers = _parse_wmic_list(wmi_cmd) if wmi_cmd else []
    script_consumers = _parse_wmic_list(wmi_script) if wmi_script else []
    for f in filters:
        name = f.get("Name", "")
        if name:
            consumer = ""
            ctype = ""
            for c in cmd_consumers:
                consumer = c.get("Name", "")
                ctype = "CommandLineEventConsumer"
                break
            if not consumer:
                for c in script_consumers:
                    consumer = c.get("Name", "")
                    ctype = "ActiveScriptEventConsumer"
                    break
            subs.append({
                "filter_name": name,
                "consumer_name": consumer,
                "consumer_type": ctype,
                "command_line_template": "",
            })
    result["wmi_subscriptions"] = subs
    appinit = _parse_reg_query(_read(d / "appinit_dlls.txt"))
    result["appinit_dlls"] = {
        "value": appinit.get("AppInit_DLLs", ""),
        "load_appinit_dlls": _to_int(appinit.get("LoadAppInit_DLLs", "0")),
    }
    ifeo_text = _read(d / "ifeo.txt")
    ifeo_entries = []
    if ifeo_text:
        current_exe = ""
        for line in ifeo_text.splitlines():
            line = line.rstrip("\r")
            if line.startswith("HKLM\\"):
                m = re.search(r"Image File Execution Options\\(.+)", line)
                if m:
                    current_exe = m.group(1).strip()
            m = re.match(r"^\s+Debugger\s+REG_SZ\s+(.*)", line)
            if m and current_exe:
                ifeo_entries.append({
                    "target_exe": current_exe,
                    "debugger": m.group(1).strip(),
                })
    result["ifeo_debuggers"] = ifeo_entries
    lsa_text = _read_or_none(d.parent / "registry_hardening", "lsa.txt")
    lsa_packages = {}
    if lsa_text:
        lsa_vals = _parse_reg_query(lsa_text)
        auth = lsa_vals.get("Authentication Packages", "")
        lsa_packages["authentication_packages"] = [p.strip() for p in auth.split("\0") if p.strip()] if auth else []
        notify = lsa_vals.get("Notification Packages", "")
        lsa_packages["notification_packages"] = [p.strip() for p in notify.split("\0") if p.strip()] if notify else []
        sec = lsa_vals.get("Security Packages", "")
        lsa_packages["security_packages"] = [p.strip() for p in sec.split("\0") if p.strip()] if sec else []
    result["lsa_packages"] = lsa_packages
    result["com_hijacks"] = []
    result["accessibility_binaries"] = []
    result["print_monitors"] = []
    result["sysmon"] = {"installed": False}
    return result


def _assemble_powershell_config(d):
    result = {}
    installed = _parse_reg_query(_read(d / "installed.txt"))
    result["dotnet_versions"] = []
    sbl = _parse_reg_query(_read(d / "scriptblock_logging.txt"))
    result["script_block_logging"] = _to_int(sbl.get("EnableScriptBlockLogging"))
    ml = _parse_reg_query(_read(d / "module_logging.txt"))
    result["module_logging"] = _to_int(ml.get("EnableModuleLogging"))
    tr = _parse_reg_query(_read(d / "transcription.txt"))
    result["transcription"] = _to_int(tr.get("EnableTranscripting"))
    result["amsi_providers"] = []
    result["language_mode"] = ""
    return result


def _assemble_laps_config(d):
    result = {}
    legacy = _parse_reg_query(_read(d / "laps_policy.txt"))
    native = _parse_reg_query(_read(d / "laps_native.txt"))
    new_policy = _parse_reg_query(_read(d / "laps_new_policy.txt"))
    result["available"] = bool(legacy or native or new_policy)
    result["legacy_installed"] = bool(legacy)
    result["windows_laps_installed"] = bool(native or new_policy)
    return result


def _assemble_print_config(d):
    result = {}
    spooler = _read(d / "spooler_service.txt")
    result["spooler_status"] = "Running" if "RUNNING" in spooler else "Stopped"
    pnp = _parse_reg_query(_read(d / "point_and_print.txt"))
    result["point_and_print"] = pnp
    return result


def _assemble_dns_config(d):
    result = {}
    dns_svc = _parse_reg_query(_read(d / "dns_server_params.txt"))
    result["dns_service_running"] = bool(dns_svc)
    result["zones"] = []
    return result


def _assemble_privacy_artifacts(d):
    return {}


def _assemble_disk_storage(d):
    result = {}
    dd_rows = _parse_wmic_csv(_read(d / "diskdrive.csv"))
    physical_disks = []
    for row in dd_rows:
        model = row.get("Model", "")
        if not model:
            continue
        size = row.get("Size", "0")
        try:
            size_gb = round(int(size) / (1024 ** 3), 1) if size else 0
        except (ValueError, TypeError):
            size_gb = 0
        physical_disks.append({
            "model": model,
            "size_gb": size_gb,
            "status": row.get("Status", ""),
            "interface_type": row.get("InterfaceType", ""),
            "media_type": row.get("MediaType", ""),
        })
    result["physical_disks"] = physical_disks
    ld_rows = _parse_wmic_csv(_read(d / "logicaldisk.csv"))
    logical_disks = []
    for row in ld_rows:
        did = row.get("DeviceID", "")
        if not did:
            continue
        size = row.get("Size", "0")
        free = row.get("FreeSpace", "0")
        try:
            size_bytes = int(size) if size else 0
            free_bytes = int(free) if free else 0
            size_gb = round(size_bytes / (1024 ** 3), 1) if size_bytes else 0
            free_gb = round(free_bytes / (1024 ** 3), 1) if free_bytes else 0
            pct_free = round((free_bytes / size_bytes) * 100, 1) if size_bytes else 0
        except (ValueError, TypeError):
            size_gb = free_gb = pct_free = 0
        dt = row.get("DriveType", "")
        dtype = "Fixed" if dt == "3" else "Removable" if dt == "2" else \
                "Network" if dt == "4" else "CD-ROM" if dt == "5" else dt
        logical_disks.append({
            "device_id": did,
            "size_gb": size_gb,
            "free_space_gb": free_gb,
            "percent_free": pct_free,
            "filesystem": row.get("FileSystem", ""),
            "drive_type": dtype,
        })
    result["logical_disks"] = logical_disks
    result["storage_physical_disks"] = []
    result["storage_pools"] = []
    result["virtual_disks"] = []
    result["disks"] = []
    result["hardware_raid"] = {}
    result["raid_controllers"] = []
    result["disk_event_errors"] = []
    return result


def _assemble_hardware_inventory(d):
    result = {}
    mem_rows = _parse_wmic_csv(_read(d / "memory.csv"))
    total_gb = 0
    slot_count = len(mem_rows)
    for row in mem_rows:
        cap = row.get("Capacity", "0")
        try:
            total_gb += int(cap) / (1024 ** 3) if cap else 0
        except (ValueError, TypeError):
            pass
    result["memory_total_gb"] = round(total_gb, 1)
    result["memory_slot_count"] = slot_count
    result["memory_ecc"] = None
    for row in mem_rows:
        ecc = row.get("TotalWidth", "")
        data = row.get("DataWidth", "")
        if ecc and data:
            try:
                result["memory_ecc"] = int(ecc) > int(data)
            except (ValueError, TypeError):
                pass
            break
    result["gpu_adapters"] = []
    result["usb_devices"] = []
    nic_rows = _parse_wmic_csv(_read(d / "nic.csv"))
    result["network_adapters"] = [{"name": r.get("Name", ""),
                                    "mac": r.get("MACAddress", "")} for r in nic_rows if r.get("Name")]
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Meta parser
# ═══════════════════════════════════════════════════════════════════════════

def _parse_meta(cmd_dir):
    meta_text = _read(Path(cmd_dir) / "meta.txt")
    meta = {}
    for line in meta_text.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            meta[key.strip().lower()] = val.strip()
    return meta


def _parse_sections(cmd_dir):
    text = _read(Path(cmd_dir) / "_sections.txt")
    collected = []
    failed = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for sep in ("=", ":"):
            parts = line.split(sep, 1)
            if len(parts) == 2:
                name = parts[0].strip()
                status = parts[1].strip().upper()
                if status in ("OK", "SUCCESS"):
                    collected.append(name)
                else:
                    failed.append(name)
                break
    return collected, failed


# ═══════════════════════════════════════════════════════════════════════════
#  Main entry point
# ═══════════════════════════════════════════════════════════════════════════

_SECTION_ASSEMBLERS = {
    "system_info": _assemble_system_info,
    "windows_update": _assemble_updates,
    "installed_software": _assemble_installed_software,
    "network_config": _assemble_network_config,
    "open_ports": _assemble_open_ports,
    "active_connections": _assemble_active_connections,
    "firewall": _assemble_firewall,
    "processes": _assemble_processes,
    "services": _assemble_services,
    "scheduled_tasks": _assemble_scheduled_tasks,
    "user_accounts": _assemble_user_accounts,
    "security_policy": _assemble_security_policy,
    "registry_hardening": _assemble_registry_hardening,
    "active_directory": _assemble_active_directory,
    "certificates": _assemble_certificates,
    "shares": _assemble_shares,
    "browser_chrome": _assemble_browser,
    "browser_edge": _assemble_browser,
    "browser_firefox": _assemble_browser,
    "server_software": _assemble_server_software,
    "remote_management": _assemble_remote_management,
    "cloud_software": _assemble_cloud_software,
    "event_logs": _assemble_event_logs,
    "startup_items": _assemble_startup_items,
    "bitlocker": _assemble_bitlocker,
    "windows_backup": _assemble_windows_backup,
    "credential_exposure": _assemble_credential_exposure,
    "privilege_escalation": _assemble_privilege_escalation,
    "defender_detailed": _assemble_defender_detailed,
    "adcs": _assemble_adcs,
    "persistence_mechanisms": _assemble_persistence_mechanisms,
    "powershell_config": _assemble_powershell_config,
    "laps_config": _assemble_laps_config,
    "print_config": _assemble_print_config,
    "dns_config": _assemble_dns_config,
    "privacy_artifacts": _assemble_privacy_artifacts,
    "disk_storage": _assemble_disk_storage,
    "hardware_inventory": _assemble_hardware_inventory,
}


def assemble(cmd_dir):
    """Convert a CMD collection directory into the same JSON dict structure
    that dredge_collect.ps1 produces."""
    base = Path(cmd_dir)
    if not base.is_dir():
        raise FileNotFoundError(f"CMD collection directory not found: {cmd_dir}")

    meta = _parse_meta(cmd_dir)
    collected, failed = _parse_sections(cmd_dir)

    output = {
        "dredge_version": meta.get("version", ""),
        "collection_timestamp": meta.get("start_time", ""),
        "collection_completed": meta.get("end_time", ""),
        "collection_duration_seconds": 0,
        "hostname": meta.get("hostname", ""),
        "fqdn": meta.get("hostname", ""),
        "collector_user": meta.get("user", ""),
        "collector_is_admin": False,
        "collector_method": "cmd",
        "sections_collected": collected,
        "sections_skipped": [],
        "sections_failed": failed,
        "section_errors": [],
    }

    try:
        start = meta.get("start_time", "")
        end = meta.get("end_time", "")
        if start and end:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y%m%d_%H%M%S"):
                try:
                    t0 = datetime.strptime(start, fmt)
                    t1 = datetime.strptime(end, fmt)
                    output["collection_duration_seconds"] = round((t1 - t0).total_seconds(), 2)
                    break
                except ValueError:
                    continue
    except Exception:
        pass

    _DIR_ALIASES = {"windows_update": "updates"}

    for section_name, assembler_fn in _SECTION_ASSEMBLERS.items():
        dir_name = _DIR_ALIASES.get(section_name, section_name)
        section_dir = base / dir_name
        if not section_dir.is_dir():
            output[section_name] = {} if section_name not in (
                "installed_software", "processes", "services",
                "open_ports", "active_connections", "certificates",
                "startup_items", "scheduled_tasks", "shares",
            ) else []
            continue
        try:
            output[section_name] = assembler_fn(section_dir)
        except Exception as e:
            output[section_name] = {"error": str(e)}
            if section_name not in output.get("sections_failed", []):
                output.setdefault("section_errors", []).append({
                    "section": section_name,
                    "error": str(e),
                })

    return output


def assemble_to_json(cmd_dir, output_path=None):
    """Assemble and optionally write to a JSON file. Returns the dict."""
    data = assemble(cmd_dir)
    if output_path:
        Path(output_path).write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
    return data


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cmd_collection_dir> [output.json]")
        sys.exit(1)
    out = sys.argv[2] if len(sys.argv) > 2 else None
    data = assemble_to_json(sys.argv[1], out)
    if not out:
        print(json.dumps(data, indent=2, default=str))
