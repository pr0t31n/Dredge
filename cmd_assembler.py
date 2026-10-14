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
    try:
        raw = p.read_bytes()
        if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
            return raw.decode('utf-16', errors='replace')
    except Exception:
        pass
    raw = p.read_bytes()
    if raw[:2] == b"\xff\xfe" or raw[:2] == b"\xfe\xff":
        try:
            return raw.decode("utf-16", errors="replace")
        except Exception:
            pass
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


def _parse_auditpol(text):
    result = {}
    category = None
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line.strip():
            continue
        if line.startswith("System audit policy") or line.startswith("Category/Subcategory"):
            continue
        if not line.startswith(" ") and not line.startswith("\t"):
            category = line.strip()
            if category and category not in result:
                result[category] = {}
        elif category:
            stripped = line.strip()
            for setting in ("Success and Failure", "Success", "Failure", "No Auditing"):
                if stripped.endswith(setting):
                    subcat = stripped[: -len(setting)].strip()
                    if subcat:
                        result[category][subcat] = setting
                    break
    return result


def _parse_secedit_inf(text):
    sections = {}
    current_section = None
    for line in text.splitlines():
        line = line.rstrip("\r").strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            if current_section not in sections:
                sections[current_section] = {}
            continue
        if current_section and "=" in line:
            key, _, val = line.partition("=")
            sections[current_section][key.strip()] = val.strip()
    return sections


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
    secedit = _read(d / "secedit_export.inf") if (d / "secedit_export.inf").exists() else ""
    if secedit:
        sections = _parse_secedit_inf(secedit)
        result["user_rights_assignment"] = sections.get("Privilege Rights", {})
        result["system_access"] = sections.get("System Access", {})
        result["event_audit"] = sections.get("Event Audit", {})
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
    # Additional UAC settings (CIS 2.3.17)
    result["EnableInstallerDetection"] = _to_int(uac.get("EnableInstallerDetection"))
    result["FilterAdministratorToken"] = _to_int(uac.get("FilterAdministratorToken"))
    result["PromptOnSecureDesktop"] = _to_int(uac.get("PromptOnSecureDesktop"))
    result["ValidateAdminCodeSignatures"] = _to_int(uac.get("ValidateAdminCodeSignatures"))
    result["EnableSecureUIAPaths"] = _to_int(uac.get("EnableSecureUIAPaths"))
    result["EnableVirtualization"] = _to_int(uac.get("EnableVirtualization"))
    result["ConsentPromptBehaviorUser"] = _to_int(uac.get("ConsentPromptBehaviorUser"))
    # Additional LSA settings (CIS 2.3.10, STIG)
    result["RestrictAnonymousSAM"] = _to_int(lsa.get("RestrictAnonymousSAM"))
    result["EveryoneIncludesAnonymous"] = _to_int(lsa.get("EveryoneIncludesAnonymous"))
    result["ForceGuest"] = _to_int(lsa.get("ForceGuest"))
    result["DisableDomainCreds"] = _to_int(lsa.get("DisableDomainCreds"))
    result["LimitBlankPasswordUse"] = _to_int(lsa.get("LimitBlankPasswordUse"))
    result["SCENoApplyLegacyAuditPolicy"] = _to_int(lsa.get("SCENoApplyLegacyAuditPolicy"))
    # SMB Server additional (CIS 2.3.8)
    result["AutoDisconnect"] = _to_int(smb_server.get("AutoDisconnect"))
    result["SMBServer_EnableSecuritySignature"] = _to_int(smb_server.get("EnableSecuritySignature"))
    result["NullSessionShares"] = smb_server.get("NullSessionShares", "")
    result["RestrictNullSessAccess"] = _to_int(smb_server.get("RestrictNullSessAccess"))
    # SMB Client (CIS 2.3.8)
    smb_client = _parse_reg_query(_read(d / "smb_client.txt"))
    result["SMBClient_RequireSecuritySignature"] = _to_int(smb_client.get("RequireSecuritySignature"))
    result["SMBClient_EnableSecuritySignature"] = _to_int(smb_client.get("EnableSecuritySignature"))
    result["SMBClient_EnablePlainTextPassword"] = _to_int(smb_client.get("EnablePlainTextPassword"))
    # RDP additional (CIS 18.9.65, STIG)
    result["MinEncryptionLevel"] = _to_int(rdp_tcp.get("MinEncryptionLevel"))
    result["SecurityLayer"] = _to_int(rdp_tcp.get("SecurityLayer"))
    # Audit policy (structured) — lives in security_policy/, not registry_hardening/
    sp_dir = d.parent / "security_policy"
    auditpol_path = sp_dir / "auditpol.txt" if sp_dir.is_dir() else d / "auditpol.txt"
    auditpol = _read(auditpol_path) if auditpol_path.exists() else ""
    if auditpol:
        result["audit_policy_raw"] = auditpol
        result["audit_policy"] = _parse_auditpol(auditpol)
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
        bps = row.get("BytesPerSector", "")
        try:
            bps_int = int(bps) if bps else None
        except (ValueError, TypeError):
            bps_int = None
        parts = row.get("Partitions", "")
        try:
            parts_int = int(parts) if parts else 0
        except (ValueError, TypeError):
            parts_int = 0
        physical_disks.append({
            "model": model,
            "size_gb": size_gb,
            "status": row.get("Status", ""),
            "interface_type": row.get("InterfaceType", ""),
            "media_type": row.get("MediaType", ""),
            "device_id": row.get("DeviceID", ""),
            "serial_number": row.get("Signature", ""),
            "firmware_revision": row.get("FirmwareRevision", ""),
            "bytes_per_sector": bps_int,
            "partitions_count": parts_int,
            "scsi_bus": row.get("SCSIBus", ""),
            "scsi_port": row.get("SCSIPort", ""),
            "scsi_target": row.get("SCSITargetId", ""),
            "index": row.get("Index", ""),
            "manufacturer": row.get("Manufacturer", ""),
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
            "volume_name": row.get("VolumeName", ""),
            "volume_serial": row.get("VolumeSerialNumber", ""),
            "provider": row.get("ProviderName", ""),
            "compressed": row.get("Compressed", "").upper() == "TRUE",
        })
    result["logical_disks"] = logical_disks

    part_rows = _parse_wmic_csv(_read(d / "partitions.csv"))
    partitions = []
    for row in part_rows:
        dev = row.get("DeviceID", "")
        if not dev:
            continue
        all_vals = " ".join(str(v) for v in row.values())
        dm = re.search(r"Disk\s*#(\d+)", all_vals)
        pm = re.search(r"Partition\s*#(\d+)", all_vals)
        di_int = int(dm.group(1)) if dm else None
        pi_int = int(pm.group(1)) if pm else None
        size_candidates = []
        for v in row.values():
            try:
                iv = int(v)
                if iv > 100_000_000:
                    size_candidates.append(iv)
            except (ValueError, TypeError):
                pass
        psize_gb = 0
        if size_candidates:
            psize_gb = round(max(size_candidates) / (1024 ** 3), 1)
        partitions.append({
            "device_id": f"Disk #{di_int}, Partition #{pi_int}"
                if di_int is not None and pi_int is not None else dev,
            "disk_index": di_int,
            "partition_index": pi_int,
            "size_gb": psize_gb,
            "bootable": "TRUE" in (row.get("Bootable", "") + row.get("BootPartition", "")).upper()
                and "BOOT" in all_vals.upper(),
            "boot_partition": row.get("BootPartition", "").upper() == "TRUE",
            "primary_partition": row.get("PrimaryPartition", "").upper() == "TRUE",
            "type": row.get("Description", row.get("Type", "")),
            "description": row.get("Description", ""),
        })
    result["partitions"] = partitions

    vol_rows = _parse_wmic_csv(_read(d / "volume.csv"))
    volumes = []
    for row in vol_rows:
        dev = row.get("DeviceID", "")
        if not dev:
            continue
        vcap = row.get("Capacity", "0")
        vfree = row.get("FreeSpace", "0")
        try:
            vcap_bytes = int(vcap) if vcap else 0
            vfree_bytes = int(vfree) if vfree else 0
            vcap_gb = round(vcap_bytes / (1024 ** 3), 1) if vcap_bytes else 0
            vfree_gb = round(vfree_bytes / (1024 ** 3), 1) if vfree_bytes else 0
        except (ValueError, TypeError):
            vcap_gb = vfree_gb = 0
        volumes.append({
            "device_id": dev,
            "drive_letter": row.get("DriveLetter", ""),
            "capacity_gb": vcap_gb,
            "free_space_gb": vfree_gb,
            "filesystem": row.get("FileSystem", ""),
            "label": row.get("Label", ""),
            "dirty_bit": row.get("DirtyBitSet", "").upper() == "TRUE",
            "serial_number": row.get("SerialNumber", ""),
            "compressed": row.get("Compressed", "").upper() == "TRUE",
            "automount": row.get("Automount", "").upper() == "TRUE",
        })
    result["volumes"] = volumes

    result["storage_physical_disks"] = []
    result["storage_pools"] = []
    result["virtual_disks"] = []
    result["disks"] = []
    result["hardware_raid"] = {}
    result["raid_controllers"] = []

    disk_events = []
    for evt_file in ("disk_error_events.txt", "disk_events.txt"):
        evt_text = _read(d / evt_file)
        if evt_text:
            parsed = _parse_wevtutil_text(evt_text)
            for ev in parsed:
                if isinstance(ev, dict) and ev not in disk_events:
                    prov = str(ev.get("source", ev.get("provider_name", ""))).lower()
                    eid = ev.get("event_id", "")
                    ev["provider"] = prov if prov else str(ev.get("provider", ""))
                    ev["id"] = eid
                    ev["message"] = ev.get("description", ev.get("message", ""))
                    disk_events.append(ev)
    result["disk_event_errors"] = disk_events

    raid_txt = _read(d / "raid_controller.txt")
    if raid_txt and "ERROR" not in raid_txt[:100].upper():
        result["hardware_raid"]["detected_cli"] = "omreport"
        result["hardware_raid"]["raw_output"] = raid_txt[:5000]
    mega_txt = _read(d / "megacli_vdisk.txt")
    if mega_txt and "ERROR" not in mega_txt[:100].upper():
        result["hardware_raid"]["detected_cli"] = "MegaCli64"
        result["hardware_raid"]["raw_output"] = mega_txt[:5000]
    perc_txt = _read(d / "perccli_controller.txt")
    if perc_txt and "ERROR" not in perc_txt[:100].upper():
        result["hardware_raid"]["detected_cli"] = "perccli64"
        result["hardware_raid"]["raw_output"] = perc_txt[:5000]
    stor_txt = _read(d / "storcli_controller.txt")
    if stor_txt and "ERROR" not in stor_txt[:100].upper():
        result["hardware_raid"]["detected_cli"] = "storcli64"
        result["hardware_raid"]["raw_output"] = stor_txt[:5000]

    return result


def _parse_compliance_data(d):
    """Parse compliance_data section files into a structured dict.

    Each file contains concatenated reg query output for a compliance category.
    REG_DWORD values are converted to int; REG_SZ / REG_EXPAND_SZ stay as str.
    """
    result = {}

    def _typed_val(raw_val, reg_type):
        """Convert a raw registry value string to int (DWORD) or str."""
        if reg_type == "REG_DWORD":
            raw_val = raw_val.strip()
            try:
                if raw_val.startswith("0x"):
                    return int(raw_val, 16)
                return int(raw_val)
            except (ValueError, TypeError):
                return raw_val
        return raw_val

    def _extract_values(text):
        """Parse reg query output into {ValueName: typed_value}."""
        vals = {}
        for line in text.splitlines():
            line = line.rstrip("\r")
            m = re.match(r"^\s+(\S+)\s+(REG_\w+)\s+(.*)", line)
            if m:
                name = m.group(1)
                rtype = m.group(2)
                rval = m.group(3).strip()
                vals[name] = _typed_val(rval, rtype)
        return vals

    def _extract_values_recursive(text):
        """Parse recursive reg query output (/s) into a flat dict of all values."""
        vals = {}
        for line in text.splitlines():
            line = line.rstrip("\r")
            m = re.match(r"^\s+(\S+)\s+(REG_\w+)\s+(.*)", line)
            if m:
                name = m.group(1)
                rtype = m.group(2)
                rval = m.group(3).strip()
                vals[name] = _typed_val(rval, rtype)
        return vals

    # --- Screensaver (CIS 18.9.11) ---
    ss_text = _read(d / "screensaver.txt")
    ss = _extract_values(ss_text)
    result["screensaver"] = {
        "ScreenSaveActive": ss.get("ScreenSaveActive"),
        "ScreenSaverIsSecure": ss.get("ScreenSaverIsSecure"),
        "ScreenSaveTimeOut": ss.get("ScreenSaveTimeOut"),
    }

    # --- Interactive Logon / Banner (CIS 2.3.7) ---
    lb_text = _read(d / "logon_banner.txt")
    lb = _extract_values(lb_text)
    result["logon_banner"] = {
        "LegalNoticeCaption": lb.get("LegalNoticeCaption"),
        "LegalNoticeText": lb.get("LegalNoticeText"),
        "InactivityTimeoutSecs": lb.get("InactivityTimeoutSecs"),
        "DontDisplayLastUserName": lb.get("DontDisplayLastUserName"),
        "ScForceOption": lb.get("ScForceOption"),
    }

    # --- MSS Settings (CIS 18.4) ---
    mss_text = _read(d / "mss_settings.txt")
    mss = _extract_values(mss_text)
    result["mss_settings"] = {
        "DisableIPSourceRouting": mss.get("DisableIPSourceRouting"),
        "EnableICMPRedirect": mss.get("EnableICMPRedirect"),
        "NodeType": mss.get("NodeType"),
        "NoNameReleaseOnDemand": mss.get("NoNameReleaseOnDemand"),
        "PerformRouterDiscovery": mss.get("PerformRouterDiscovery"),
        "KeepAliveTime": mss.get("KeepAliveTime"),
        "EnableDeadGWDetect": mss.get("EnableDeadGWDetect"),
        "TcpMaxDataRetransmissions": mss.get("TcpMaxDataRetransmissions"),
    }

    # --- Network Security (CIS 2.3.11) ---
    ns_text = _read(d / "network_security.txt")
    ns = _extract_values(ns_text)
    result["network_security"] = {
        "NTLMMinClientSec": ns.get("NTLMMinClientSec"),
        "NTLMMinServerSec": ns.get("NTLMMinServerSec"),
        "RequireSignOrSeal": ns.get("RequireSignOrSeal"),
        "SealSecureChannel": ns.get("SealSecureChannel"),
        "SignSecureChannel": ns.get("SignSecureChannel"),
        "RequireStrongKey": ns.get("RequireStrongKey"),
    }

    # --- Remote Assistance (CIS 18.8.36) ---
    ra_text = _read(d / "remote_assistance.txt")
    ra = _extract_values(ra_text)
    result["remote_assistance"] = {
        "fAllowToGetHelp": ra.get("fAllowToGetHelp"),
        "fAllowFullControl": ra.get("fAllowFullControl"),
    }

    # --- Shutdown Settings (CIS 2.3.13) ---
    sd_text = _read(d / "shutdown.txt")
    sd = _extract_values(sd_text)
    result["shutdown"] = {
        "ShutdownWithoutLogon": sd.get("ShutdownWithoutLogon"),
        "ClearPageFileAtShutdown": sd.get("ClearPageFileAtShutdown"),
    }

    # --- Print Spooler (CIS 18.4.8) ---
    ps_text = _read(d / "print_spooler.txt")
    ps = _extract_values(ps_text)
    result["print_spooler"] = {
        "DisableWebPnPDownload": ps.get("DisableWebPnPDownload"),
        "DisableHTTPPrinting": ps.get("DisableHTTPPrinting"),
    }

    # --- AutoPlay Detailed (CIS 18.9.8) ---
    ap_text = _read(d / "autoplay.txt")
    ap = _extract_values(ap_text)
    result["autoplay"] = {
        "NoDriveTypeAutoRun": ap.get("NoDriveTypeAutoRun"),
        "NoAutorun": ap.get("NoAutorun"),
        "NoAutoplayfornonVolume": ap.get("NoAutoplayfornonVolume"),
    }

    # --- WinRM Security (CIS 18.9.102) ---
    winrm_client_text = _read(d / "winrm_client.txt")
    winrm_service_text = _read(d / "winrm_service.txt")
    winrm = {}
    winrm["client"] = _extract_values_recursive(winrm_client_text)
    winrm["service"] = _extract_values_recursive(winrm_service_text)
    result["winrm_security"] = winrm

    # --- AppLocker / SRP (STIG) ---
    srp_text = _read(d / "applocker_srp.txt")
    result["applocker_srp"] = _extract_values_recursive(srp_text)

    return result


def _assemble_hardware_inventory(d):
    _ARCH_MAP = {"0": "x86", "5": "ARM", "6": "IA-64", "9": "x64"}
    _MEM_TYPE = {
        "0": "Unknown", "1": "Other", "2": "DRAM", "3": "Sync DRAM",
        "4": "Cache DRAM", "5": "EDO", "6": "EDRAM", "7": "VRAM",
        "8": "SRAM", "9": "RAM", "10": "ROM", "11": "Flash",
        "12": "EEPROM", "13": "FEPROM", "14": "EPROM", "15": "CDRAM",
        "16": "3DRAM", "17": "SDRAM", "18": "SGRAM", "19": "RDRAM",
        "20": "DDR", "21": "DDR2", "22": "DDR2 FB-DIMM",
        "24": "DDR3", "26": "DDR4", "30": "LPDDR4", "34": "DDR5",
    }
    _FORM_FACTOR = {
        "0": "Unknown", "1": "Other", "2": "SIP", "3": "DIP",
        "4": "ZIP", "5": "SOJ", "6": "Proprietary", "7": "SIMM",
        "8": "DIMM", "9": "TSOP", "10": "PGA", "11": "RIMM",
        "12": "SODIMM", "13": "SRIMM", "14": "SMD", "15": "SSMP",
        "16": "QFP", "17": "TQFP", "18": "SOIC", "19": "LCC",
        "20": "PLCC", "21": "BGA", "22": "FPBGA", "23": "LGA",
    }

    result = {}

    bb_rows = _parse_wmic_csv(_read(d / "baseboard.csv"))
    if bb_rows:
        row = bb_rows[0]
        result["baseboard"] = {
            "manufacturer": row.get("Manufacturer", ""),
            "product": row.get("Product", ""),
            "serial_number": row.get("SerialNumber", ""),
            "version": row.get("Version", ""),
            "status": row.get("Status", ""),
            "model": row.get("Model", ""),
        }
    else:
        result["baseboard"] = None

    bios_rows = _parse_wmic_csv(_read(d / "bios.csv"))
    if bios_rows:
        row = bios_rows[0]
        result["bios"] = {
            "manufacturer": row.get("Manufacturer", ""),
            "name": row.get("Name", ""),
            "version": row.get("Version", ""),
            "release_date": row.get("ReleaseDate", ""),
            "serial_number": row.get("SerialNumber", ""),
            "smbios_version": row.get("SMBIOSBIOSVersion", ""),
            "status": row.get("Status", ""),
        }
    else:
        result["bios"] = None

    cpu_rows = _parse_wmic_csv(_read(d / "cpu.csv"))
    processors = []
    for row in cpu_rows:
        name = row.get("Name", "")
        if not name:
            continue
        cores = row.get("NumberOfCores", "")
        lp = row.get("NumberOfLogicalProcessors", "")
        mcs = row.get("MaxClockSpeed", "")
        l2 = row.get("L2CacheSize", "")
        l3 = row.get("L3CacheSize", "")
        arch_code = row.get("Architecture", "")
        try:
            cores_int = int(cores) if cores else None
        except (ValueError, TypeError):
            cores_int = None
        try:
            lp_int = int(lp) if lp else None
        except (ValueError, TypeError):
            lp_int = None
        try:
            mcs_int = int(mcs) if mcs else None
        except (ValueError, TypeError):
            mcs_int = None
        try:
            l2_int = int(l2) if l2 else None
        except (ValueError, TypeError):
            l2_int = None
        try:
            l3_int = int(l3) if l3 else None
        except (ValueError, TypeError):
            l3_int = None
        processors.append({
            "name": name.strip(),
            "cores": cores_int,
            "logical_processors": lp_int,
            "max_clock_speed_mhz": mcs_int,
            "architecture": _ARCH_MAP.get(arch_code, arch_code),
            "socket": row.get("SocketDesignation", ""),
            "manufacturer": row.get("Manufacturer", ""),
            "l2_cache_kb": l2_int,
            "l3_cache_kb": l3_int,
            "virtualization_enabled": row.get(
                "VirtualizationFirmwareEnabled", "").upper() == "TRUE",
            "status": row.get("Status", ""),
            "device_id": row.get("DeviceID", ""),
            "current_clock_speed_mhz": mcs_int,
        })
    result["processors"] = processors

    mem_rows = _parse_wmic_csv(_read(d / "memory.csv"))
    total_gb = 0
    slot_count = len(mem_rows)
    memory_modules = []
    for row in mem_rows:
        cap = row.get("Capacity", "0")
        try:
            cap_bytes = int(cap) if cap else 0
            total_gb += cap_bytes / (1024 ** 3)
            cap_gb = round(cap_bytes / (1024 ** 3), 1)
        except (ValueError, TypeError):
            cap_gb = 0
        spd = row.get("Speed", "")
        try:
            spd_int = int(spd) if spd else None
        except (ValueError, TypeError):
            spd_int = None
        mt = row.get("MemoryType", "")
        ff = row.get("FormFactor", "")
        mfr = row.get("Manufacturer", "")
        if mfr:
            mfr = mfr.strip()
        memory_modules.append({
            "bank_label": row.get("BankLabel", ""),
            "device_locator": row.get("DeviceLocator", "").strip(),
            "capacity_gb": cap_gb,
            "speed_mhz": spd_int,
            "memory_type": _MEM_TYPE.get(mt, mt),
            "form_factor": _FORM_FACTOR.get(ff, ff),
            "manufacturer": mfr,
            "part_number": row.get("PartNumber", "").strip(),
            "serial_number": row.get("SerialNumber", ""),
        })
    result["memory_total_gb"] = round(total_gb, 1)
    result["memory_slot_count"] = slot_count
    result["memory_modules"] = memory_modules
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

    gpu_rows = _parse_wmic_csv(_read(d / "gpu.csv"))
    gpu_adapters = []
    for row in gpu_rows:
        name = row.get("Name", "")
        if not name:
            continue
        vram = row.get("AdapterRAM", "0")
        try:
            vram_gb = round(int(vram) / (1024 ** 3), 1) if vram else 0
        except (ValueError, TypeError):
            vram_gb = 0
        hres = row.get("CurrentHorizontalResolution", "")
        vres = row.get("CurrentVerticalResolution", "")
        res = f"{hres}x{vres}" if hres and vres else ""
        gpu_adapters.append({
            "name": name,
            "adapter_ram_gb": vram_gb,
            "driver_version": row.get("DriverVersion", ""),
            "driver_date": row.get("DriverDate", ""),
            "status": row.get("Status", ""),
            "current_resolution": res,
        })
    result["gpu_adapters"] = gpu_adapters

    usb_rows = _parse_wmic_csv(_read(d / "usb.csv"))
    usb_devices = []
    for row in usb_rows:
        name = row.get("Name", "")
        if not name:
            continue
        usb_devices.append({
            "name": name,
            "device_id": row.get("DeviceID", ""),
            "manufacturer": row.get("Manufacturer", ""),
            "status": row.get("Status", ""),
            "class": row.get("ClassGuid", ""),
        })
    result["usb_devices"] = usb_devices

    nic_rows = _parse_wmic_csv(_read(d / "nic.csv"))
    network_adapters = []
    for r in nic_rows:
        name = r.get("Name", "")
        if not name:
            continue
        spd = r.get("Speed", "")
        try:
            spd_mbps = round(int(spd) / 1_000_000) if spd else None
        except (ValueError, TypeError):
            spd_mbps = None
        mac = r.get("MACAddress", "")
        network_adapters.append({
            "name": name,
            "mac": mac,
            "mac_address": mac,
            "speed_mbps": spd_mbps,
            "adapter_type": r.get("AdapterType", ""),
            "manufacturer": r.get("Manufacturer", ""),
            "status": r.get("Status", ""),
            "net_connection_id": r.get("NetConnectionID", ""),
            "service_name": r.get("ServiceName", ""),
        })
    result["network_adapters"] = network_adapters

    scsi_rows = _parse_wmic_csv(_read(d / "scsi.csv"))
    scsi_controllers = []
    for row in scsi_rows:
        name = row.get("Name", "")
        if not name:
            continue
        scsi_controllers.append({
            "name": name,
            "manufacturer": row.get("Manufacturer", ""),
            "driver_name": row.get("DriverName", ""),
            "status": row.get("Status", ""),
        })
    result["scsi_controllers"] = scsi_controllers

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
    "compliance_data": _parse_compliance_data,
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
