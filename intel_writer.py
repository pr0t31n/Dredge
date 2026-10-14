"""Write per-domain intelligence JSON files for Crucible v2 panels."""
import json
from pathlib import Path


def _safe(v):
    if v is None:
        return ""
    return v


def _build_disk_storage_report(data):
    ds = data.get("disk_storage", {})
    if not ds:
        return None

    report = {
        "physical_disks": [],
        "logical_disks": [],
        "storage_spaces": {
            "pools": [],
            "virtual_disks": [],
        },
        "hardware_raid": None,
        "controllers": [],
        "raid_summary": [],
    }

    for d in ds.get("physical_disks", []):
        if not isinstance(d, dict):
            continue
        report["physical_disks"].append({
            "device": _safe(d.get("device_id")),
            "model": _safe(d.get("model")),
            "size_gb": d.get("size_gb", 0),
            "interface": _safe(d.get("interface_type")),
            "media": _safe(d.get("media_type")),
            "status": _safe(d.get("status")),
            "serial": _safe(d.get("serial_number")),
            "firmware": _safe(d.get("firmware_revision")),
        })

    for d in ds.get("logical_disks", []):
        if not isinstance(d, dict):
            continue
        report["logical_disks"].append({
            "drive": _safe(d.get("device_id")),
            "filesystem": _safe(d.get("file_system")),
            "size_gb": d.get("size_gb", 0),
            "free_gb": d.get("free_gb", 0),
            "percent_free": d.get("percent_free", 0),
            "volume": _safe(d.get("volume_name")),
            "type": _safe(d.get("drive_type")),
        })

    for p in ds.get("storage_pools", []):
        if not isinstance(p, dict):
            continue
        pool_entry = {
            "name": _safe(p.get("friendly_name")),
            "health": _safe(p.get("health_status")),
            "operational_status": _safe(p.get("operational_status")),
            "size_gb": p.get("size_gb", 0),
            "allocated_gb": p.get("allocated_size_gb", 0),
            "disks": [],
        }
        for pd in p.get("physical_disks", []):
            if isinstance(pd, dict):
                pool_entry["disks"].append({
                    "name": _safe(pd.get("friendly_name")),
                    "health": _safe(pd.get("health_status")),
                    "status": _safe(pd.get("operational_status")),
                    "usage": _safe(pd.get("usage")),
                    "media": _safe(pd.get("media_type")),
                    "size_gb": pd.get("size_gb", 0),
                })
        report["storage_spaces"]["pools"].append(pool_entry)

    for v in ds.get("virtual_disks", []):
        if not isinstance(v, dict):
            continue
        report["storage_spaces"]["virtual_disks"].append({
            "name": _safe(v.get("friendly_name")),
            "health": _safe(v.get("health_status")),
            "operational_status": _safe(v.get("operational_status")),
            "size_gb": v.get("size_gb", 0),
            "raid_level": _safe(v.get("raid_level")),
            "resiliency": _safe(v.get("resiliency_setting")),
            "columns": v.get("number_of_columns"),
            "disk_redundancy": v.get("physical_disk_redundancy"),
            "data_copies": v.get("number_of_data_copies"),
        })
        report["raid_summary"].append({
            "source": "Storage Spaces",
            "name": _safe(v.get("friendly_name")),
            "raid_level": _safe(v.get("raid_level")),
            "size_gb": v.get("size_gb", 0),
            "health": _safe(v.get("health_status")),
            "status": _safe(v.get("operational_status")),
        })

    hw_raid = ds.get("hardware_raid", {})
    if isinstance(hw_raid, dict) and hw_raid.get("detected_cli"):
        report["hardware_raid"] = {
            "cli": _safe(hw_raid.get("detected_cli")),
            "controller": _safe(hw_raid.get("controller")),
            "virtual_drives": [],
        }
        for vd in hw_raid.get("virtual_drives", []):
            if not isinstance(vd, dict):
                continue
            entry = {
                "vd": _safe(vd.get("vd")),
                "raid_level": _safe(vd.get("raid_level")),
                "state": _safe(vd.get("state")),
                "size": _safe(vd.get("size")),
                "source_cli": _safe(vd.get("source_cli")),
            }
            if vd.get("name"):
                entry["name"] = vd["name"]
            report["hardware_raid"]["virtual_drives"].append(entry)
            report["raid_summary"].append({
                "source": f"Hardware ({_safe(vd.get('source_cli'))})",
                "name": _safe(vd.get("name", f"VD {vd.get('vd', '?')}")),
                "raid_level": _safe(vd.get("raid_level")),
                "size_gb": _safe(vd.get("size")),
                "health": _safe(vd.get("state")),
                "status": _safe(vd.get("state")),
            })

    for c in ds.get("raid_controllers", []):
        if isinstance(c, dict):
            report["controllers"].append({
                "name": _safe(c.get("name")),
                "manufacturer": _safe(c.get("manufacturer")),
                "driver": _safe(c.get("driver_name")),
                "status": _safe(c.get("status")),
            })

    spd = ds.get("storage_physical_disks", [])
    if spd:
        report["storage_module_disks"] = []
        for d in spd:
            if not isinstance(d, dict):
                continue
            report["storage_module_disks"].append({
                "name": _safe(d.get("friendly_name")),
                "serial": _safe(d.get("serial_number")),
                "media": _safe(d.get("media_type")),
                "size_gb": d.get("size_gb", 0),
                "health": _safe(d.get("health_status")),
                "status": _safe(d.get("operational_status")),
                "usage": _safe(d.get("usage")),
                "bus": _safe(d.get("bus_type")),
                "can_pool": d.get("can_pool"),
            })

    disk_events = ds.get("disk_event_errors", [])
    if disk_events:
        report["disk_event_errors"] = []
        for ev in disk_events:
            if isinstance(ev, dict):
                report["disk_event_errors"].append({
                    "time": _safe(ev.get("time")),
                    "provider": _safe(ev.get("provider")),
                    "event_id": ev.get("id"),
                    "level": _safe(ev.get("level")),
                    "message": _safe(ev.get("message")),
                })
        report["disk_event_error_count"] = len(report["disk_event_errors"])

    return report


def _build_hardware_report(data):
    hw = data.get("hardware_inventory", {})
    if not hw:
        return None

    report = {
        "baseboard": None,
        "processors": [],
        "memory": {
            "total_gb": hw.get("memory_total_gb", 0),
            "slot_count": hw.get("memory_slot_count", 0),
            "ecc": hw.get("memory_ecc"),
            "modules": [],
        },
        "gpu_adapters": [],
        "network_adapters": [],
        "usb_devices": [],
        "pci_devices": [],
        "batteries": [],
        "power_plan": hw.get("active_power_plan"),
    }

    bb = hw.get("baseboard")
    if isinstance(bb, dict):
        report["baseboard"] = {
            "manufacturer": _safe(bb.get("manufacturer")),
            "product": _safe(bb.get("product")),
            "serial": _safe(bb.get("serial_number")),
            "version": _safe(bb.get("version")),
            "status": _safe(bb.get("status")),
        }

    for cpu in hw.get("processors", []):
        if not isinstance(cpu, dict):
            continue
        report["processors"].append({
            "name": _safe(cpu.get("name")),
            "cores": cpu.get("cores"),
            "logical_processors": cpu.get("logical_processors"),
            "max_clock_mhz": cpu.get("max_clock_speed_mhz"),
            "architecture": _safe(cpu.get("architecture")),
            "socket": _safe(cpu.get("socket")),
            "manufacturer": _safe(cpu.get("manufacturer")),
            "l2_cache_kb": cpu.get("l2_cache_kb"),
            "l3_cache_kb": cpu.get("l3_cache_kb"),
            "virtualization": cpu.get("virtualization_enabled"),
        })

    for m in hw.get("memory_modules", []):
        if not isinstance(m, dict):
            continue
        report["memory"]["modules"].append({
            "bank": _safe(m.get("bank_label")),
            "locator": _safe(m.get("device_locator")),
            "capacity_gb": m.get("capacity_gb", 0),
            "speed_mhz": m.get("speed_mhz"),
            "type": _safe(m.get("memory_type")),
            "manufacturer": _safe(m.get("manufacturer")),
            "part_number": _safe(m.get("part_number")),
        })

    for g in hw.get("gpu_adapters", []):
        if not isinstance(g, dict):
            continue
        report["gpu_adapters"].append({
            "name": _safe(g.get("name")),
            "vram_gb": g.get("adapter_ram_gb", 0),
            "driver_version": _safe(g.get("driver_version")),
            "driver_date": _safe(g.get("driver_date")),
            "status": _safe(g.get("status")),
            "resolution": _safe(g.get("current_resolution")),
        })

    for n in hw.get("network_adapters", []):
        if not isinstance(n, dict):
            continue
        report["network_adapters"].append({
            "name": _safe(n.get("name")),
            "mac": _safe(n.get("mac_address")),
            "speed_mbps": n.get("speed_mbps"),
            "type": _safe(n.get("adapter_type")),
            "manufacturer": _safe(n.get("manufacturer")),
        })

    for u in hw.get("usb_devices", []):
        if isinstance(u, dict):
            report["usb_devices"].append({
                "name": _safe(u.get("name")),
                "class": _safe(u.get("class")),
                "manufacturer": _safe(u.get("manufacturer")),
                "status": _safe(u.get("status")),
            })

    for p in hw.get("pci_devices", []):
        if isinstance(p, dict):
            report["pci_devices"].append({
                "name": _safe(p.get("name")),
                "class": _safe(p.get("class")),
                "manufacturer": _safe(p.get("manufacturer")),
                "status": _safe(p.get("status")),
            })

    for b in hw.get("batteries", []):
        if isinstance(b, dict):
            report["batteries"].append({
                "name": _safe(b.get("name")),
                "status": _safe(b.get("status")),
                "charge_pct": b.get("estimated_charge"),
                "battery_status": _safe(b.get("battery_status")),
                "chemistry": _safe(b.get("chemistry")),
            })

    return report


def _build_endpoint_status(data):
    si = data.get("system_info", {})
    if not isinstance(si, dict) or not si:
        return None
    dd = data.get("defender_detailed", {})
    av = dd.get("av_products", []) if isinstance(dd, dict) else []
    pe = data.get("privilege_escalation", {})
    return {
        "hostname": _safe(data.get("hostname") or si.get("hostname")),
        "os_name": _safe(si.get("os_name")),
        "os_version": _safe(si.get("os_version")),
        "os_build": si.get("os_build", 0),
        "os_product_type": _safe(si.get("os_product_type")),
        "domain_joined": si.get("is_domain_joined", False),
        "domain_name": _safe(si.get("domain")),
        "domain_role": _safe(si.get("domain_role")),
        "uptime_days": si.get("uptime_days", 0),
        "bios_version": _safe(si.get("bios_version")),
        "secure_boot": si.get("secure_boot", False),
        "tpm": si.get("tpm", {}),
        "collector_method": _safe(data.get("collector_method")),
        "collection_timestamp": _safe(data.get("collection_timestamp")),
        "collection_duration_seconds": data.get("collection_duration_seconds", 0),
        "sections_collected": len(data.get("sections_collected", [])),
        "sections_failed": len(data.get("sections_failed", [])),
        "total_findings": 0,
        "antivirus": [{"name": _safe(a.get("name")),
                       "state": _safe(a.get("state"))}
                      for a in av if isinstance(a, dict)] if av else [],
        "realtime_monitoring_disabled": dd.get("realtime_monitoring_disabled", False)
            if isinstance(dd, dict) else False,
        "always_install_elevated": (
            pe.get("always_install_elevated_hklm") == 1
            or pe.get("always_install_elevated_hkcu") == 1
        ) if isinstance(pe, dict) else False,
    }


def _build_hardening_results(data):
    rh = data.get("registry_hardening", {})
    sp = data.get("security_policy", {})
    if (not isinstance(rh, dict) or not rh) and (not isinstance(sp, dict) or not sp):
        return None

    _RECOMMENDED = {
        "EnableLUA": (1, "UAC enabled"),
        "ConsentPromptBehaviorAdmin": (2, "Prompt for consent on secure desktop"),
        "LmCompatibilityLevel": (5, "Send NTLMv2 only / refuse LM & NTLM"),
        "EnableInstallerDetection": (1, "Installer detection enabled"),
        "FilterAdministratorToken": (1, "Filter admin token for built-in admin"),
        "PromptOnSecureDesktop": (1, "Prompt on secure desktop"),
        "ValidateAdminCodeSignatures": (1, "Validate admin code signatures"),
        "EnableSecureUIAPaths": (1, "Secure UIA paths enabled"),
        "EnableVirtualization": (1, "File/registry virtualization enabled"),
        "WDigest_UseLogonCredential": (0, "WDigest cleartext disabled"),
        "LSA_RunAsPPL": (1, "LSA runs as protected process"),
        "NullSessionPipes": (0, "No null session pipes"),
        "NullSessionShares": (0, "No null session shares"),
        "RestrictAnonymous": (1, "Restrict anonymous access"),
        "RestrictAnonymousSAM": (1, "Restrict anonymous SAM enumeration"),
        "EveryoneIncludesAnonymous": (0, "Everyone does not include anonymous"),
        "NoLMHash": (1, "Do not store LM hash"),
        "EnableFirewall_Domain": (1, "Domain firewall enabled"),
        "EnableFirewall_Private": (1, "Private firewall enabled"),
        "EnableFirewall_Public": (1, "Public firewall enabled"),
        "AllowICMPRedirect": (0, "ICMP redirects disabled"),
        "DisableIPSourceRouting": (2, "IP source routing fully disabled"),
        "TcpMaxDataRetransmissions": (3, "Limit TCP retransmissions"),
        "EnableDeadGWDetect": (0, "Dead GW detect disabled"),
        "KeepAliveTime": (300000, "Keepalive time 5 min"),
    }

    items = []
    if isinstance(rh, dict):
        for setting, current_val in rh.items():
            rec = _RECOMMENDED.get(setting)
            if rec:
                rec_val, rec_desc = rec
                items.append({
                    "setting": setting,
                    "current_value": current_val,
                    "recommended_value": rec_val,
                    "recommendation": rec_desc,
                    "compliant": current_val == rec_val if current_val is not None else False,
                })
            else:
                items.append({
                    "setting": setting,
                    "current_value": current_val,
                    "recommended_value": None,
                    "recommendation": "",
                    "compliant": None,
                })

    pp = sp.get("password_policy", {}) if isinstance(sp, dict) else {}
    lp = sp.get("lockout_policy", {}) if isinstance(sp, dict) else {}

    return {
        "registry_hardening": items,
        "compliant_count": sum(1 for i in items if i.get("compliant") is True),
        "non_compliant_count": sum(1 for i in items if i.get("compliant") is False),
        "unchecked_count": sum(1 for i in items if i.get("compliant") is None),
        "password_policy": pp if isinstance(pp, dict) else {},
        "lockout_policy": lp if isinstance(lp, dict) else {},
    }


def _build_software_inventory(data):
    sw = data.get("installed_software", [])
    svcs = data.get("services", [])
    tasks = data.get("scheduled_tasks", [])
    if not sw and not svcs and not tasks:
        return None

    software = []
    if isinstance(sw, list):
        for s in sw:
            if not isinstance(s, dict):
                continue
            software.append({
                "name": _safe(s.get("name")),
                "version": _safe(s.get("version")),
                "publisher": _safe(s.get("publisher")),
                "install_date": _safe(s.get("install_date")),
            })

    running = 0
    auto_start = 0
    svc_list = []
    if isinstance(svcs, list):
        for s in svcs:
            if not isinstance(s, dict):
                continue
            state = _safe(s.get("status")).upper()
            start = _safe(s.get("start_type")).upper()
            if state == "RUNNING":
                running += 1
            if "AUTO" in start:
                auto_start += 1
            svc_list.append({
                "name": _safe(s.get("name")),
                "display_name": _safe(s.get("display_name")),
                "state": _safe(s.get("status")),
                "start_type": _safe(s.get("start_type")),
                "account": _safe(s.get("start_account")),
            })

    notable = []
    if isinstance(tasks, list):
        seen = set()
        for t in tasks:
            if not isinstance(t, dict):
                continue
            tname = t.get("TaskName", "")
            if tname in seen:
                continue
            seen.add(tname)
            if t.get("Scheduled Task State") != "Enabled":
                continue
            author = _safe(t.get("Author")).lower()
            if "microsoft" in author:
                continue
            notable.append({
                "task_name": tname,
                "run_as": _safe(t.get("Run As User")),
                "command": _safe(t.get("Task To Run")),
                "status": _safe(t.get("Status")),
                "schedule_type": _safe(t.get("Schedule Type")),
            })

    return {
        "software": software,
        "software_count": len(software),
        "services_summary": {
            "total": len(svc_list),
            "running": running,
            "auto_start": auto_start,
        },
        "services": svc_list,
        "notable_tasks": notable,
        "notable_task_count": len(notable),
        "total_scheduled_tasks": len(tasks) if isinstance(tasks, list) else 0,
    }


def _build_ad_assessment(data):
    ad = data.get("active_directory", {})
    ua = data.get("user_accounts", {})
    adcs = data.get("adcs", {})
    laps = data.get("laps_config", {})
    si = data.get("system_info", {})
    if not isinstance(ad, dict):
        ad = {}
    if not isinstance(ua, dict):
        ua = {}
    if not ad and not ua:
        return None

    local_users = []
    admins_group = []
    if isinstance(ua, dict):
        for u in ua.get("local_users", []):
            if not isinstance(u, dict):
                continue
            local_users.append({
                "name": _safe(u.get("name")),
                "enabled": u.get("enabled", False),
                "password_never_expires": u.get("password_never_expires", False),
                "description": _safe(u.get("description")),
            })
        raw_admins = ua.get("administrators_group", [])
        if isinstance(raw_admins, list):
            admins_group = [_safe(a) if isinstance(a, str) else _safe(a.get("name"))
                           for a in raw_admins if a]

    ca_list = []
    templates = []
    if isinstance(adcs, dict):
        for ca in adcs.get("certificate_authorities", []):
            if isinstance(ca, dict):
                ca_list.append({
                    "name": _safe(ca.get("name")),
                    "type": _safe(ca.get("type")),
                    "status": _safe(ca.get("status")),
                })
        for t in adcs.get("templates", []):
            if isinstance(t, dict):
                templates.append({
                    "name": _safe(t.get("name")),
                    "oid": _safe(t.get("oid")),
                })

    return {
        "domain_joined": si.get("is_domain_joined", False)
            if isinstance(si, dict) else False,
        "domain_name": _safe(si.get("domain") if isinstance(si, dict) else ""),
        "domain_controllers": ad.get("domain_controllers", []),
        "domain_admins": ad.get("domain_admins", []),
        "enterprise_admins": ad.get("enterprise_admins", []),
        "ldap_signing": ad.get("ldap_signing", {})
            if isinstance(ad.get("ldap_signing"), dict) else {},
        "local_users": local_users,
        "local_user_count": len(local_users),
        "administrators_group": admins_group,
        "administrator_count": len(admins_group),
        "adcs_available": adcs.get("available", False) if isinstance(adcs, dict) else False,
        "certificate_authorities": ca_list,
        "certificate_templates": templates,
        "laps_available": laps.get("available", False) if isinstance(laps, dict) else False,
        "laps_legacy_installed": laps.get("legacy_installed", False)
            if isinstance(laps, dict) else False,
        "laps_windows_installed": laps.get("windows_laps_installed", False)
            if isinstance(laps, dict) else False,
    }


def _build_network_posture(data):
    nc = data.get("network_config", {})
    op = data.get("open_ports", [])
    ac = data.get("active_connections", [])
    fw = data.get("firewall", {})
    dns = data.get("dns_config", {})
    if not isinstance(nc, dict):
        nc = {}
    if not nc and not op and not ac:
        return None

    _HIGH_RISK = {
        21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
        1433: "MSSQL", 1434: "MSSQL Browser", 3306: "MySQL", 3389: "RDP",
        5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis",
        27017: "MongoDB",
    }

    adapters = []
    for a in nc.get("adapters", []):
        if isinstance(a, dict):
            adapters.append({
                "description": _safe(a.get("description")),
                "ip_address": _safe(a.get("ip_address")),
                "subnet": _safe(a.get("subnet")),
                "gateway": _safe(a.get("gateway")),
                "dhcp_enabled": a.get("dhcp_enabled", False),
                "mac_address": _safe(a.get("mac_address")),
            })

    high_risk = []
    listening_ports = set()
    if isinstance(op, list):
        for p in op:
            if not isinstance(p, dict):
                continue
            port = p.get("port", 0)
            state = _safe(p.get("state")).upper()
            if state == "LISTENING":
                listening_ports.add(port)
            if port in _HIGH_RISK and state == "LISTENING":
                high_risk.append({
                    "port": port,
                    "service": _HIGH_RISK[port],
                    "protocol": _safe(p.get("protocol")),
                    "process": p.get("process", ""),
                })

    established = 0
    listening = 0
    remote_ips = set()
    if isinstance(ac, list):
        for c in ac:
            if not isinstance(c, dict):
                continue
            state = _safe(c.get("state")).upper()
            if state == "ESTABLISHED":
                established += 1
            elif state == "LISTENING":
                listening += 1
            rip = c.get("remote_address", "")
            if rip and rip not in ("0.0.0.0", "::", "127.0.0.1", "::1", "*"):
                remote_ips.add(rip)

    profiles = {}
    if isinstance(fw, dict):
        for pname, pdata in fw.get("profiles", {}).items():
            if isinstance(pdata, dict):
                profiles[pname] = {
                    "enabled": pdata.get("State", pdata.get("enabled", "unknown")),
                }
            else:
                profiles[pname] = {"enabled": "unknown"}

    dns_info = {}
    if isinstance(dns, dict):
        dns_info = {
            "service_running": dns.get("dns_service_running", False),
            "zones": dns.get("zones", []),
        }

    return {
        "adapters": adapters,
        "dns_servers": nc.get("dns_servers", []),
        "proxy": nc.get("proxy", {}),
        "domain": _safe(nc.get("domain")),
        "netbios_over_tcpip": nc.get("netbios_over_tcpip", False),
        "open_ports_total": len(listening_ports),
        "high_risk_ports": high_risk,
        "high_risk_port_count": len(high_risk),
        "connections_total": len(ac) if isinstance(ac, list) else 0,
        "connections_established": established,
        "connections_listening": listening,
        "unique_remote_ips": len(remote_ips),
        "firewall_profiles": profiles,
        "dns": dns_info,
    }


def _build_browser_audit(data):
    browsers = {}
    has_any = False
    for key, label in (("browser_chrome", "Chrome"),
                       ("browser_edge", "Edge"),
                       ("browser_firefox", "Firefox")):
        bd = data.get(key, {})
        if not isinstance(bd, dict):
            bd = {}
        installed = bool(bd)
        if installed:
            has_any = True
        extensions = []
        for e in bd.get("extensions", []):
            if isinstance(e, dict):
                extensions.append({
                    "name": _safe(e.get("name")),
                    "id": _safe(e.get("id")),
                    "version": _safe(e.get("version")),
                    "enabled": e.get("enabled", True),
                })
        browsers[label] = {
            "installed": installed,
            "extensions": extensions,
            "extension_count": len(extensions),
            "history_entries": len(bd.get("history", [])),
            "saved_passwords": len(bd.get("saved_passwords", [])),
        }
    if not has_any:
        return None
    return browsers


def write_intel_files(data, output_dir):
    out = Path(output_dir)

    disk_report = _build_disk_storage_report(data)
    if disk_report is not None:
        (out / "disk_storage_report.json").write_text(
            json.dumps(disk_report, indent=2), encoding="utf-8")

    hw_report = _build_hardware_report(data)
    if hw_report is not None:
        (out / "hardware_report.json").write_text(
            json.dumps(hw_report, indent=2), encoding="utf-8")

    _BUILDERS = [
        ("endpoint_status.json", _build_endpoint_status),
        ("hardening_results.json", _build_hardening_results),
        ("software_inventory.json", _build_software_inventory),
        ("ad_assessment.json", _build_ad_assessment),
        ("network_posture.json", _build_network_posture),
        ("browser_audit.json", _build_browser_audit),
    ]

    written = []
    if disk_report is not None:
        written.append("disk_storage_report.json")
    if hw_report is not None:
        written.append("hardware_report.json")

    for filename, builder in _BUILDERS:
        try:
            result = builder(data)
        except Exception:
            continue
        if result is not None:
            (out / filename).write_text(
                json.dumps(result, indent=2, default=str), encoding="utf-8")
            written.append(filename)

    return written
