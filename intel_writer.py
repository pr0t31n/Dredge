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
        "partitions": [],
        "volumes": [],
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
            "filesystem": _safe(d.get("filesystem")),
            "size_gb": d.get("size_gb", 0),
            "free_gb": d.get("free_space_gb", 0),
            "percent_free": d.get("percent_free", 0),
            "volume": _safe(d.get("volume_name")),
            "type": _safe(d.get("drive_type")),
        })

    for p in ds.get("partitions", []):
        if not isinstance(p, dict):
            continue
        report["partitions"].append({
            "device": _safe(p.get("device_id")),
            "disk_index": p.get("disk_index"),
            "partition_index": p.get("partition_index"),
            "size_gb": p.get("size_gb", 0),
            "bootable": p.get("bootable", False),
            "boot_partition": p.get("boot_partition", False),
            "primary": p.get("primary_partition", False),
            "type": _safe(p.get("type")),
        })

    for v in ds.get("volumes", []):
        if not isinstance(v, dict):
            continue
        report["volumes"].append({
            "drive_letter": _safe(v.get("drive_letter")),
            "capacity_gb": v.get("capacity_gb", 0),
            "free_gb": v.get("free_space_gb", 0),
            "filesystem": _safe(v.get("filesystem")),
            "label": _safe(v.get("label")),
            "dirty": v.get("dirty_bit", False),
            "serial": _safe(v.get("serial_number")),
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
        "bios": None,
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
        "scsi_controllers": [],
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

    bi = hw.get("bios")
    if isinstance(bi, dict):
        report["bios"] = {
            "manufacturer": _safe(bi.get("manufacturer")),
            "name": _safe(bi.get("name")),
            "version": _safe(bi.get("version")),
            "release_date": _safe(bi.get("release_date")),
            "smbios_version": _safe(bi.get("smbios_version")),
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

    for sc in hw.get("scsi_controllers", []):
        if isinstance(sc, dict):
            report["scsi_controllers"].append({
                "name": _safe(sc.get("name")),
                "manufacturer": _safe(sc.get("manufacturer")),
                "driver": _safe(sc.get("driver_name")),
                "status": _safe(sc.get("status")),
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
        "NullSessionPipes": ("", "No null session pipes"),
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
        "SMB1": (0, "SMBv1 disabled"),
        "RequireSecuritySignature": (1, "SMB signing required"),
        "EnableVirtualizationBasedSecurity": (1, "VBS enabled"),
        "HypervisorEnforcedCodeIntegrity": (1, "HVCI enabled"),
        "LsaCfgFlags": (1, "Credential Guard enabled"),
        "NoDriveTypeAutoRun": (255, "AutoRun disabled all drives"),
        "ScriptBlockLogging": (1, "PS script block logging enabled"),
        "ModuleLogging": (1, "PS module logging enabled"),
        "Transcription": (1, "PS transcription enabled"),
        "EnableMulticast": (0, "LLMNR disabled"),
        "defender_disabled": (0, "Defender not disabled"),
        "real_time_protection": (1, "Real-time protection enabled"),
        "fDenyTSConnections": (1, "RDP disabled unless needed"),
        "UserAuthentication": (1, "NLA required for RDP"),
        "WpadOverride": (True, "WPAD disabled"),
        "nx_policy": ("OptOut", "DEP OptOut policy"),
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


# ---------------------------------------------------------------------------
# Compliance assessment helpers
# ---------------------------------------------------------------------------

def _intval(v):
    """Coerce a value to int, or return None if not possible."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return None


def _eval_control(ctrl_id, title, severity, current, expected_str,
                  check_fn, source, remediation):
    """Evaluate a single compliance control and return a result dict.

    If *current* is None the control is NOT_ASSESSED (data not collected).
    Otherwise *check_fn(current)* determines PASS / FAIL.
    """
    if current is None:
        return {
            "id": ctrl_id, "title": title, "severity": severity,
            "status": "NOT_ASSESSED", "current_value": "Not collected",
            "expected_value": expected_str, "data_source": source,
            "remediation": "",
        }
    try:
        passed = bool(check_fn(current))
    except Exception:
        passed = False
    return {
        "id": ctrl_id, "title": title, "severity": severity,
        "status": "PASS" if passed else "FAIL",
        "current_value": str(current),
        "expected_value": expected_str, "data_source": source,
        "remediation": "" if passed else remediation,
    }


def _finalize_category(cat_id, name, controls):
    """Wrap a list of control results into a category dict with tallies."""
    p = sum(1 for c in controls if c["status"] == "PASS")
    f = sum(1 for c in controls if c["status"] == "FAIL")
    na = sum(1 for c in controls if c["status"] == "NOT_ASSESSED")
    return {
        "id": cat_id, "name": name, "controls": controls,
        "pass_count": p, "fail_count": f, "not_assessed": na,
    }


def _finalize_assessment(framework, scope, categories):
    """Build top-level assessment result from a list of category dicts."""
    total = sum(len(c["controls"]) for c in categories)
    p = sum(c["pass_count"] for c in categories)
    f = sum(c["fail_count"] for c in categories)
    na = sum(c["not_assessed"] for c in categories)
    denom = p + f
    score = round(p / denom * 100, 1) if denom > 0 else 0.0
    if score >= 90:
        rating = "PASS"
    elif score >= 60:
        rating = "PARTIAL"
    else:
        rating = "FAIL"
    return {
        "framework": framework, "scope": scope,
        "overall_rating": rating, "score_percent": score,
        "total_controls": total, "pass_count": p,
        "fail_count": f, "not_assessed": na,
        "categories": categories,
    }


def _svc_running(services, name):
    """Return True if a named service is running, False if stopped/absent,
    None if service data was not collected."""
    if not isinstance(services, list) or not services:
        return None
    nl = name.lower()
    for s in services:
        if isinstance(s, dict) and _safe(s.get("name")).lower() == nl:
            return _safe(s.get("status")).upper() == "RUNNING"
    return False


def _fw_enabled(fw, profile):
    """Return True/False/None for a firewall profile's enabled state."""
    if not isinstance(fw, dict):
        return None
    profiles = fw.get("profiles", {})
    if not isinstance(profiles, dict) or not profiles:
        return None
    for pn, pd in profiles.items():
        if pn.lower() == profile.lower():
            if not isinstance(pd, dict):
                return None
            st = pd.get("State", pd.get("enabled"))
            if st is None:
                return None
            if isinstance(st, bool):
                return st
            return str(st).upper() in ("TRUE", "ON", "1", "ENABLED", "YES")
    return None


def _audit_val(audit, *keys):
    """Find an audit policy setting by trying multiple key spellings."""
    if not isinstance(audit, dict):
        return None
    for k in keys:
        v = audit.get(k)
        if v is not None:
            return v
    return None


# ---------------------------------------------------------------------------
# CIS Benchmarks for Windows Server
# ---------------------------------------------------------------------------

def _build_cis_assessment(data):
    rh = data.get("registry_hardening", {})
    if not isinstance(rh, dict):
        rh = {}
    sp = data.get("security_policy", {})
    if not isinstance(sp, dict):
        sp = {}
    services = data.get("services", [])
    fw = data.get("firewall", {})
    dd = data.get("defender_detailed", {})
    if not isinstance(dd, dict):
        dd = {}
    si = data.get("system_info", {})
    if not isinstance(si, dict):
        si = {}
    ad = data.get("active_directory", {})
    if not isinstance(ad, dict):
        ad = {}

    if not rh and not sp and not isinstance(services, list):
        return None

    pp = sp.get("password_policy", {})
    if not isinstance(pp, dict):
        pp = {}
    lp = sp.get("lockout_policy", {})
    if not isinstance(lp, dict):
        lp = {}
    ap = sp.get("audit_policy", {})
    if not isinstance(ap, dict):
        ap = {}

    # -- local shorthand helpers --
    def _rc(ctrl_id, title, sev, key, check_fn, expected_str, remed):
        return _eval_control(ctrl_id, title, sev, rh.get(key), expected_str,
                             check_fn, f"registry_hardening.{key}", remed)

    def _sd(ctrl_id, title, sev, svc_name, remed):
        return _eval_control(ctrl_id, title, sev, _svc_running(services, svc_name),
                             "Not running", lambda v: not v,
                             f"services.{svc_name}", remed)

    # ===== Category 1: Account Policies =====
    cat1 = []
    cat1.append(_eval_control(
        "CIS-1.1.1", "Enforce password history >= 24", "HIGH",
        pp.get("history"), ">=24",
        lambda v: _intval(v) is not None and _intval(v) >= 24,
        "password_policy.history",
        "Set 'Enforce password history' to 24 or more via secpol.msc"))
    cat1.append(_eval_control(
        "CIS-1.1.2", "Maximum password age <= 365 days", "MEDIUM",
        pp.get("max_age"), "<=365",
        lambda v: _intval(v) is not None and 1 <= _intval(v) <= 365,
        "password_policy.max_age",
        "Set 'Maximum password age' to 365 or fewer days via secpol.msc"))
    cat1.append(_eval_control(
        "CIS-1.1.3", "Minimum password age >= 1 day", "MEDIUM",
        pp.get("min_age"), ">=1",
        lambda v: _intval(v) is not None and _intval(v) >= 1,
        "password_policy.min_age",
        "Set 'Minimum password age' to 1 or more days via secpol.msc"))
    cat1.append(_eval_control(
        "CIS-1.1.4", "Minimum password length >= 14 characters", "HIGH",
        pp.get("min_length"), ">=14",
        lambda v: _intval(v) is not None and _intval(v) >= 14,
        "password_policy.min_length",
        "Set 'Minimum password length' to 14 or more via secpol.msc"))
    cat1.append(_eval_control(
        "CIS-1.1.5", "Password complexity requirements enabled", "HIGH",
        pp.get("complexity_enabled"), "True",
        lambda v: v is True or v == 1 or str(v).lower() in ("true", "1", "yes"),
        "password_policy.complexity_enabled",
        "Enable 'Password must meet complexity requirements' via secpol.msc"))
    cat1.append(_eval_control(
        "CIS-1.2.1", "Account lockout threshold between 1 and 5", "HIGH",
        lp.get("threshold"), "1-5",
        lambda v: _intval(v) is not None and 1 <= _intval(v) <= 5,
        "lockout_policy.threshold",
        "Set 'Account lockout threshold' to 1-5 via secpol.msc"))
    cat1.append(_eval_control(
        "CIS-1.2.2", "Account lockout duration >= 15 minutes", "MEDIUM",
        lp.get("duration"), ">=15",
        lambda v: _intval(v) is not None and _intval(v) >= 15,
        "lockout_policy.duration",
        "Set 'Account lockout duration' to 15 or more minutes via secpol.msc"))
    cat1.append(_eval_control(
        "CIS-1.2.3", "Lockout observation window >= 15 minutes", "MEDIUM",
        lp.get("observation_window"), ">=15",
        lambda v: _intval(v) is not None and _intval(v) >= 15,
        "lockout_policy.observation_window",
        "Set 'Reset account lockout counter' to 15 or more minutes via secpol.msc"))

    # ===== Category 2: Local Policies / Security Options =====
    cat2 = []
    # -- UAC --
    cat2.append(_rc("CIS-2.1.1", "UAC: EnableLUA enabled", "CRITICAL",
                     "EnableLUA", lambda v: _intval(v) == 1, "1",
                     "Enable UAC via Group Policy > Security Options"))
    cat2.append(_rc("CIS-2.1.2", "UAC: ConsentPromptBehaviorAdmin <= 2", "HIGH",
                     "ConsentPromptBehaviorAdmin",
                     lambda v: _intval(v) is not None and _intval(v) <= 2, "<=2",
                     "Set ConsentPromptBehaviorAdmin to 2 or lower via Group Policy"))
    cat2.append(_rc("CIS-2.1.3", "UAC: FilterAdministratorToken enabled", "HIGH",
                     "FilterAdministratorToken", lambda v: _intval(v) == 1, "1",
                     "Enable FilterAdministratorToken via registry or Group Policy"))
    cat2.append(_rc("CIS-2.1.4", "UAC: PromptOnSecureDesktop enabled", "MEDIUM",
                     "PromptOnSecureDesktop", lambda v: _intval(v) == 1, "1",
                     "Enable PromptOnSecureDesktop via Group Policy"))
    cat2.append(_rc("CIS-2.1.5", "UAC: ValidateAdminCodeSignatures enabled", "MEDIUM",
                     "ValidateAdminCodeSignatures", lambda v: _intval(v) == 1, "1",
                     "Enable ValidateAdminCodeSignatures via Group Policy"))
    cat2.append(_rc("CIS-2.1.6", "UAC: EnableInstallerDetection enabled", "LOW",
                     "EnableInstallerDetection", lambda v: _intval(v) == 1, "1",
                     "Enable EnableInstallerDetection via Group Policy"))
    cat2.append(_rc("CIS-2.1.7", "UAC: EnableSecureUIAPaths enabled", "MEDIUM",
                     "EnableSecureUIAPaths", lambda v: _intval(v) == 1, "1",
                     "Enable EnableSecureUIAPaths via Group Policy"))
    # -- Network access --
    cat2.append(_rc("CIS-2.2.1", "Restrict anonymous access", "HIGH",
                     "RestrictAnonymous",
                     lambda v: _intval(v) is not None and _intval(v) >= 1, ">=1",
                     "Set RestrictAnonymous to 1 or higher via Group Policy"))
    cat2.append(_rc("CIS-2.2.2", "Restrict anonymous SAM enumeration", "HIGH",
                     "RestrictAnonymousSAM", lambda v: _intval(v) == 1, "1",
                     "Set RestrictAnonymousSAM to 1 via Group Policy"))
    cat2.append(_rc("CIS-2.2.3", "No null session pipes", "HIGH",
                     "NullSessionPipes",
                     lambda v: not v or (isinstance(v, str) and not v.strip()),
                     "Empty",
                     "Clear NullSessionPipes list via Group Policy"))
    cat2.append(_rc("CIS-2.2.4", "No null session shares", "HIGH",
                     "NullSessionShares",
                     lambda v: not v or (isinstance(v, str) and not v.strip()),
                     "Empty",
                     "Clear NullSessionShares list via Group Policy"))
    cat2.append(_rc("CIS-2.2.5", "Everyone does not include anonymous", "MEDIUM",
                     "EveryoneIncludesAnonymous", lambda v: _intval(v) == 0, "0",
                     "Set EveryoneIncludesAnonymous to 0 via Group Policy"))
    # -- Network security --
    cat2.append(_rc("CIS-2.3.1", "LAN Manager auth: NTLMv2 only (level >= 5)", "CRITICAL",
                     "LmCompatibilityLevel",
                     lambda v: _intval(v) is not None and _intval(v) >= 5, ">=5",
                     "Set LmCompatibilityLevel to 5 via Group Policy > Network Security"))
    cat2.append(_rc("CIS-2.3.2", "Do not store LAN Manager hash", "HIGH",
                     "NoLMHash", lambda v: _intval(v) == 1, "1",
                     "Set NoLMHash to 1 via Group Policy"))
    cat2.append(_rc("CIS-2.3.3", "SMB signing required", "HIGH",
                     "RequireSecuritySignature", lambda v: _intval(v) == 1, "1",
                     "Enable 'Digitally sign communications (always)' via Group Policy"))
    ldap_val = rh.get("LDAPClientIntegrity")
    if ldap_val is None:
        ls = ad.get("ldap_signing", {})
        if isinstance(ls, dict):
            ldap_val = ls.get("client_signing") or ls.get("require_signing")
    cat2.append(_eval_control(
        "CIS-2.3.4", "LDAP client signing required", "HIGH",
        ldap_val, ">=1 (Negotiate or Require)",
        lambda v: _intval(v) is not None and _intval(v) >= 1,
        "registry_hardening.LDAPClientIntegrity / active_directory.ldap_signing",
        "Set LDAP client signing to Negotiate Signing or Require Signing via Group Policy"))
    # -- Interactive logon --
    legal = rh.get("LegalNoticeCaption") or rh.get("LegalNoticeText")
    cat2.append(_eval_control(
        "CIS-2.4.1", "Legal notice text configured", "LOW",
        legal, "Non-empty",
        lambda v: bool(v) and str(v).strip() != "",
        "registry_hardening.LegalNoticeCaption",
        "Configure a legal notice banner via Group Policy > Interactive Logon"))
    inactivity = rh.get("InactivityTimeoutSecs") or rh.get("ScreenSaverTimeout")
    cat2.append(_eval_control(
        "CIS-2.4.2", "Machine inactivity timeout configured", "MEDIUM",
        inactivity, "<=900 seconds",
        lambda v: _intval(v) is not None and 1 <= _intval(v) <= 900,
        "registry_hardening.InactivityTimeoutSecs",
        "Set machine inactivity limit to 900 seconds or less via Group Policy"))
    # -- System --
    cat2.append(_rc("CIS-2.5.1", "DEP/NX policy set to OptOut", "HIGH",
                     "nx_policy",
                     lambda v: str(v).lower() in ("optout", "alwayson"), "OptOut",
                     "Set DEP to OptOut via bcdedit /set nx OptOut"))
    cat2.append(_rc("CIS-2.5.2", "IP source routing fully disabled", "MEDIUM",
                     "DisableIPSourceRouting",
                     lambda v: _intval(v) is not None and _intval(v) >= 2, "2",
                     "Set DisableIPSourceRouting to 2 via Group Policy"))
    cat2.append(_rc("CIS-2.5.3", "ICMP redirects disabled", "MEDIUM",
                     "AllowICMPRedirect", lambda v: _intval(v) == 0, "0",
                     "Set AllowICMPRedirect to 0 via Group Policy"))

    # ===== Category 3: Event Logging / Audit Policy =====
    cat3 = []
    cat3.append(_eval_control(
        "CIS-3.1", "Audit logon events", "HIGH",
        _audit_val(ap, "Audit Logon", "Logon", "audit_logon"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Logon",
        "Enable 'Audit Logon Events' for Success and Failure via auditpol"))
    cat3.append(_eval_control(
        "CIS-3.2", "Audit account management", "HIGH",
        _audit_val(ap, "Audit Account Management", "Account Management",
                   "User Account Management", "audit_account_management"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Account Management",
        "Enable 'Audit Account Management' for Success and Failure via auditpol"))
    cat3.append(_eval_control(
        "CIS-3.3", "Audit policy change", "HIGH",
        _audit_val(ap, "Audit Policy Change", "Policy Change",
                   "audit_policy_change"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Policy Change",
        "Enable 'Audit Policy Change' for Success and Failure via auditpol"))
    cat3.append(_eval_control(
        "CIS-3.4", "Audit privilege use", "MEDIUM",
        _audit_val(ap, "Audit Privilege Use", "Sensitive Privilege Use",
                   "Privilege Use", "audit_privilege_use"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Privilege Use",
        "Enable 'Audit Privilege Use' for Success and Failure via auditpol"))
    cat3.append(_eval_control(
        "CIS-3.5", "Audit system events", "MEDIUM",
        _audit_val(ap, "Audit System Events", "Security State Change",
                   "System", "audit_system"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.System Events",
        "Enable 'Audit System Events' for Success and Failure via auditpol"))

    # ===== Category 4: Windows Firewall =====
    cat4 = []
    cat4.append(_eval_control(
        "CIS-4.1", "Domain firewall profile enabled", "HIGH",
        _fw_enabled(fw, "Domain"), "Enabled",
        lambda v: v is True, "firewall.profiles.Domain",
        "Enable the Domain firewall profile via Windows Firewall with Advanced Security"))
    cat4.append(_eval_control(
        "CIS-4.2", "Private firewall profile enabled", "HIGH",
        _fw_enabled(fw, "Private"), "Enabled",
        lambda v: v is True, "firewall.profiles.Private",
        "Enable the Private firewall profile via Windows Firewall with Advanced Security"))
    cat4.append(_eval_control(
        "CIS-4.3", "Public firewall profile enabled", "HIGH",
        _fw_enabled(fw, "Public"), "Enabled",
        lambda v: v is True, "firewall.profiles.Public",
        "Enable the Public firewall profile via Windows Firewall with Advanced Security"))

    # ===== Category 5: Security Settings =====
    cat5 = []
    cat5.append(_rc("CIS-5.1", "LSA protection (RunAsPPL) enabled", "CRITICAL",
                     "LSA_RunAsPPL", lambda v: _intval(v) == 1, "1",
                     "Set LSA RunAsPPL to 1 via registry or Group Policy"))
    cat5.append(_rc("CIS-5.2", "WDigest cleartext credentials disabled", "CRITICAL",
                     "WDigest_UseLogonCredential", lambda v: _intval(v) == 0, "0",
                     "Set WDigest UseLogonCredential to 0 via registry"))
    cat5.append(_rc("CIS-5.3", "Credential Guard enabled", "HIGH",
                     "LsaCfgFlags", lambda v: _intval(v) == 1, "1",
                     "Enable Credential Guard via Group Policy > Device Guard"))
    cat5.append(_rc("CIS-5.4", "Virtualization Based Security enabled", "HIGH",
                     "EnableVirtualizationBasedSecurity",
                     lambda v: _intval(v) == 1, "1",
                     "Enable VBS via Group Policy > Device Guard"))
    cat5.append(_rc("CIS-5.5", "HVCI (Hypervisor Code Integrity) enabled", "HIGH",
                     "HypervisorEnforcedCodeIntegrity",
                     lambda v: _intval(v) == 1, "1",
                     "Enable HVCI via Group Policy > Device Guard"))
    cat5.append(_rc("CIS-5.6", "LLMNR disabled", "HIGH",
                     "EnableMulticast", lambda v: _intval(v) == 0, "0",
                     "Set EnableMulticast to 0 via Group Policy > DNS Client"))
    wpad = rh.get("WpadOverride")
    if wpad is None:
        wpad = rh.get("WPADOverride")
    cat5.append(_eval_control(
        "CIS-5.7", "WPAD disabled", "HIGH",
        wpad, "True/Disabled",
        lambda v: v is True or v == 1 or str(v).lower() in ("true", "1", "disabled"),
        "registry_hardening.WpadOverride",
        "Disable WPAD via registry or Group Policy"))
    cat5.append(_rc("CIS-5.8", "AutoRun disabled for all drives", "HIGH",
                     "NoDriveTypeAutoRun",
                     lambda v: _intval(v) is not None and _intval(v) == 255, "255",
                     "Set NoDriveTypeAutoRun to 255 via Group Policy"))
    cat5.append(_rc("CIS-5.9", "NLA required for RDP", "HIGH",
                     "UserAuthentication", lambda v: _intval(v) == 1, "1",
                     "Require Network Level Authentication for RDP via Group Policy"))
    cat5.append(_rc("CIS-5.10", "SMBv1 protocol disabled", "CRITICAL",
                     "SMB1", lambda v: _intval(v) == 0, "0",
                     "Disable SMBv1 via Disable-WindowsOptionalFeature or Group Policy"))
    cat5.append(_rc("CIS-5.11", "PowerShell script block logging enabled", "MEDIUM",
                     "ScriptBlockLogging", lambda v: _intval(v) == 1, "1",
                     "Enable PowerShell script block logging via Group Policy"))
    cat5.append(_rc("CIS-5.12", "PowerShell module logging enabled", "MEDIUM",
                     "ModuleLogging", lambda v: _intval(v) == 1, "1",
                     "Enable PowerShell module logging via Group Policy"))

    # ===== Category 6: System Services =====
    cat6 = []
    cat6.append(_sd("CIS-6.1", "Telnet service stopped/disabled", "HIGH",
                     "TlntSvr", "Stop and disable Telnet (TlntSvr) service"))
    cat6.append(_sd("CIS-6.2", "FTP service stopped/disabled", "HIGH",
                     "ftpsvc", "Stop and disable FTP (ftpsvc) service"))
    cat6.append(_sd("CIS-6.3", "SNMP service stopped/disabled", "MEDIUM",
                     "SNMP", "Stop and disable SNMP service or restrict community strings"))
    cat6.append(_sd("CIS-6.4", "Remote Registry service stopped/disabled", "HIGH",
                     "RemoteRegistry",
                     "Stop and disable Remote Registry service"))
    cat6.append(_sd("CIS-6.5", "SSDP Discovery service stopped/disabled", "MEDIUM",
                     "SSDPSRV",
                     "Stop and disable SSDP Discovery (SSDPSRV) service"))
    cat6.append(_sd("CIS-6.6", "UPnP Device Host service stopped/disabled", "MEDIUM",
                     "upnphost",
                     "Stop and disable UPnP Device Host service"))
    cat6.append(_sd("CIS-6.7", "Xbox Live Auth Manager stopped/disabled", "LOW",
                     "XblAuthManager",
                     "Stop and disable Xbox services on servers"))
    cat6.append(_sd("CIS-6.8", "Windows Remote Management (WinRM) reviewed", "MEDIUM",
                     "WinRM",
                     "Disable WinRM service if remote management is not required"))

    # ===== Category 7: Defender / AV =====
    cat7 = []
    av_products = dd.get("av_products", [])
    av_installed = None
    if isinstance(dd, dict) and dd:
        av_installed = isinstance(av_products, list) and len(av_products) > 0
    cat7.append(_eval_control(
        "CIS-7.1", "Antivirus product installed", "CRITICAL",
        av_installed, "True",
        lambda v: v is True,
        "defender_detailed.av_products",
        "Install an antivirus product on the system"))
    rt_disabled = dd.get("realtime_monitoring_disabled")
    rt_val = None
    if rt_disabled is not None:
        rt_val = not rt_disabled
    cat7.append(_eval_control(
        "CIS-7.2", "Real-time protection enabled", "CRITICAL",
        rt_val, "True",
        lambda v: v is True,
        "defender_detailed.realtime_monitoring_disabled",
        "Enable real-time monitoring in Windows Defender or installed AV"))
    cat7.append(_rc("CIS-7.3", "Windows Defender not disabled by policy", "CRITICAL",
                     "defender_disabled", lambda v: _intval(v) == 0, "0",
                     "Remove DisableAntiSpyware registry key or set to 0"))
    cat7.append(_eval_control(
        "CIS-7.4", "Anti-spyware component enabled", "HIGH",
        dd.get("anti_spyware_enabled"),
        "True",
        lambda v: v is True or v == 1 or str(v).lower() in ("true", "1"),
        "defender_detailed.anti_spyware_enabled",
        "Enable anti-spyware protection in Defender settings"))
    cat7.append(_eval_control(
        "CIS-7.5", "PUA protection enabled", "MEDIUM",
        dd.get("pua_protection"),
        "Enabled",
        lambda v: v is True or _intval(v) == 1
        or str(v).lower() in ("true", "enabled", "1"),
        "defender_detailed.pua_protection",
        "Enable PUA protection via Set-MpPreference -PUAProtection Enabled"))
    cat7.append(_eval_control(
        "CIS-7.6", "Cloud-delivered protection enabled", "MEDIUM",
        dd.get("cloud_protection") if isinstance(dd, dict) and dd else None,
        "Enabled",
        lambda v: v is True or _intval(v) == 1
        or str(v).lower() in ("true", "enabled", "1"),
        "defender_detailed.cloud_protection",
        "Enable cloud-delivered protection via Windows Security settings"))

    categories = [
        _finalize_category("1", "Account Policies", cat1),
        _finalize_category("2", "Local Policies / Security Options", cat2),
        _finalize_category("3", "Event Logging / Audit Policy", cat3),
        _finalize_category("4", "Windows Firewall", cat4),
        _finalize_category("5", "Security Settings", cat5),
        _finalize_category("6", "System Services", cat6),
        _finalize_category("7", "Defender / Antivirus", cat7),
    ]
    return _finalize_assessment("CIS Benchmarks v3.0.0", "Windows Server", categories)


# ---------------------------------------------------------------------------
# NIST SP 800-123 -- Guide to General Server Security
# ---------------------------------------------------------------------------

def _build_nist_assessment(data):
    rh = data.get("registry_hardening", {})
    if not isinstance(rh, dict):
        rh = {}
    sp = data.get("security_policy", {})
    if not isinstance(sp, dict):
        sp = {}
    services = data.get("services", [])
    fw = data.get("firewall", {})
    dd = data.get("defender_detailed", {})
    if not isinstance(dd, dict):
        dd = {}
    si = data.get("system_info", {})
    if not isinstance(si, dict):
        si = {}
    nc = data.get("network_config", {})
    if not isinstance(nc, dict):
        nc = {}
    op = data.get("open_ports", [])
    ua = data.get("user_accounts", {})
    if not isinstance(ua, dict):
        ua = {}

    if not rh and not sp and not isinstance(services, list):
        return None

    pp = sp.get("password_policy", {})
    if not isinstance(pp, dict):
        pp = {}
    lp = sp.get("lockout_policy", {})
    if not isinstance(lp, dict):
        lp = {}
    ap = sp.get("audit_policy", {})
    if not isinstance(ap, dict):
        ap = {}

    def _rc(ctrl_id, title, sev, key, check_fn, expected_str, remed):
        return _eval_control(ctrl_id, title, sev, rh.get(key), expected_str,
                             check_fn, f"registry_hardening.{key}", remed)

    def _sd(ctrl_id, title, sev, svc_name, remed):
        return _eval_control(ctrl_id, title, sev, _svc_running(services, svc_name),
                             "Not running", lambda v: not v,
                             f"services.{svc_name}", remed)

    # ===== Category 1: OS Patching & Updates =====
    cat1 = []
    cat1.append(_eval_control(
        "NIST-1.1", "Windows Update service running", "HIGH",
        _svc_running(services, "wuauserv"), "Running",
        lambda v: v is True, "services.wuauserv",
        "Enable and start the Windows Update (wuauserv) service"))
    cat1.append(_eval_control(
        "NIST-1.2", "Update Orchestrator service running", "MEDIUM",
        _svc_running(services, "UsoSvc"), "Running",
        lambda v: v is True, "services.UsoSvc",
        "Enable the Update Orchestrator (UsoSvc) service"))
    cat1.append(_eval_control(
        "NIST-1.3", "BITS service available for updates", "MEDIUM",
        _svc_running(services, "BITS"), "Running",
        lambda v: v is True, "services.BITS",
        "Enable BITS service for background update transfers"))
    cat1.append(_eval_control(
        "NIST-1.4", "Cryptographic services running", "MEDIUM",
        _svc_running(services, "CryptSvc"), "Running",
        lambda v: v is True, "services.CryptSvc",
        "Enable Cryptographic Services for update signature verification"))
    uptime = si.get("uptime_days")
    cat1.append(_eval_control(
        "NIST-1.5", "System rebooted within last 90 days (patches applied)", "MEDIUM",
        uptime, "<=90 days",
        lambda v: _intval(v) is not None and _intval(v) <= 90,
        "system_info.uptime_days",
        "Reboot the server to apply pending patches and updates"))

    # ===== Category 2: Unnecessary Services =====
    cat2 = []
    cat2.append(_sd("NIST-2.1", "Telnet service not running", "HIGH",
                     "TlntSvr", "Disable Telnet; use SSH for remote administration"))
    cat2.append(_sd("NIST-2.2", "FTP service not running", "HIGH",
                     "ftpsvc", "Disable FTP; use SFTP/SCP for file transfers"))
    cat2.append(_sd("NIST-2.3", "SNMP service not running", "MEDIUM",
                     "SNMP", "Disable SNMP or restrict with SNMPv3 authentication"))
    cat2.append(_sd("NIST-2.4", "Remote Registry not running", "HIGH",
                     "RemoteRegistry", "Disable Remote Registry service"))
    cat2.append(_sd("NIST-2.5", "TFTP service not running", "HIGH",
                     "tftpd", "Disable TFTP daemon service"))
    cat2.append(_sd("NIST-2.6", "Simple TCP/IP Services not running", "MEDIUM",
                     "simptcp",
                     "Disable Simple TCP/IP Services (echo, daytime, etc.)"))
    cat2.append(_sd("NIST-2.7", "IIS web service not running (unless required)", "MEDIUM",
                     "W3SVC",
                     "Disable IIS (W3SVC) if web hosting is not required"))

    # ===== Category 3: User Account Management =====
    cat3 = []
    cat3.append(_eval_control(
        "NIST-3.1", "Minimum password length >= 14", "HIGH",
        pp.get("min_length"), ">=14",
        lambda v: _intval(v) is not None and _intval(v) >= 14,
        "password_policy.min_length",
        "Set minimum password length to 14 or more"))
    cat3.append(_eval_control(
        "NIST-3.2", "Password complexity enabled", "HIGH",
        pp.get("complexity_enabled"), "True",
        lambda v: v is True or v == 1 or str(v).lower() in ("true", "1", "yes"),
        "password_policy.complexity_enabled",
        "Enable password complexity requirements"))
    cat3.append(_eval_control(
        "NIST-3.3", "Account lockout threshold configured", "HIGH",
        lp.get("threshold"), "1-10",
        lambda v: _intval(v) is not None and 1 <= _intval(v) <= 10,
        "lockout_policy.threshold",
        "Set account lockout threshold between 1-10 attempts"))
    admins = ua.get("administrators_group", [])
    admin_count = len(admins) if isinstance(admins, list) else None
    cat3.append(_eval_control(
        "NIST-3.4", "Limit local administrators (<= 5 members)", "HIGH",
        admin_count, "<=5",
        lambda v: _intval(v) is not None and _intval(v) <= 5,
        "user_accounts.administrators_group",
        "Remove unnecessary accounts from the local Administrators group"))
    cat3.append(_eval_control(
        "NIST-3.5", "Password history >= 12", "MEDIUM",
        pp.get("history"), ">=12",
        lambda v: _intval(v) is not None and _intval(v) >= 12,
        "password_policy.history",
        "Set password history to remember at least 12 passwords"))
    cat3.append(_eval_control(
        "NIST-3.6", "Maximum password age <= 365 days", "MEDIUM",
        pp.get("max_age"), "<=365",
        lambda v: _intval(v) is not None and 1 <= _intval(v) <= 365,
        "password_policy.max_age",
        "Set maximum password age to 365 days or fewer"))

    # ===== Category 4: Authentication Mechanisms =====
    cat4 = []
    cat4.append(_rc("NIST-4.1", "NTLMv2 authentication enforced (level >= 5)", "CRITICAL",
                     "LmCompatibilityLevel",
                     lambda v: _intval(v) is not None and _intval(v) >= 5, ">=5",
                     "Set LmCompatibilityLevel to 5 (NTLMv2 only)"))
    cat4.append(_rc("NIST-4.2", "LM hash storage disabled", "HIGH",
                     "NoLMHash", lambda v: _intval(v) == 1, "1",
                     "Set NoLMHash to 1 to prevent LM hash storage"))
    cat4.append(_rc("NIST-4.3", "WDigest cleartext credentials disabled", "CRITICAL",
                     "WDigest_UseLogonCredential", lambda v: _intval(v) == 0, "0",
                     "Set WDigest UseLogonCredential to 0"))
    cat4.append(_rc("NIST-4.4", "LSA protection enabled", "HIGH",
                     "LSA_RunAsPPL", lambda v: _intval(v) == 1, "1",
                     "Enable LSA protection (RunAsPPL)"))
    cat4.append(_rc("NIST-4.5", "Credential Guard enabled", "HIGH",
                     "LsaCfgFlags", lambda v: _intval(v) == 1, "1",
                     "Enable Credential Guard via Group Policy"))
    cat4.append(_rc("NIST-4.6", "SMB signing required", "HIGH",
                     "RequireSecuritySignature", lambda v: _intval(v) == 1, "1",
                     "Enable mandatory SMB signing"))
    cat4.append(_eval_control(
        "NIST-4.7", "NLA required for RDP connections", "HIGH",
        rh.get("UserAuthentication"), "1",
        lambda v: _intval(v) == 1,
        "registry_hardening.UserAuthentication",
        "Require NLA for Remote Desktop connections"))

    # ===== Category 5: Resource Controls =====
    cat5 = []
    cat5.append(_eval_control(
        "NIST-5.1", "Domain firewall enabled", "HIGH",
        _fw_enabled(fw, "Domain"), "Enabled",
        lambda v: v is True, "firewall.profiles.Domain",
        "Enable the Domain firewall profile"))
    cat5.append(_eval_control(
        "NIST-5.2", "Private firewall enabled", "HIGH",
        _fw_enabled(fw, "Private"), "Enabled",
        lambda v: v is True, "firewall.profiles.Private",
        "Enable the Private firewall profile"))
    cat5.append(_eval_control(
        "NIST-5.3", "Public firewall enabled", "HIGH",
        _fw_enabled(fw, "Public"), "Enabled",
        lambda v: v is True, "firewall.profiles.Public",
        "Enable the Public firewall profile"))
    cat5.append(_rc("NIST-5.4", "SMBv1 protocol disabled", "HIGH",
                     "SMB1", lambda v: _intval(v) == 0, "0",
                     "Disable SMBv1 protocol"))
    netbios = nc.get("netbios_over_tcpip")
    cat5.append(_eval_control(
        "NIST-5.5", "NetBIOS over TCP/IP disabled", "MEDIUM",
        netbios if netbios is not None else None, "False",
        lambda v: v is False or v == 0 or str(v).lower() in ("false", "0", "disabled"),
        "network_config.netbios_over_tcpip",
        "Disable NetBIOS over TCP/IP on each network adapter"))

    # ===== Category 6: Logging & Monitoring =====
    cat6 = []
    cat6.append(_eval_control(
        "NIST-6.1", "Audit logon events configured", "HIGH",
        _audit_val(ap, "Audit Logon", "Logon", "audit_logon"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Logon",
        "Enable logon event auditing via auditpol"))
    cat6.append(_eval_control(
        "NIST-6.2", "Audit account management configured", "HIGH",
        _audit_val(ap, "Audit Account Management", "Account Management",
                   "audit_account_management"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Account Management",
        "Enable account management auditing via auditpol"))
    cat6.append(_eval_control(
        "NIST-6.3", "Audit object access configured", "MEDIUM",
        _audit_val(ap, "Audit Object Access", "Object Access",
                   "audit_object_access"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Object Access",
        "Enable object access auditing via auditpol"))
    cat6.append(_rc("NIST-6.4", "PowerShell script block logging enabled", "HIGH",
                     "ScriptBlockLogging", lambda v: _intval(v) == 1, "1",
                     "Enable PowerShell script block logging via Group Policy"))
    cat6.append(_rc("NIST-6.5", "PowerShell transcription enabled", "MEDIUM",
                     "Transcription", lambda v: _intval(v) == 1, "1",
                     "Enable PowerShell transcription via Group Policy"))
    cat6.append(_eval_control(
        "NIST-6.6", "Event Log service running", "HIGH",
        _svc_running(services, "EventLog"), "Running",
        lambda v: v is True, "services.EventLog",
        "Ensure the Windows Event Log service is running"))

    # ===== Category 7: Network Configuration =====
    cat7 = []
    cat7.append(_rc("NIST-7.1", "LLMNR disabled", "HIGH",
                     "EnableMulticast", lambda v: _intval(v) == 0, "0",
                     "Disable LLMNR via Group Policy > DNS Client"))
    wpad = rh.get("WpadOverride") or rh.get("WPADOverride")
    cat7.append(_eval_control(
        "NIST-7.2", "WPAD disabled", "HIGH",
        wpad, "True/Disabled",
        lambda v: v is True or v == 1 or str(v).lower() in ("true", "1", "disabled"),
        "registry_hardening.WpadOverride",
        "Disable WPAD via registry"))
    _HIGH_RISK = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 5985}
    hr_ports = []
    if isinstance(op, list):
        for p in op:
            if isinstance(p, dict):
                pn = p.get("port", 0)
                if _safe(p.get("state")).upper() == "LISTENING" and pn in _HIGH_RISK:
                    hr_ports.append(pn)
    hr_count = len(hr_ports) if isinstance(op, list) and op else None
    cat7.append(_eval_control(
        "NIST-7.3", "No high-risk ports exposed (FTP/Telnet/RDP/SMB/etc.)", "HIGH",
        hr_count, "0",
        lambda v: _intval(v) == 0,
        "open_ports",
        f"Close or restrict high-risk listening ports: {hr_ports}" if hr_ports
        else "Close or restrict high-risk listening ports"))
    cat7.append(_rc("NIST-7.4", "IP source routing disabled", "MEDIUM",
                     "DisableIPSourceRouting",
                     lambda v: _intval(v) is not None and _intval(v) >= 2, "2",
                     "Set DisableIPSourceRouting to 2"))
    cat7.append(_rc("NIST-7.5", "ICMP redirects disabled", "MEDIUM",
                     "AllowICMPRedirect", lambda v: _intval(v) == 0, "0",
                     "Set AllowICMPRedirect to 0"))

    # ===== Category 8: Malware Protection =====
    cat8 = []
    av_products = dd.get("av_products", [])
    av_installed = None
    if isinstance(dd, dict) and dd:
        av_installed = isinstance(av_products, list) and len(av_products) > 0
    cat8.append(_eval_control(
        "NIST-8.1", "Antivirus product installed", "CRITICAL",
        av_installed, "True",
        lambda v: v is True,
        "defender_detailed.av_products",
        "Install an antivirus/endpoint protection product"))
    rt_disabled = dd.get("realtime_monitoring_disabled")
    rt_val = None
    if rt_disabled is not None:
        rt_val = not rt_disabled
    cat8.append(_eval_control(
        "NIST-8.2", "Real-time protection enabled", "CRITICAL",
        rt_val, "True",
        lambda v: v is True,
        "defender_detailed.realtime_monitoring_disabled",
        "Enable real-time monitoring in antivirus software"))
    cat8.append(_rc("NIST-8.3", "Defender not disabled via policy", "CRITICAL",
                     "defender_disabled", lambda v: _intval(v) == 0, "0",
                     "Remove DisableAntiSpyware policy; set to 0"))
    cat8.append(_eval_control(
        "NIST-8.4", "Windows Defender service running", "HIGH",
        _svc_running(services, "WinDefend"), "Running",
        lambda v: v is True, "services.WinDefend",
        "Start the Windows Defender (WinDefend) service"))
    cat8.append(_rc("NIST-8.5", "AutoRun disabled", "MEDIUM",
                     "NoDriveTypeAutoRun",
                     lambda v: _intval(v) is not None and _intval(v) == 255, "255",
                     "Set NoDriveTypeAutoRun to 255 to block all AutoRun"))

    categories = [
        _finalize_category("1", "OS Patching & Updates", cat1),
        _finalize_category("2", "Unnecessary Services", cat2),
        _finalize_category("3", "User Account Management", cat3),
        _finalize_category("4", "Authentication Mechanisms", cat4),
        _finalize_category("5", "Resource Controls", cat5),
        _finalize_category("6", "Logging & Monitoring", cat6),
        _finalize_category("7", "Network Configuration", cat7),
        _finalize_category("8", "Malware Protection", cat8),
    ]
    return _finalize_assessment("NIST SP 800-123", "Windows Server", categories)


# ---------------------------------------------------------------------------
# DISA STIG -- Windows Server
# ---------------------------------------------------------------------------

def _build_stig_assessment(data):
    rh = data.get("registry_hardening", {})
    if not isinstance(rh, dict):
        rh = {}
    sp = data.get("security_policy", {})
    if not isinstance(sp, dict):
        sp = {}
    services = data.get("services", [])
    fw = data.get("firewall", {})
    dd = data.get("defender_detailed", {})
    if not isinstance(dd, dict):
        dd = {}
    pe = data.get("privilege_escalation", {})
    if not isinstance(pe, dict):
        pe = {}
    si = data.get("system_info", {})
    if not isinstance(si, dict):
        si = {}
    nc = data.get("network_config", {})
    if not isinstance(nc, dict):
        nc = {}
    op = data.get("open_ports", [])
    ua = data.get("user_accounts", {})
    if not isinstance(ua, dict):
        ua = {}
    ad = data.get("active_directory", {})
    if not isinstance(ad, dict):
        ad = {}

    if not rh and not sp and not isinstance(services, list):
        return None

    pp = sp.get("password_policy", {})
    if not isinstance(pp, dict):
        pp = {}
    lp = sp.get("lockout_policy", {})
    if not isinstance(lp, dict):
        lp = {}
    ap = sp.get("audit_policy", {})
    if not isinstance(ap, dict):
        ap = {}

    def _rc(ctrl_id, title, sev, key, check_fn, expected_str, remed):
        return _eval_control(ctrl_id, title, sev, rh.get(key), expected_str,
                             check_fn, f"registry_hardening.{key}", remed)

    def _sd(ctrl_id, title, sev, svc_name, remed):
        return _eval_control(ctrl_id, title, sev, _svc_running(services, svc_name),
                             "Not running", lambda v: not v,
                             f"services.{svc_name}", remed)

    # ===== Category 1: Account Management =====
    cat1 = []
    cat1.append(_eval_control(
        "STIG-1.1", "Minimum password length >= 14", "HIGH",
        pp.get("min_length"), ">=14",
        lambda v: _intval(v) is not None and _intval(v) >= 14,
        "password_policy.min_length",
        "Configure minimum password length to 14 characters"))
    cat1.append(_eval_control(
        "STIG-1.2", "Password complexity enabled", "HIGH",
        pp.get("complexity_enabled"), "True",
        lambda v: v is True or v == 1 or str(v).lower() in ("true", "1", "yes"),
        "password_policy.complexity_enabled",
        "Enable password complexity requirements"))
    cat1.append(_eval_control(
        "STIG-1.3", "Password history >= 24", "MEDIUM",
        pp.get("history"), ">=24",
        lambda v: _intval(v) is not None and _intval(v) >= 24,
        "password_policy.history",
        "Set password history to remember 24 or more passwords"))
    cat1.append(_eval_control(
        "STIG-1.4", "Maximum password age <= 60 days", "MEDIUM",
        pp.get("max_age"), "<=60",
        lambda v: _intval(v) is not None and 1 <= _intval(v) <= 60,
        "password_policy.max_age",
        "Set maximum password age to 60 days or fewer"))
    cat1.append(_eval_control(
        "STIG-1.5", "Minimum password age >= 1 day", "LOW",
        pp.get("min_age"), ">=1",
        lambda v: _intval(v) is not None and _intval(v) >= 1,
        "password_policy.min_age",
        "Set minimum password age to 1 day"))
    cat1.append(_eval_control(
        "STIG-1.6", "Account lockout threshold <= 3 attempts", "HIGH",
        lp.get("threshold"), "<=3",
        lambda v: _intval(v) is not None and 1 <= _intval(v) <= 3,
        "lockout_policy.threshold",
        "Set account lockout threshold to 3 or fewer attempts"))
    cat1.append(_eval_control(
        "STIG-1.7", "Account lockout duration >= 15 minutes", "MEDIUM",
        lp.get("duration"), ">=15",
        lambda v: _intval(v) is not None and _intval(v) >= 15,
        "lockout_policy.duration",
        "Set account lockout duration to 15 minutes or more"))
    admins = ua.get("administrators_group", [])
    admin_count = len(admins) if isinstance(admins, list) else None
    cat1.append(_eval_control(
        "STIG-1.8", "Limit local administrator accounts", "HIGH",
        admin_count, "<=3",
        lambda v: _intval(v) is not None and _intval(v) <= 3,
        "user_accounts.administrators_group",
        "Reduce local Administrators group to essential accounts only"))

    # ===== Category 2: Access Control =====
    cat2 = []
    cat2.append(_rc("STIG-2.1", "UAC enabled (EnableLUA)", "CRITICAL",
                     "EnableLUA", lambda v: _intval(v) == 1, "1",
                     "Enable User Account Control"))
    cat2.append(_rc("STIG-2.2", "UAC: Admin approval mode for built-in admin", "HIGH",
                     "FilterAdministratorToken", lambda v: _intval(v) == 1, "1",
                     "Enable Admin Approval Mode for built-in Administrator"))
    cat2.append(_rc("STIG-2.3", "UAC: ConsentPromptBehaviorAdmin", "HIGH",
                     "ConsentPromptBehaviorAdmin",
                     lambda v: _intval(v) is not None and _intval(v) <= 2, "<=2",
                     "Set admin consent prompt to secure level"))
    aie_hklm = pe.get("always_install_elevated_hklm")
    aie_hkcu = pe.get("always_install_elevated_hkcu")
    aie_val = None
    if aie_hklm is not None or aie_hkcu is not None:
        aie_val = (aie_hklm == 1 or aie_hkcu == 1)
    cat2.append(_eval_control(
        "STIG-2.4", "AlwaysInstallElevated disabled", "CRITICAL",
        aie_val, "False (disabled)",
        lambda v: v is False or v == 0,
        "privilege_escalation.always_install_elevated",
        "Set AlwaysInstallElevated to 0 in both HKLM and HKCU"))
    cat2.append(_rc("STIG-2.5", "RDP: Network Level Authentication required", "HIGH",
                     "UserAuthentication", lambda v: _intval(v) == 1, "1",
                     "Require NLA for Remote Desktop"))
    cat2.append(_rc("STIG-2.6", "Restrict anonymous access", "HIGH",
                     "RestrictAnonymous",
                     lambda v: _intval(v) is not None and _intval(v) >= 1, ">=1",
                     "Set RestrictAnonymous to 1 or higher"))
    cat2.append(_rc("STIG-2.7", "Restrict anonymous SAM enumeration", "HIGH",
                     "RestrictAnonymousSAM", lambda v: _intval(v) == 1, "1",
                     "Set RestrictAnonymousSAM to 1"))
    cat2.append(_rc("STIG-2.8", "No null session pipes", "HIGH",
                     "NullSessionPipes",
                     lambda v: not v or (isinstance(v, str) and not v.strip()),
                     "Empty", "Clear null session pipes list"))

    # ===== Category 3: Audit and Accountability =====
    cat3 = []
    cat3.append(_eval_control(
        "STIG-3.1", "Audit logon events", "HIGH",
        _audit_val(ap, "Audit Logon", "Logon", "audit_logon"),
        "Success and Failure",
        lambda v: "success" in str(v).lower() and "failure" in str(v).lower(),
        "audit_policy.Logon",
        "Enable Logon auditing for both Success and Failure"))
    cat3.append(_eval_control(
        "STIG-3.2", "Audit account management", "HIGH",
        _audit_val(ap, "Audit Account Management", "Account Management",
                   "audit_account_management"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Account Management",
        "Enable Account Management auditing"))
    cat3.append(_eval_control(
        "STIG-3.3", "Audit policy change", "HIGH",
        _audit_val(ap, "Audit Policy Change", "Policy Change",
                   "audit_policy_change"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Policy Change",
        "Enable Policy Change auditing"))
    cat3.append(_eval_control(
        "STIG-3.4", "Audit privilege use", "HIGH",
        _audit_val(ap, "Audit Privilege Use", "Sensitive Privilege Use",
                   "Privilege Use", "audit_privilege_use"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Privilege Use",
        "Enable Privilege Use auditing"))
    cat3.append(_eval_control(
        "STIG-3.5", "Audit object access", "MEDIUM",
        _audit_val(ap, "Audit Object Access", "Object Access",
                   "audit_object_access"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.Object Access",
        "Enable Object Access auditing"))
    cat3.append(_eval_control(
        "STIG-3.6", "Audit system events", "MEDIUM",
        _audit_val(ap, "Audit System Events", "Security State Change",
                   "System", "audit_system"),
        "Success and Failure",
        lambda v: "success" in str(v).lower(),
        "audit_policy.System Events",
        "Enable System Events auditing"))
    cat3.append(_rc("STIG-3.7", "PowerShell script block logging enabled", "HIGH",
                     "ScriptBlockLogging", lambda v: _intval(v) == 1, "1",
                     "Enable PowerShell script block logging"))
    cat3.append(_rc("STIG-3.8", "PowerShell module logging enabled", "MEDIUM",
                     "ModuleLogging", lambda v: _intval(v) == 1, "1",
                     "Enable PowerShell module logging"))

    # ===== Category 4: Configuration Management =====
    cat4 = []
    secure_boot = si.get("secure_boot")
    cat4.append(_eval_control(
        "STIG-4.1", "Secure Boot enabled", "HIGH",
        secure_boot, "True",
        lambda v: v is True,
        "system_info.secure_boot",
        "Enable Secure Boot in UEFI firmware settings"))
    tpm = si.get("tpm", {})
    tpm_present = None
    if isinstance(tpm, dict) and tpm:
        tpm_present = tpm.get("present", tpm.get("is_present",
                     tpm.get("activated", bool(tpm))))
    elif isinstance(tpm, bool):
        tpm_present = tpm
    cat4.append(_eval_control(
        "STIG-4.2", "TPM present and activated", "HIGH",
        tpm_present, "True",
        lambda v: v is True or v == 1,
        "system_info.tpm",
        "Enable and activate the TPM in BIOS/UEFI"))
    cat4.append(_rc("STIG-4.3", "DEP/NX policy set to OptOut or AlwaysOn", "HIGH",
                     "nx_policy",
                     lambda v: str(v).lower() in ("optout", "alwayson"),
                     "OptOut",
                     "Set DEP to OptOut via bcdedit"))
    cat4.append(_rc("STIG-4.4", "AutoRun disabled for all drives", "HIGH",
                     "NoDriveTypeAutoRun",
                     lambda v: _intval(v) is not None and _intval(v) == 255, "255",
                     "Set NoDriveTypeAutoRun to 255"))
    cat4.append(_sd("STIG-4.5", "Print Spooler stopped unless required", "MEDIUM",
                     "Spooler",
                     "Disable Print Spooler service if printing not needed"))
    cat4.append(_sd("STIG-4.6", "Xbox services stopped on server", "LOW",
                     "XblAuthManager", "Disable Xbox services on servers"))
    cat4.append(_eval_control(
        "STIG-4.7", "Windows Time service running", "MEDIUM",
        _svc_running(services, "W32Time"), "Running",
        lambda v: v is True, "services.W32Time",
        "Enable Windows Time (W32Time) service for time synchronization"))
    cat4.append(_rc("STIG-4.8", "SMBv1 protocol disabled", "CRITICAL",
                     "SMB1", lambda v: _intval(v) == 0, "0",
                     "Disable SMBv1 via Disable-WindowsOptionalFeature"))

    # ===== Category 5: Identification and Authentication =====
    cat5 = []
    cat5.append(_rc("STIG-5.1", "NTLMv2 authentication enforced (level >= 5)", "CRITICAL",
                     "LmCompatibilityLevel",
                     lambda v: _intval(v) is not None and _intval(v) >= 5, ">=5",
                     "Set LmCompatibilityLevel to 5"))
    cat5.append(_rc("STIG-5.2", "LM hash storage disabled", "HIGH",
                     "NoLMHash", lambda v: _intval(v) == 1, "1",
                     "Set NoLMHash to 1"))
    cat5.append(_rc("STIG-5.3", "LSA protection enabled (RunAsPPL)", "CRITICAL",
                     "LSA_RunAsPPL", lambda v: _intval(v) == 1, "1",
                     "Enable LSA RunAsPPL protection"))
    cat5.append(_rc("STIG-5.4", "WDigest cleartext credentials disabled", "CRITICAL",
                     "WDigest_UseLogonCredential", lambda v: _intval(v) == 0, "0",
                     "Set WDigest UseLogonCredential to 0"))
    cat5.append(_rc("STIG-5.5", "Credential Guard enabled", "HIGH",
                     "LsaCfgFlags", lambda v: _intval(v) == 1, "1",
                     "Enable Credential Guard via Device Guard"))
    cat5.append(_eval_control(
        "STIG-5.6", "Everyone does not include anonymous", "HIGH",
        rh.get("EveryoneIncludesAnonymous"), "0",
        lambda v: _intval(v) == 0,
        "registry_hardening.EveryoneIncludesAnonymous",
        "Set EveryoneIncludesAnonymous to 0"))
    legal = rh.get("LegalNoticeCaption") or rh.get("LegalNoticeText")
    cat5.append(_eval_control(
        "STIG-5.7", "DoD login banner configured", "MEDIUM",
        legal, "Non-empty",
        lambda v: bool(v) and str(v).strip() != "",
        "registry_hardening.LegalNoticeCaption",
        "Configure the interactive logon legal notice via Group Policy"))
    cat5.append(_rc("STIG-5.8", "RDP NLA required", "HIGH",
                     "UserAuthentication", lambda v: _intval(v) == 1, "1",
                     "Require Network Level Authentication for RDP"))

    # ===== Category 6: System and Communications Protection =====
    cat6 = []
    cat6.append(_rc("STIG-6.1", "SMB signing required", "HIGH",
                     "RequireSecuritySignature", lambda v: _intval(v) == 1, "1",
                     "Enable mandatory SMB signing"))
    ldap_val = rh.get("LDAPClientIntegrity")
    if ldap_val is None:
        ls = ad.get("ldap_signing", {})
        if isinstance(ls, dict):
            ldap_val = ls.get("client_signing") or ls.get("require_signing")
    cat6.append(_eval_control(
        "STIG-6.2", "LDAP client signing required", "HIGH",
        ldap_val, ">=1",
        lambda v: _intval(v) is not None and _intval(v) >= 1,
        "registry_hardening.LDAPClientIntegrity",
        "Set LDAP client signing to Negotiate or Require"))
    cat6.append(_eval_control(
        "STIG-6.3", "Domain firewall enabled", "HIGH",
        _fw_enabled(fw, "Domain"), "Enabled",
        lambda v: v is True, "firewall.profiles.Domain",
        "Enable the Domain firewall profile"))
    cat6.append(_eval_control(
        "STIG-6.4", "Private firewall enabled", "HIGH",
        _fw_enabled(fw, "Private"), "Enabled",
        lambda v: v is True, "firewall.profiles.Private",
        "Enable the Private firewall profile"))
    cat6.append(_eval_control(
        "STIG-6.5", "Public firewall enabled", "HIGH",
        _fw_enabled(fw, "Public"), "Enabled",
        lambda v: v is True, "firewall.profiles.Public",
        "Enable the Public firewall profile"))
    cat6.append(_rc("STIG-6.6", "LLMNR disabled", "HIGH",
                     "EnableMulticast", lambda v: _intval(v) == 0, "0",
                     "Disable LLMNR via Group Policy"))
    wpad = rh.get("WpadOverride") or rh.get("WPADOverride")
    cat6.append(_eval_control(
        "STIG-6.7", "WPAD disabled", "HIGH",
        wpad, "True/Disabled",
        lambda v: v is True or v == 1 or str(v).lower() in ("true", "1", "disabled"),
        "registry_hardening.WpadOverride",
        "Disable WPAD via registry"))
    cat6.append(_rc("STIG-6.8", "IP source routing disabled", "MEDIUM",
                     "DisableIPSourceRouting",
                     lambda v: _intval(v) is not None and _intval(v) >= 2, "2",
                     "Set DisableIPSourceRouting to 2"))
    cat6.append(_rc("STIG-6.9", "VBS enabled", "HIGH",
                     "EnableVirtualizationBasedSecurity",
                     lambda v: _intval(v) == 1, "1",
                     "Enable Virtualization Based Security via Group Policy"))

    # ===== Category 7: System and Information Integrity =====
    cat7 = []
    av_products = dd.get("av_products", [])
    av_installed = None
    if isinstance(dd, dict) and dd:
        av_installed = isinstance(av_products, list) and len(av_products) > 0
    cat7.append(_eval_control(
        "STIG-7.1", "Antivirus/endpoint protection installed", "CRITICAL",
        av_installed, "True",
        lambda v: v is True,
        "defender_detailed.av_products",
        "Install an antivirus/endpoint protection product"))
    rt_disabled = dd.get("realtime_monitoring_disabled")
    rt_val = None
    if rt_disabled is not None:
        rt_val = not rt_disabled
    cat7.append(_eval_control(
        "STIG-7.2", "Real-time protection enabled", "CRITICAL",
        rt_val, "True",
        lambda v: v is True,
        "defender_detailed.realtime_monitoring_disabled",
        "Enable real-time monitoring in the AV product"))
    cat7.append(_rc("STIG-7.3", "Defender not disabled via policy", "CRITICAL",
                     "defender_disabled", lambda v: _intval(v) == 0, "0",
                     "Remove/reset DisableAntiSpyware registry key"))
    uptime = si.get("uptime_days")
    cat7.append(_eval_control(
        "STIG-7.4", "System rebooted within last 30 days (updates applied)", "HIGH",
        uptime, "<=30 days",
        lambda v: _intval(v) is not None and _intval(v) <= 30,
        "system_info.uptime_days",
        "Reboot to apply pending security updates"))
    cat7.append(_rc("STIG-7.5", "HVCI enabled", "HIGH",
                     "HypervisorEnforcedCodeIntegrity",
                     lambda v: _intval(v) == 1, "1",
                     "Enable Hypervisor-enforced Code Integrity"))
    cat7.append(_eval_control(
        "STIG-7.6", "Windows Defender service running", "HIGH",
        _svc_running(services, "WinDefend"), "Running",
        lambda v: v is True, "services.WinDefend",
        "Start the Windows Defender service"))
    cat7.append(_rc("STIG-7.7", "PowerShell transcription enabled", "MEDIUM",
                     "Transcription", lambda v: _intval(v) == 1, "1",
                     "Enable PowerShell transcription for forensic capability"))

    categories = [
        _finalize_category("1", "Account Management", cat1),
        _finalize_category("2", "Access Control", cat2),
        _finalize_category("3", "Audit and Accountability", cat3),
        _finalize_category("4", "Configuration Management", cat4),
        _finalize_category("5", "Identification and Authentication", cat5),
        _finalize_category("6", "System and Communications Protection", cat6),
        _finalize_category("7", "System and Information Integrity", cat7),
    ]
    return _finalize_assessment("DISA STIG", "Windows Server", categories)


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
        ("cis_assessment.json", _build_cis_assessment),
        ("nist_assessment.json", _build_nist_assessment),
        ("stig_assessment.json", _build_stig_assessment),
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
