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
        # UAC
        "EnableLUA": (1, "UAC enabled"),
        "ConsentPromptBehaviorAdmin": (2, "Prompt for consent on secure desktop"),
        "EnableInstallerDetection": (1, "Installer detection enabled"),
        "FilterAdministratorToken": (1, "Filter admin token for built-in admin"),
        "PromptOnSecureDesktop": (1, "Prompt on secure desktop"),
        "ValidateAdminCodeSignatures": (1, "Validate admin code signatures"),
        "EnableSecureUIAPaths": (1, "Secure UIA paths enabled"),
        "EnableVirtualization": (1, "File/registry virtualization enabled"),
        # Authentication
        "LmCompatibilityLevel": (5, "Send NTLMv2 only / refuse LM & NTLM"),
        "NoLMHash": (1, "Do not store LM hash"),
        "UseLogonCredential": (0, "WDigest cleartext disabled"),
        "RunAsPPL": (1, "LSA runs as protected process"),
        "RestrictAnonymous": (1, "Restrict anonymous access"),
        "RestrictAnonymousSAM": (1, "Restrict anonymous SAM enumeration"),
        "EveryoneIncludesAnonymous": (0, "Everyone does not include anonymous"),
        "LimitBlankPasswordUse": (1, "Blank password logon restricted"),
        "ForceGuest": (0, "Classic sharing model (not Guest-only)"),
        "DisableDomainCreds": (0, "Allow caching of domain credentials"),
        "SCENoApplyLegacyAuditPolicy": (1, "Force advanced audit policy subcategories"),
        # SMB Server
        "SMB1": (0, "SMBv1 disabled"),
        "RequireSecuritySignature": (1, "SMB server signing required"),
        "NullSessionPipes": (0, "No null session pipes"),
        "NullSessionShares": (0, "No null session shares"),
        "RestrictNullSessAccess": (1, "Restrict null session access"),
        "AutoDisconnect": (15, "Auto-disconnect idle sessions (15 min)"),
        "EnableSecuritySignature": (1, "SMB server signing enabled"),
        # SMB Client
        "SMBClient_RequireSecuritySignature": (1, "SMB client signing required"),
        "SMBClient_EnableSecuritySignature": (1, "SMB client signing enabled"),
        "ConsentPromptBehaviorUser": (3, "Standard user elevation prompt: deny"),
        # RDP
        "fDenyTSConnections": (0, "RDP access controlled (0=allowed if needed)"),
        "UserAuthentication": (1, "NLA required for RDP"),
        "MinEncryptionLevel": (3, "RDP encryption set to High"),
        "SecurityLayer": (2, "RDP uses TLS security layer"),
        # Device Guard / Credential Guard
        "EnableVirtualizationBasedSecurity": (1, "Virtualization-Based Security enabled"),
        "HypervisorEnforcedCodeIntegrity": (1, "HVCI enabled"),
        "LsaCfgFlags": (1, "Credential Guard enabled"),
        # PowerShell
        "ScriptBlockLogging": (1, "PowerShell script block logging enabled"),
        "ModuleLogging": (1, "PowerShell module logging enabled"),
        "Transcription": (1, "PowerShell transcription enabled"),
        # Network
        "EnableMulticast": (0, "LLMNR disabled"),
        "NoDriveTypeAutoRun": (255, "AutoRun disabled on all drives"),
        # Defender
        "defender_disabled": (0, "Windows Defender enabled"),
        "real_time_protection": (0, "Real-time protection enabled"),
        # SMB Client (new — from assembler additions)
        "SMBClient_EnablePlainTextPassword": (0, "SMB client plain-text password disabled"),
        # SMB Server additional
        "SMBServer_EnableSecuritySignature": (1, "SMB server signing enabled (if client agrees)"),
    }

    _SKIP_KEYS = {"audit_policy", "audit_policy_raw", "defender_exclusions",
                   "nx_policy", "WpadOverride"}

    items = []
    if isinstance(rh, dict):
        for setting, current_val in rh.items():
            if setting in _SKIP_KEYS or isinstance(current_val, (list, dict)):
                continue
            rec = _RECOMMENDED.get(setting)
            if rec:
                rec_val, rec_desc = rec
                compliant = current_val == rec_val if current_val is not None else False
                items.append({
                    "setting": setting,
                    "current_value": current_val,
                    "recommended_value": rec_val,
                    "recommendation": rec_desc,
                    "compliant": compliant,
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


_CIS_AUDIT_POLICY_REQUIREMENTS = {
    "System": {
        "Security System Extension": "Success",
        "System Integrity": "Success and Failure",
        "Security State Change": "Success",
    },
    "Logon/Logoff": {
        "Logon": "Success and Failure",
        "Logoff": "Success",
        "Account Lockout": "Failure",
        "Special Logon": "Success",
        "Other Logon/Logoff Events": "Success and Failure",
    },
    "Object Access": {
        "Removable Storage": "Success and Failure",
    },
    "Privilege Use": {
        "Sensitive Privilege Use": "Success and Failure",
    },
    "Detailed Tracking": {
        "Process Creation": "Success",
    },
    "Policy Change": {
        "Audit Policy Change": "Success and Failure",
        "Authentication Policy Change": "Success",
        "Authorization Policy Change": "Success",
    },
    "Account Management": {
        "User Account Management": "Success and Failure",
        "Security Group Management": "Success",
        "Computer Account Management": "Success",
        "Other Account Management Events": "Success and Failure",
    },
    "DS Access": {
        "Directory Service Access": "Success and Failure",
        "Directory Service Changes": "Success and Failure",
    },
    "Account Logon": {
        "Credential Validation": "Success and Failure",
        "Kerberos Authentication Service": "Success and Failure",
        "Kerberos Service Ticket Operations": "Success and Failure",
    },
}


def _audit_setting_meets(actual, required):
    if not actual or actual == "No Auditing":
        return False
    if required == actual:
        return True
    if required in ("Success", "Failure") and actual == "Success and Failure":
        return True
    return False


def _build_cis_compliance(data):
    rh = data.get("registry_hardening", {})
    sp = data.get("security_policy", {})
    fw = data.get("firewall", {})
    si = data.get("system_info", {})
    if not isinstance(rh, dict):
        rh = {}
    if not isinstance(sp, dict):
        sp = {}

    controls = []

    def _add(cis_id, section, title, status, current, expected, severity="L1"):
        controls.append({
            "id": cis_id, "section": section, "title": title,
            "status": status, "current": str(current) if current is not None else "Not configured",
            "expected": str(expected), "severity": severity,
        })

    # 1. Account Policies
    pp = sp.get("password_policy", {})
    if isinstance(pp, dict):
        ml = pp.get("minimum_password_length", "")
        ml_int = int(ml) if str(ml).isdigit() else 0
        _add("1.1.4", "Account Policies", "Minimum password length >= 14",
             "Pass" if ml_int >= 14 else "Fail", ml, "14+")
        ma = pp.get("maximum_password_age", "")
        ma_int = int(ma) if str(ma).isdigit() else 999
        _add("1.1.2", "Account Policies", "Maximum password age <= 365 days",
             "Pass" if 0 < ma_int <= 365 else "Fail", ma, "1-365")
        mia = pp.get("minimum_password_age", "")
        mia_int = int(mia) if str(mia).isdigit() else 0
        _add("1.1.3", "Account Policies", "Minimum password age >= 1 day",
             "Pass" if mia_int >= 1 else "Fail", mia, "1+")
        ph = pp.get("password_history_count", "")
        ph_int = int(ph) if str(ph).isdigit() else 0
        _add("1.1.1", "Account Policies", "Password history >= 24",
             "Pass" if ph_int >= 24 else "Fail", ph, "24+")

    lp = sp.get("lockout_policy", {})
    if isinstance(lp, dict):
        lt = lp.get("lockout_threshold", "")
        lt_int = int(lt) if str(lt).isdigit() else 0
        _add("1.2.1", "Account Policies", "Account lockout threshold <= 5",
             "Pass" if 0 < lt_int <= 5 else "Fail", lt, "1-5")
        ld = lp.get("lockout_duration", "")
        ld_int = int(ld) if str(ld).isdigit() else 0
        _add("1.2.2", "Account Policies", "Account lockout duration >= 15 min",
             "Pass" if ld_int >= 15 else "Fail", ld, "15+")

    # 2. Local Policies — Security Options
    _CIS_REGISTRY = [
        ("2.3.1.1", "Security Options", "Accounts: Block Microsoft accounts", "NoConnectedUser", 3, "L1"),
        ("2.3.1.2", "Security Options", "Accounts: Guest account status", None, None, "L1"),
        ("2.3.1.5", "Security Options", "Accounts: Limit local use of blank passwords", "LimitBlankPasswordUse", 1, "L1"),
        ("2.3.2.1", "Security Options", "Audit: Force audit subcategory settings", "SCENoApplyLegacyAuditPolicy", 1, "L1"),
        ("2.3.7.1", "Security Options", "Interactive logon: Do not display last user", None, None, "L1"),
        ("2.3.8.1", "Security Options", "MS Network Client: Digitally sign (always)", "SMBClient_RequireSecuritySignature", 1, "L1"),
        ("2.3.8.2", "Security Options", "MS Network Client: Digitally sign (if server agrees)", "SMBClient_EnableSecuritySignature", 1, "L1"),
        ("2.3.9.1", "Security Options", "MS Network Server: Idle time before disconnect", "AutoDisconnect", 15, "L1"),
        ("2.3.9.2", "Security Options", "MS Network Server: Digitally sign (always)", "RequireSecuritySignature", 1, "L1"),
        ("2.3.9.3", "Security Options", "MS Network Server: Digitally sign (if client agrees)", "EnableSecuritySignature", 1, "L1"),
        ("2.3.10.2", "Security Options", "Network access: No anonymous SAM enumeration", "RestrictAnonymousSAM", 1, "L1"),
        ("2.3.10.4", "Security Options", "Network access: Restrict anonymous access", "RestrictAnonymous", 1, "L1"),
        ("2.3.10.7", "Security Options", "Network access: Restrict null session pipes", "NullSessionPipes", 0, "L1"),
        ("2.3.10.10", "Security Options", "Network access: Restrict null session access", "RestrictNullSessAccess", 1, "L1"),
        ("2.3.11.4", "Security Options", "Network security: LAN Manager auth level", "LmCompatibilityLevel", 5, "L1"),
        ("2.3.11.7", "Security Options", "Network security: Do not store LM hash", "NoLMHash", 1, "L1"),
        ("2.3.17.1", "Security Options", "UAC: Admin Approval Mode for built-in admin", "FilterAdministratorToken", 1, "L1"),
        ("2.3.17.2", "Security Options", "UAC: Behavior of elevation prompt (admin)", "ConsentPromptBehaviorAdmin", 2, "L1"),
        ("2.3.17.4", "Security Options", "UAC: Detect application installations", "EnableInstallerDetection", 1, "L1"),
        ("2.3.17.5", "Security Options", "UAC: Only elevate signed executables", "ValidateAdminCodeSignatures", 0, "L1"),
        ("2.3.17.6", "Security Options", "UAC: Only elevate UIAccess for secure locations", "EnableSecureUIAPaths", 1, "L1"),
        ("2.3.17.7", "Security Options", "UAC: Run admins in Admin Approval Mode", "EnableLUA", 1, "L1"),
        ("2.3.17.8", "Security Options", "UAC: Switch to secure desktop for elevation", "PromptOnSecureDesktop", 1, "L1"),
    ]
    for cis_id, section, title, key, expected, severity in _CIS_REGISTRY:
        if key is None:
            continue
        current = rh.get(key)
        status = "Pass" if current == expected else ("Fail" if current is not None else "Not Configured")
        _add(cis_id, section, title, status, current, expected, severity)

    # 9. Windows Firewall
    if isinstance(fw, dict):
        profiles = fw.get("profiles", {})
        for pname, pdata in (profiles.items() if isinstance(profiles, dict) else []):
            pval = pdata.get("State", pdata.get("enabled", "")) if isinstance(pdata, dict) else ""
            is_on = str(pval).lower() in ("on", "true", "1", "enabled")
            _add(f"9.1.{pname[:3].lower()}", "Windows Firewall",
                 f"Firewall {pname} profile enabled", "Pass" if is_on else "Fail",
                 pval, "ON")

    # 17. Advanced Audit Policy
    audit = rh.get("audit_policy", {})
    if isinstance(audit, dict):
        for cat, subs in _CIS_AUDIT_POLICY_REQUIREMENTS.items():
            cat_data = audit.get(cat, {})
            if not isinstance(cat_data, dict):
                continue
            for sub, required in subs.items():
                actual = cat_data.get(sub, "No Auditing")
                status = "Pass" if _audit_setting_meets(actual, required) else "Fail"
                _add(f"17.{cat[:4]}", "Advanced Audit Policy",
                     f"{cat} > {sub} includes '{required}'",
                     status, actual, required)

    # 18.x Registry / MSS
    _add("18.3.6", "MSS Settings", "SMBv1 protocol disabled",
         "Pass" if rh.get("SMB1") == 0 else "Fail", rh.get("SMB1"), 0)
    _add("18.4.4", "MSS Settings", "WDigest Authentication disabled",
         "Pass" if rh.get("UseLogonCredential") == 0 else "Fail",
         rh.get("UseLogonCredential"), 0)
    _add("18.8.3", "Admin Templates", "LSASS as Protected Process",
         "Pass" if rh.get("RunAsPPL") == 1 else "Fail", rh.get("RunAsPPL"), 1)
    _add("18.9.100", "Admin Templates", "PowerShell Script Block Logging",
         "Pass" if rh.get("ScriptBlockLogging") == 1 else "Fail",
         rh.get("ScriptBlockLogging"), 1)
    _add("18.9.100", "Admin Templates", "PowerShell Module Logging",
         "Pass" if rh.get("ModuleLogging") == 1 else "Fail",
         rh.get("ModuleLogging"), 1)
    _add("18.6.1", "Admin Templates", "LLMNR disabled (NetBIOS poisoning)",
         "Pass" if rh.get("EnableMulticast") == 0 else "Fail",
         rh.get("EnableMulticast"), 0)
    _add("18.9.25", "Admin Templates", "NLA required for RDP",
         "Pass" if rh.get("UserAuthentication") == 1 else "Fail",
         rh.get("UserAuthentication"), 1)

    pass_count = sum(1 for c in controls if c["status"] == "Pass")
    fail_count = sum(1 for c in controls if c["status"] == "Fail")
    nc_count = sum(1 for c in controls if c["status"] == "Not Configured")
    total = len(controls)
    score = round(pass_count / total * 100, 1) if total else 0

    return {
        "framework": "CIS",
        "framework_full": "CIS Microsoft Windows Server Benchmark",
        "version": "v2.3.0+",
        "controls": controls,
        "summary": {
            "total": total, "pass": pass_count,
            "fail": fail_count, "not_configured": nc_count,
            "score_percent": score,
        },
        "rating": ("Good" if score >= 80 else "Fair" if score >= 60
                   else "Poor" if score >= 40 else "Critical"),
    }


def _build_nist_800_123_compliance(data):
    rh = data.get("registry_hardening", {})
    sp = data.get("security_policy", {})
    si = data.get("system_info", {})
    fw = data.get("firewall", {})
    svcs = data.get("services", [])
    updates = data.get("updates", {})
    ua = data.get("user_accounts", {})
    dd = data.get("defender_detailed", {})
    if not isinstance(rh, dict):
        rh = {}
    if not isinstance(si, dict):
        si = {}

    controls = []

    def _add(nist_id, category, title, status, detail, recommendation):
        controls.append({
            "id": nist_id, "category": category, "title": title,
            "status": status, "detail": str(detail) if detail is not None else "",
            "recommendation": recommendation,
        })

    # 4.1 OS Patching and Updates
    if isinstance(updates, dict):
        total = updates.get("total_updates_installed", 0)
        pending = updates.get("pending_count", 0)
        svc_status = updates.get("update_service_status", "")
        _add("4.1.1", "OS Patching", "Windows Update service status",
             "Pass" if svc_status.lower() == "running" else "Fail",
             svc_status, "Ensure Windows Update service is running")
        _add("4.1.2", "OS Patching", "Pending updates installed",
             "Pass" if pending == 0 else "Fail",
             f"{pending} pending, {total} installed",
             "Apply all pending security updates")

    os_name = si.get("os_name", "")
    is_eol = "2012" in os_name or "2008" in os_name or "2003" in os_name
    _add("4.1.3", "OS Patching", "Operating system supported / not EOL",
         "Fail" if is_eol else "Pass", os_name,
         "Upgrade to a supported Windows Server version")

    # 4.2 Remove Unnecessary Services
    risky_running = []
    _UNNECESSARY = {"telnet", "tlntsvr", "snmp", "ftpsvc", "msftpsvc",
                    "iisadmin", "ssdpsrv", "upnphost", "simptcp",
                    "remoteregistry", "browser", "fax", "tapisrv"}
    if isinstance(svcs, list):
        for svc in svcs:
            if not isinstance(svc, dict):
                continue
            state = (svc.get("status", "") or svc.get("state", "")).upper()
            name = (svc.get("name", "") or "").lower()
            if state in ("RUNNING", "RUN") and name in _UNNECESSARY:
                risky_running.append(svc.get("display_name", name))
    _add("4.2.1", "Remove Unnecessary Services", "No risky services running",
         "Pass" if not risky_running else "Fail",
         ", ".join(risky_running[:5]) or "None found",
         "Disable unnecessary services (Telnet, FTP, SNMP, etc.)")

    # 4.3 Authentication and Access Control
    _add("4.3.1", "Authentication", "NTLMv2 enforced (LmCompatibilityLevel=5)",
         "Pass" if rh.get("LmCompatibilityLevel") == 5 else "Fail",
         rh.get("LmCompatibilityLevel"), "Set LmCompatibilityLevel to 5")
    _add("4.3.2", "Authentication", "LM hash storage disabled",
         "Pass" if rh.get("NoLMHash") == 1 else "Fail",
         rh.get("NoLMHash"), "Set NoLMHash to 1")
    _add("4.3.3", "Authentication", "WDigest cleartext credentials disabled",
         "Pass" if rh.get("UseLogonCredential") == 0 else "Fail",
         rh.get("UseLogonCredential"),
         "Set UseLogonCredential to 0")
    pp = sp.get("password_policy", {}) if isinstance(sp, dict) else {}
    ml = int(pp.get("minimum_password_length", "0") or "0") if isinstance(pp, dict) else 0
    _add("4.3.4", "Authentication", "Minimum password length >= 14",
         "Pass" if ml >= 14 else "Fail", ml,
         "Set minimum password length to 14 or more")

    lp = sp.get("lockout_policy", {}) if isinstance(sp, dict) else {}
    lt = int(lp.get("lockout_threshold", "0") or "0") if isinstance(lp, dict) else 0
    _add("4.3.5", "Authentication", "Account lockout enabled",
         "Pass" if 0 < lt <= 10 else "Fail", lt,
         "Set lockout threshold between 3-5 failed attempts")

    local_users = ua.get("local_users", []) if isinstance(ua, dict) else []
    pw_never = sum(1 for u in local_users
                   if isinstance(u, dict) and u.get("enabled") and u.get("password_never_expires"))
    _add("4.3.6", "Authentication", "No enabled accounts with password never expires",
         "Pass" if pw_never == 0 else "Fail",
         f"{pw_never} accounts",
         "Set password expiration on all enabled accounts")

    admins = ua.get("administrators_group", []) if isinstance(ua, dict) else []
    _add("4.3.7", "Authentication", "Local Administrators group minimized",
         "Pass" if len(admins) <= 3 else "Fail",
         f"{len(admins)} members: {', '.join(str(a) for a in admins[:5])}",
         "Limit local admin group to essential accounts only")

    # 4.4 Resource Controls
    _add("4.4.1", "Resource Controls", "SMBv1 disabled",
         "Pass" if rh.get("SMB1") == 0 else "Fail",
         rh.get("SMB1"), "Disable SMBv1 protocol")
    _add("4.4.2", "Resource Controls", "SMB signing required (server)",
         "Pass" if rh.get("RequireSecuritySignature") == 1 else "Fail",
         rh.get("RequireSecuritySignature"), "Enable RequireSecuritySignature")
    _add("4.4.3", "Resource Controls", "Anonymous access restricted",
         "Pass" if rh.get("RestrictAnonymous") == 1 else "Fail",
         rh.get("RestrictAnonymous"), "Set RestrictAnonymous to 1")
    _add("4.4.4", "Resource Controls", "Null session pipes restricted",
         "Pass" if rh.get("NullSessionPipes") in (0, "", None, "0") else "Fail",
         rh.get("NullSessionPipes"), "Remove all null session pipes")

    # 4.5 Logging and Monitoring
    _add("4.5.1", "Logging", "PowerShell Script Block Logging enabled",
         "Pass" if rh.get("ScriptBlockLogging") == 1 else "Fail",
         rh.get("ScriptBlockLogging"), "Enable ScriptBlockLogging")
    _add("4.5.2", "Logging", "PowerShell Module Logging enabled",
         "Pass" if rh.get("ModuleLogging") == 1 else "Fail",
         rh.get("ModuleLogging"), "Enable ModuleLogging")

    # 4.6 Host-based Firewall
    profiles = fw.get("profiles", {}) if isinstance(fw, dict) else {}
    all_on = True
    for pname, pdata in (profiles.items() if isinstance(profiles, dict) else []):
        pval = pdata.get("State", pdata.get("enabled", "")) if isinstance(pdata, dict) else ""
        if str(pval).lower() not in ("on", "true", "1", "enabled"):
            all_on = False
    _add("4.6.1", "Host Firewall", "All firewall profiles enabled",
         "Pass" if all_on and profiles else "Fail",
         ", ".join(f"{k}={v.get('State', v.get('enabled', '?'))}"
                   for k, v in profiles.items()
                   if isinstance(v, dict)) if profiles else "No profiles",
         "Enable Domain, Private, and Public firewall profiles")

    # 4.7 Anti-malware
    av = dd.get("av_products", []) if isinstance(dd, dict) else []
    has_av = bool(av and any(isinstance(a, dict) and a.get("name") for a in av))
    _add("4.7.1", "Anti-malware", "Antivirus product installed",
         "Pass" if has_av else "Fail",
         ", ".join(a.get("name", "?") for a in av[:3] if isinstance(a, dict)) or "None detected",
         "Install and maintain endpoint antivirus")
    rt = rh.get("real_time_protection")
    _add("4.7.2", "Anti-malware", "Real-time protection enabled",
         "Pass" if rt == 0 else ("Fail" if rt == 1 else "Unknown"),
         rt, "Enable real-time antivirus scanning")

    pass_count = sum(1 for c in controls if c["status"] == "Pass")
    fail_count = sum(1 for c in controls if c["status"] == "Fail")
    total = len(controls)
    score = round(pass_count / total * 100, 1) if total else 0

    return {
        "framework": "NIST",
        "framework_full": "NIST SP 800-123 Guide to General Server Security",
        "version": "July 2008",
        "controls": controls,
        "summary": {
            "total": total, "pass": pass_count,
            "fail": fail_count,
            "score_percent": score,
        },
        "rating": ("Good" if score >= 80 else "Fair" if score >= 60
                   else "Poor" if score >= 40 else "Critical"),
    }


def _build_disa_stig_compliance(data):
    rh = data.get("registry_hardening", {})
    sp = data.get("security_policy", {})
    si = data.get("system_info", {})
    ua = data.get("user_accounts", {})
    fw = data.get("firewall", {})
    svcs = data.get("services", [])
    updates = data.get("updates", {})
    dd = data.get("defender_detailed", {})
    if not isinstance(rh, dict):
        rh = {}
    if not isinstance(si, dict):
        si = {}

    controls = []

    def _add(vuln_id, cat, sev, title, status, detail, fix_text):
        controls.append({
            "id": vuln_id, "category": cat, "severity": sev,
            "title": title, "status": status,
            "detail": str(detail) if detail is not None else "",
            "fix_text": fix_text,
        })

    # --- CAT I (High) ---
    os_name = si.get("os_name", "")
    is_eol = "2012" in os_name or "2008" in os_name or "2003" in os_name
    _add("V-225417", "OS Support", "CAT I",
         "System must be running a supported OS version",
         "Fail" if is_eol else "Pass", os_name,
         "Upgrade to a DISA-approved Windows Server version")

    _add("V-225418", "Authentication", "CAT I",
         "Do not store LAN Manager hash values",
         "Pass" if rh.get("NoLMHash") == 1 else "Fail", rh.get("NoLMHash"),
         "Set NoLMHash to 1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")

    _add("V-225419", "Authentication", "CAT I",
         "LAN Manager auth level set to NTLMv2 only",
         "Pass" if (rh.get("LmCompatibilityLevel") or 0) >= 5 else "Fail",
         rh.get("LmCompatibilityLevel"),
         "Set LmCompatibilityLevel to 5")

    _add("V-225420", "Access Control", "CAT I",
         "UAC must be enabled (Admin Approval Mode)",
         "Pass" if rh.get("EnableLUA") == 1 else "Fail", rh.get("EnableLUA"),
         "Set EnableLUA to 1")

    _add("V-225421", "Protocol", "CAT I",
         "SMBv1 protocol must be disabled",
         "Pass" if rh.get("SMB1") == 0 else "Fail", rh.get("SMB1"),
         "Disable SMBv1 server and client")

    _add("V-225422", "Credential Protection", "CAT I",
         "WDigest cleartext storage must be disabled",
         "Pass" if rh.get("UseLogonCredential") == 0 else "Fail",
         rh.get("UseLogonCredential"),
         "Set UseLogonCredential to 0")

    # --- CAT II (Medium) ---
    pp = sp.get("password_policy", {}) if isinstance(sp, dict) else {}
    ml = int(pp.get("minimum_password_length", "0") or "0") if isinstance(pp, dict) else 0
    _add("V-225430", "Account Policy", "CAT II",
         "Minimum password length must be 14+ characters",
         "Pass" if ml >= 14 else "Fail", ml,
         "Set minimum password length to 14 via Group Policy")

    ph = int(pp.get("password_history_count", "0") or "0") if isinstance(pp, dict) else 0
    _add("V-225431", "Account Policy", "CAT II",
         "Password history must enforce 24+ passwords",
         "Pass" if ph >= 24 else "Fail", ph,
         "Set Enforce password history to 24")

    lp = sp.get("lockout_policy", {}) if isinstance(sp, dict) else {}
    lt = int(lp.get("lockout_threshold", "0") or "0") if isinstance(lp, dict) else 0
    _add("V-225432", "Account Policy", "CAT II",
         "Account lockout threshold must be 3 or fewer",
         "Pass" if 0 < lt <= 3 else "Fail", lt,
         "Set account lockout threshold to 3 or fewer attempts")

    ld = int(lp.get("lockout_duration", "0") or "0") if isinstance(lp, dict) else 0
    _add("V-225433", "Account Policy", "CAT II",
         "Lockout duration must be >= 15 minutes",
         "Pass" if ld >= 15 else "Fail", ld,
         "Set lockout duration to 15 minutes or greater")

    _add("V-225440", "SMB", "CAT II",
         "SMB server signing must be required",
         "Pass" if rh.get("RequireSecuritySignature") == 1 else "Fail",
         rh.get("RequireSecuritySignature"),
         "Set RequireSecuritySignature to 1 on LanmanServer\\Parameters")

    _add("V-225441", "SMB", "CAT II",
         "SMB client signing must be required",
         "Pass" if rh.get("SMBClient_RequireSecuritySignature") == 1 else "Fail",
         rh.get("SMBClient_RequireSecuritySignature"),
         "Set RequireSecuritySignature to 1 on LanmanWorkstation\\Parameters")

    _add("V-225442", "Access Control", "CAT II",
         "Anonymous SAM enumeration must be restricted",
         "Pass" if rh.get("RestrictAnonymousSAM") == 1 else "Fail",
         rh.get("RestrictAnonymousSAM"),
         "Set RestrictAnonymousSAM to 1")

    _add("V-225443", "Access Control", "CAT II",
         "Anonymous access to named pipes must be restricted",
         "Pass" if rh.get("NullSessionPipes") in (0, "", None, "0") else "Fail",
         rh.get("NullSessionPipes"),
         "Remove entries from NullSessionPipes")

    _add("V-225444", "Access Control", "CAT II",
         "Anonymous enumeration of shares must be restricted",
         "Pass" if rh.get("RestrictAnonymous") == 1 else "Fail",
         rh.get("RestrictAnonymous"),
         "Set RestrictAnonymous to 1")

    _add("V-225445", "RDP", "CAT II",
         "Network Level Authentication required for RDP",
         "Pass" if rh.get("UserAuthentication") == 1 else "Fail",
         rh.get("UserAuthentication"),
         "Enable Network Level Authentication for Remote Desktop")

    _add("V-225446", "Credential Protection", "CAT II",
         "LSA protection (RunAsPPL) must be enabled",
         "Pass" if rh.get("RunAsPPL") == 1 else "Fail",
         rh.get("RunAsPPL"),
         "Set RunAsPPL to 1 for LSA protection")

    _add("V-225450", "Logging", "CAT II",
         "PowerShell Script Block Logging must be enabled",
         "Pass" if rh.get("ScriptBlockLogging") == 1 else "Fail",
         rh.get("ScriptBlockLogging"),
         "Enable Script Block Logging in Group Policy")

    _add("V-225451", "Network", "CAT II",
         "LLMNR must be disabled",
         "Pass" if rh.get("EnableMulticast") == 0 else "Fail",
         rh.get("EnableMulticast"),
         "Set EnableMulticast to 0")

    _add("V-225452", "AutoPlay", "CAT II",
         "AutoRun must be disabled for all drives",
         "Pass" if rh.get("NoDriveTypeAutoRun") == 255 else "Fail",
         rh.get("NoDriveTypeAutoRun"),
         "Set NoDriveTypeAutoRun to 0xFF (255)")

    # Firewall
    profiles = fw.get("profiles", {}) if isinstance(fw, dict) else {}
    all_on = all(
        str((pd.get("State", pd.get("enabled", "")) if isinstance(pd, dict) else "")).lower()
        in ("on", "true", "1", "enabled")
        for pd in profiles.values() if isinstance(pd, dict)
    ) if profiles else False
    _add("V-225460", "Firewall", "CAT II",
         "Windows Firewall must be enabled for all profiles",
         "Pass" if all_on and profiles else "Fail",
         ", ".join(f"{k}" for k in profiles) or "None",
         "Enable Domain, Private, and Public firewall profiles")

    # Admin accounts
    admins = ua.get("administrators_group", []) if isinstance(ua, dict) else []
    local_users = ua.get("local_users", []) if isinstance(ua, dict) else []
    pw_never = sum(1 for u in local_users
                   if isinstance(u, dict) and u.get("enabled") and u.get("password_never_expires"))
    _add("V-225470", "Account Management", "CAT II",
         "Enabled accounts must have password expiration",
         "Pass" if pw_never == 0 else "Fail",
         f"{pw_never} accounts with password never expires",
         "Set password expiration for all enabled accounts")

    # AV
    av = dd.get("av_products", []) if isinstance(dd, dict) else []
    has_av = bool(av and any(isinstance(a, dict) and a.get("name") for a in av))
    _add("V-225480", "Anti-Virus", "CAT II",
         "Antivirus software must be installed and active",
         "Pass" if has_av else "Fail",
         ", ".join(a.get("name", "?") for a in av[:3] if isinstance(a, dict)) or "None detected",
         "Install DoD-approved antivirus software")

    # Audit policy checks
    audit = rh.get("audit_policy", {})
    if isinstance(audit, dict):
        _STIG_AUDIT = [
            ("V-225490", "Logon/Logoff", "Logon", "Success and Failure"),
            ("V-225491", "Account Management", "User Account Management", "Success and Failure"),
            ("V-225492", "Account Management", "Security Group Management", "Success"),
            ("V-225493", "Policy Change", "Audit Policy Change", "Success and Failure"),
            ("V-225494", "Detailed Tracking", "Process Creation", "Success"),
            ("V-225495", "Account Logon", "Credential Validation", "Success and Failure"),
            ("V-225496", "DS Access", "Directory Service Access", "Success and Failure"),
        ]
        for vuln_id, cat, sub, required in _STIG_AUDIT:
            cat_data = audit.get(cat, {})
            actual = cat_data.get(sub, "No Auditing") if isinstance(cat_data, dict) else "No Auditing"
            _add(vuln_id, "Audit Policy", "CAT II",
                 f"Audit '{cat} > {sub}' must include '{required}'",
                 "Pass" if _audit_setting_meets(actual, required) else "Fail",
                 actual,
                 f"Configure {sub} auditing to {required}")

    cat1_fail = sum(1 for c in controls if c["severity"] == "CAT I" and c["status"] == "Fail")
    cat2_fail = sum(1 for c in controls if c["severity"] == "CAT II" and c["status"] == "Fail")
    pass_count = sum(1 for c in controls if c["status"] == "Pass")
    fail_count = sum(1 for c in controls if c["status"] == "Fail")
    total = len(controls)
    score = round(pass_count / total * 100, 1) if total else 0

    return {
        "framework": "DISA_STIG",
        "framework_full": "DISA STIG Windows Server 2012/2012 R2",
        "version": "v3r7",
        "controls": controls,
        "summary": {
            "total": total, "pass": pass_count,
            "fail": fail_count, "cat1_fail": cat1_fail, "cat2_fail": cat2_fail,
            "score_percent": score,
        },
        "rating": ("Good" if score >= 80 and cat1_fail == 0
                   else "Fair" if score >= 60 and cat1_fail <= 1
                   else "Poor" if score >= 40 else "Critical"),
    }


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
        ("cis_compliance.json", _build_cis_compliance),
        ("nist_800_123_compliance.json", _build_nist_800_123_compliance),
        ("disa_stig_compliance.json", _build_disa_stig_compliance),
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
