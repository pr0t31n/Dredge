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

    written = []
    if disk_report is not None:
        written.append("disk_storage_report.json")
    if hw_report is not None:
        written.append("hardware_report.json")
    return written
