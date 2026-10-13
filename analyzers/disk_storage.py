from analyzers.base import BaseAnalyzer


class DiskStorageAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_physical_disk_health()
        self._check_storage_pool_health()
        self._check_virtual_disk_health()
        self._check_redundancy_after_failure()
        self._check_hw_raid_degraded()
        self._check_no_redundancy()
        self._check_disk_space_critical()
        self._check_disk_space_low()
        self._check_predictive_failure()
        self._check_raid_controller()
        self._check_disk_event_log_errors()
        return self.findings

    def _check_physical_disk_health(self):
        ds = self._get_section("disk_storage", {})
        bad = []

        for d in ds.get("storage_physical_disks", []):
            if not isinstance(d, dict):
                continue
            hs = str(d.get("health_status", "")).strip()
            os_ = str(d.get("operational_status", "")).strip()
            if hs and hs.lower() != "healthy":
                bad.append(f"{d.get('friendly_name', '?')} — Health: {hs}, Op: {os_}, "
                           f"Size: {d.get('size_gb', '?')} GB, Media: {d.get('media_type', '?')}")
            elif os_ and os_.lower() not in ("ok", ""):
                bad.append(f"{d.get('friendly_name', '?')} — Health: {hs}, Op: {os_}, "
                           f"Size: {d.get('size_gb', '?')} GB, Media: {d.get('media_type', '?')}")

        for d in ds.get("disks", []):
            if not isinstance(d, dict):
                continue
            hs = str(d.get("health_status", "")).strip()
            if hs and hs.lower() != "healthy":
                label = d.get("friendly_name") or f"Disk {d.get('number', '?')}"
                entry = (f"{label} — Health: {hs}, Size: {d.get('size_gb', '?')} GB, "
                         f"Boot: {d.get('is_boot', '?')}")
                if entry not in bad:
                    bad.append(entry)

        if bad:
            self._add_finding(
                "DR-DISK-001",
                "Physical Disk Health Degraded",
                "HIGH",
                f"{len(bad)} physical disk(s) are reporting a non-healthy status. "
                "This may indicate imminent disk failure or an already-failed drive "
                "in a redundant array.",
                "A degraded physical disk can lead to data loss if a second disk in "
                "the same redundancy group fails. In non-redundant configurations, "
                "a single disk failure results in immediate data loss.",
                "Replace the failed or degraded disk(s) immediately. If part of a "
                "Storage Spaces pool or hardware RAID, initiate a rebuild after "
                "replacement. Verify backups are current before replacement.",
                output="\n".join(bad),
                confidence="Certain",
                remediation_effort="Significant",
                remediation_component="Infrastructure",
                mitre_attack=[{"technique": "T1485", "tactic": "Impact",
                               "name": "Data Destruction"}],
                nist_800_53=["CP-9", "CP-10"],
            )

    def _check_storage_pool_health(self):
        ds = self._get_section("disk_storage", {})
        bad = []
        for p in ds.get("storage_pools", []):
            if not isinstance(p, dict):
                continue
            name = p.get("friendly_name", "?")
            if name.lower() == "primordial":
                continue
            hs = str(p.get("health_status", "")).strip()
            if hs and hs.lower() != "healthy":
                bad.append(f"{name} — Health: {hs}, Op: {p.get('operational_status', '?')}, "
                           f"Size: {p.get('size_gb', '?')} GB, "
                           f"Allocated: {p.get('allocated_size_gb', '?')} GB")

        if bad:
            self._add_finding(
                "DR-DISK-002",
                "Storage Pool Health Degraded",
                "CRITICAL",
                f"{len(bad)} storage pool(s) are in a degraded or unhealthy state. "
                "This typically means one or more physical disks in the pool have "
                "failed or been removed.",
                "A degraded storage pool is operating with reduced or no fault "
                "tolerance. Depending on the resiliency setting, one additional "
                "disk failure could cause complete data loss for volumes in this pool.",
                "Identify and replace the failed physical disk(s) in the pool. "
                "Windows Storage Spaces will automatically begin rebuilding once "
                "a replacement disk is added. Do NOT remove additional disks. "
                "Verify backups before any hardware changes.",
                output="\n".join(bad),
                confidence="Certain",
                remediation_effort="Significant",
                remediation_component="Infrastructure",
                mitre_attack=[{"technique": "T1485", "tactic": "Impact",
                               "name": "Data Destruction"}],
                nist_800_53=["CP-9", "CP-10", "CP-2"],
            )

    def _check_virtual_disk_health(self):
        ds = self._get_section("disk_storage", {})
        bad = []
        for v in ds.get("virtual_disks", []):
            if not isinstance(v, dict):
                continue
            hs = str(v.get("health_status", "")).strip()
            os_ = str(v.get("operational_status", "")).strip()
            degraded = (hs and hs.lower() != "healthy") or "degrade" in os_.lower()
            if degraded:
                resiliency = v.get("resiliency_setting", "Unknown")
                bad.append(
                    f"{v.get('friendly_name', '?')} — Health: {hs}, Op: {os_}, "
                    f"Resiliency: {resiliency}, Size: {v.get('size_gb', '?')} GB, "
                    f"Redundancy: {v.get('physical_disk_redundancy', '?')}, "
                    f"Copies: {v.get('number_of_data_copies', '?')}")

        if bad:
            self._add_finding(
                "DR-DISK-003",
                "Virtual Disk Not Healthy",
                "HIGH",
                f"{len(bad)} virtual disk(s) are reporting a degraded or unhealthy "
                "status. Virtual disks in Storage Spaces represent the logical "
                "volumes built on top of storage pools.",
                "A degraded virtual disk means the resiliency layer is compromised. "
                "For Parity volumes, one disk failure is tolerable but a second "
                "failure causes data loss. For Mirror volumes, tolerance depends "
                "on the number of data copies configured.",
                "Replace the underlying failed physical disk(s). The virtual disk "
                "will automatically repair once the pool has sufficient healthy "
                "capacity. Monitor the rebuild progress in Server Manager or "
                "PowerShell (Get-VirtualDisk | Get-StorageJob).",
                output="\n".join(bad),
                confidence="Certain",
                remediation_effort="Significant",
                remediation_component="Infrastructure",
                nist_800_53=["CP-9", "CP-10"],
            )

    def _check_redundancy_after_failure(self):
        ds = self._get_section("disk_storage", {})
        pools = ds.get("storage_pools", [])
        vdisks = ds.get("virtual_disks", [])
        phys = ds.get("storage_physical_disks", [])

        degraded_pools = set()
        for p in pools:
            if not isinstance(p, dict):
                continue
            name = p.get("friendly_name", "")
            if name.lower() == "primordial":
                continue
            hs = str(p.get("health_status", "")).strip()
            if hs and hs.lower() != "healthy":
                degraded_pools.add(name)

        if not degraded_pools:
            return

        failed_disks = []
        for d in phys:
            if not isinstance(d, dict):
                continue
            hs = str(d.get("health_status", "")).strip()
            if hs and hs.lower() != "healthy":
                failed_disks.append(d.get("friendly_name", "?"))

        at_risk = []
        for v in vdisks:
            if not isinstance(v, dict):
                continue
            resiliency = str(v.get("resiliency_setting", "")).lower()
            redundancy = v.get("physical_disk_redundancy", 0)
            try:
                redundancy = int(redundancy)
            except (ValueError, TypeError):
                redundancy = 0
            if resiliency == "parity" and redundancy <= 1:
                at_risk.append(
                    f"{v.get('friendly_name', '?')} — Resiliency: Parity, "
                    f"Disk Redundancy: {redundancy} (single-parity), "
                    f"Size: {v.get('size_gb', '?')} GB")
            elif resiliency == "mirror":
                copies = v.get("number_of_data_copies", 0)
                try:
                    copies = int(copies)
                except (ValueError, TypeError):
                    copies = 0
                if copies <= 2 and len(failed_disks) >= 1:
                    at_risk.append(
                        f"{v.get('friendly_name', '?')} — Resiliency: Mirror "
                        f"(2-way), Disk Redundancy: {redundancy}, "
                        f"Size: {v.get('size_gb', '?')} GB")

        if at_risk:
            lines = ["DEGRADED POOLS: " + ", ".join(degraded_pools)]
            lines.append(f"FAILED DISKS: {', '.join(failed_disks) if failed_disks else 'unknown'}")
            lines.append("")
            lines.append("AT-RISK VOLUMES:")
            lines.extend(f"  • {r}" for r in at_risk)
            self._add_finding(
                "DR-DISK-009",
                "Disk Running Without Redundancy After Failure",
                "CRITICAL",
                f"One or more storage pools are degraded and the virtual disks "
                f"within them have exhausted their fault tolerance. "
                f"{len(at_risk)} volume(s) are now running with ZERO remaining "
                f"redundancy — one additional disk failure will cause data loss.",
                "The storage array has already lost a disk and is operating in a "
                "degraded state with no remaining fault tolerance. If another "
                "disk in the same pool fails before the array is rebuilt, all "
                "data on the affected volume(s) will be permanently lost. This "
                "is an emergency.",
                "IMMEDIATE ACTION REQUIRED: 1) Replace the failed disk(s) as "
                "soon as possible. 2) Do NOT power down the server until "
                "replacement disks are installed and the rebuild completes. "
                "3) Verify that current backups exist before any hardware work. "
                "4) Monitor rebuild progress with Get-StorageJob. 5) Consider "
                "upgrading to dual-parity (or 3-way mirror) for critical data.",
                output="\n".join(lines),
                confidence="Certain",
                remediation_effort="Major",
                remediation_component="Infrastructure",
                mitre_attack=[{"technique": "T1485", "tactic": "Impact",
                               "name": "Data Destruction"}],
                nist_800_53=["CP-9", "CP-10", "CP-2", "CP-6"],
            )

    def _check_hw_raid_degraded(self):
        ds = self._get_section("disk_storage", {})
        hw = ds.get("hardware_raid", {})
        if not isinstance(hw, dict) or not hw.get("detected_cli"):
            return
        bad = []
        for vd in hw.get("virtual_drives", []):
            if not isinstance(vd, dict):
                continue
            state = str(vd.get("state", "")).strip().lower()
            if state and state not in ("optimal", "ok", "online", "ready", ""):
                bad.append(
                    f"VD {vd.get('vd', '?')} — RAID: {vd.get('raid_level', '?')}, "
                    f"State: {vd.get('state', '?')}, Size: {vd.get('size', '?')}, "
                    f"CLI: {vd.get('source_cli', '?')}")
        if bad:
            self._add_finding(
                "DR-DISK-010",
                "Hardware RAID Virtual Drive Degraded",
                "CRITICAL",
                f"{len(bad)} hardware RAID virtual drive(s) are in a non-optimal "
                f"state as reported by {hw.get('detected_cli', 'the controller CLI')}. "
                "This typically means one or more member disks have failed.",
                "A degraded hardware RAID array is operating with reduced fault "
                "tolerance. Depending on the RAID level, one additional disk "
                "failure may cause total data loss for the array.",
                "Replace the failed disk(s) immediately and initiate a rebuild "
                f"using the controller CLI ({hw.get('detected_cli', '?')}). "
                "Do not power down the server until replacement disks are "
                "installed. Verify backups are current.",
                output=f"Controller: {hw.get('controller', '?')}\n"
                       f"CLI: {hw.get('detected_cli', '?')}\n\n"
                       + "\n".join(bad),
                confidence="Certain",
                remediation_effort="Major",
                remediation_component="Infrastructure",
                mitre_attack=[{"technique": "T1485", "tactic": "Impact",
                               "name": "Data Destruction"}],
                nist_800_53=["CP-9", "CP-10", "CP-2"],
            )

    def _check_no_redundancy(self):
        if not self._is_server():
            return
        ds = self._get_section("disk_storage", {})
        pools = [p for p in ds.get("storage_pools", [])
                 if isinstance(p, dict) and p.get("friendly_name", "").lower() != "primordial"]
        vdisks = ds.get("virtual_disks", [])

        hw_raid = ds.get("hardware_raid", {})
        has_hw_raid = (isinstance(hw_raid, dict)
                       and hw_raid.get("detected_cli")
                       and hw_raid.get("virtual_drives"))

        if not pools and not vdisks and not has_hw_raid:
            phys = ds.get("physical_disks", [])
            if len(phys) > 1:
                self._add_finding(
                    "DR-DISK-004",
                    "No Disk Redundancy Configured",
                    "MEDIUM",
                    "This server has multiple physical disks but no Storage Spaces "
                    "pools or RAID configuration was detected. Data is stored on "
                    "individual disks with no redundancy.",
                    "Without disk redundancy, a single disk failure will result in "
                    "loss of all data stored on that disk. Servers typically require "
                    "redundancy for availability and data protection.",
                    "Configure Storage Spaces with Mirror or Parity resiliency, or "
                    "implement hardware RAID. For critical data, use at least 2-way "
                    "mirror or dual-parity. Ensure backups are in place regardless "
                    "of redundancy configuration.",
                    output=f"Physical disks detected: {len(phys)}\nStorage pools: 0\nRAID: not detected",
                    confidence="Certain",
                    remediation_effort="Significant",
                    remediation_component="Infrastructure",
                    nist_800_53=["CP-9", "CP-10"],
                )
            return

        if vdisks:
            all_simple = all(
                str(v.get("resiliency_setting", "")).lower() == "simple"
                for v in vdisks if isinstance(v, dict))
            if all_simple:
                names = [v.get("friendly_name", "?") for v in vdisks if isinstance(v, dict)]
                self._add_finding(
                    "DR-DISK-004",
                    "No Disk Redundancy Configured",
                    "MEDIUM",
                    f"All {len(names)} virtual disk(s) use 'Simple' resiliency "
                    "(no redundancy). Data is striped across disks with no fault "
                    "tolerance.",
                    "Simple (striped) virtual disks offer no protection against "
                    "disk failure. A single disk failure in the pool will cause "
                    "data loss across all Simple volumes.",
                    "Recreate virtual disks with Mirror or Parity resiliency. "
                    "For critical server data, use at least 2-way mirror or "
                    "single-parity. Back up data before reconfiguring.",
                    output="Simple volumes:\n" + "\n".join(f"  • {n}" for n in names),
                    confidence="Certain",
                    remediation_effort="Significant",
                    remediation_component="Infrastructure",
                    nist_800_53=["CP-9", "CP-10"],
                )

    def _check_disk_space_critical(self):
        ds = self._get_section("disk_storage", {})
        critical = []
        for d in ds.get("logical_disks", []):
            if not isinstance(d, dict):
                continue
            if str(d.get("drive_type", "")).lower() != "fixed":
                continue
            pct = d.get("percent_free")
            if pct is None:
                continue
            try:
                pct = float(pct)
            except (ValueError, TypeError):
                continue
            if pct < 5:
                critical.append(
                    f"{d.get('device_id', '?')} — {pct:.1f}% free "
                    f"({d.get('free_space_gb', '?')} GB / {d.get('size_gb', '?')} GB), "
                    f"FS: {d.get('filesystem', '?')}")

        if critical:
            self._add_finding(
                "DR-DISK-005",
                "Disk Space Critical",
                "HIGH",
                f"{len(critical)} drive(s) have less than 5% free space remaining. "
                "Critically low disk space can cause system instability, service "
                "failures, and inability to write logs or temporary files.",
                "When a volume runs out of space, services crash, databases corrupt, "
                "event logging stops (destroying the audit trail), and the system may "
                "become unresponsive. Attackers can intentionally fill disks to "
                "disable logging.",
                "Free disk space immediately by removing unnecessary files, "
                "expanding the volume, or adding storage capacity. Implement "
                "disk space monitoring alerts at 80% and 90% thresholds.",
                output="\n".join(critical),
                confidence="Certain",
                remediation_effort="Moderate",
                remediation_component="Infrastructure",
                nist_800_53=["AU-4", "SI-4"],
            )

    def _check_disk_space_low(self):
        ds = self._get_section("disk_storage", {})
        low = []
        for d in ds.get("logical_disks", []):
            if not isinstance(d, dict):
                continue
            if str(d.get("drive_type", "")).lower() != "fixed":
                continue
            pct = d.get("percent_free")
            if pct is None:
                continue
            try:
                pct = float(pct)
            except (ValueError, TypeError):
                continue
            if 5 <= pct < 15:
                low.append(
                    f"{d.get('device_id', '?')} — {pct:.1f}% free "
                    f"({d.get('free_space_gb', '?')} GB / {d.get('size_gb', '?')} GB), "
                    f"FS: {d.get('filesystem', '?')}")

        if low:
            self._add_finding(
                "DR-DISK-006",
                "Disk Space Low",
                "MEDIUM",
                f"{len(low)} drive(s) have between 5–15% free space remaining. "
                "Low disk space is a precursor to service disruption.",
                "Drives approaching capacity may cause performance degradation, "
                "application errors, and eventually the same critical failures "
                "seen when space is exhausted. Proactive monitoring prevents "
                "unplanned outages.",
                "Plan capacity expansion or clean up unnecessary files. "
                "Implement monitoring alerts at 80% and 90% usage thresholds. "
                "Review log rotation and temporary file cleanup policies.",
                output="\n".join(low),
                confidence="Certain",
                remediation_effort="Easy",
                remediation_component="Infrastructure",
            )

    def _check_predictive_failure(self):
        ds = self._get_section("disk_storage", {})
        failing = []
        for d in ds.get("physical_disks", []):
            if not isinstance(d, dict):
                continue
            status = str(d.get("status", "")).strip()
            if not status:
                continue
            sl = status.lower()
            if "pred" in sl or "error" in sl or "degrade" in sl:
                failing.append(
                    f"{d.get('model', '?')} — Status: {status}, "
                    f"Size: {d.get('size_gb', '?')} GB, "
                    f"Interface: {d.get('interface_type', '?')}")

        if failing:
            self._add_finding(
                "DR-DISK-007",
                "Physical Disk Predictive Failure",
                "HIGH",
                f"{len(failing)} physical disk(s) are reporting a predictive "
                "failure, error, or degraded status via WMI. This indicates the "
                "drive's self-monitoring (SMART) has detected conditions that "
                "precede failure.",
                "A predictive failure warning means the disk's firmware has "
                "determined that failure is likely based on internal diagnostics. "
                "Continued use risks sudden data loss.",
                "Replace the disk(s) as soon as possible. If the disk is part of "
                "a RAID or Storage Spaces pool, the array will rebuild after "
                "replacement. Verify backups are current and tested before "
                "proceeding with replacement.",
                output="\n".join(failing),
                confidence="Certain",
                remediation_effort="Significant",
                remediation_component="Infrastructure",
                nist_800_53=["CP-9", "CP-10"],
            )

    def _check_raid_controller(self):
        ds = self._get_section("disk_storage", {})
        bad = []
        for c in ds.get("raid_controllers", []):
            if not isinstance(c, dict):
                continue
            status = str(c.get("status", "")).strip()
            if status and status.lower() != "ok":
                bad.append(
                    f"{c.get('name', '?')} — Status: {status}, "
                    f"Manufacturer: {c.get('manufacturer', '?')}")

        if bad:
            self._add_finding(
                "DR-DISK-008",
                "RAID Controller Reporting Issues",
                "MEDIUM",
                f"{len(bad)} storage/RAID controller(s) are reporting a non-OK "
                "status. Controller issues can affect all disks managed by that "
                "controller.",
                "A failing RAID controller can cause data corruption, array "
                "degradation, or complete loss of access to all disks behind it. "
                "Controller failures are often harder to recover from than "
                "individual disk failures.",
                "Check the controller manufacturer's management utility for "
                "detailed diagnostics. Update controller firmware if available. "
                "If the controller is failing, plan for replacement with the "
                "same model (or compatible) to preserve array configuration.",
                output="\n".join(bad),
                confidence="Certain",
                remediation_effort="Significant",
                remediation_component="Infrastructure",
                nist_800_53=["CP-9", "CP-10"],
            )

    def _check_disk_event_log_errors(self):
        ds = self._get_section("disk_storage", {})
        events = ds.get("disk_event_errors", [])
        if not events:
            return
        critical_errors = []
        warnings = []
        _DISK_FAIL_IDS = {7, 9, 11, 15, 51, 52, 55, 129, 137, 153, 154}
        _NTFS_CORRUPT_IDS = {55, 98, 137}
        for ev in events:
            if not isinstance(ev, dict):
                continue
            eid = ev.get("id")
            try:
                eid = int(eid)
            except (ValueError, TypeError):
                continue
            level = str(ev.get("level", "")).lower()
            provider = str(ev.get("provider", "")).lower()
            msg = str(ev.get("message", ""))[:300]
            ts = ev.get("time", "?")
            entry = f"[{ts}] {ev.get('provider','?')} ID:{eid} ({ev.get('level','?')}): {msg}"
            if level in ("critical", "error"):
                if (eid in _DISK_FAIL_IDS
                        or eid in _NTFS_CORRUPT_IDS
                        or "disk" in provider
                        or "ntfs" in provider
                        or "storagespace" in provider
                        or "megasas" in provider
                        or "percsas" in provider
                        or "iastor" in provider):
                    critical_errors.append(entry)
                else:
                    warnings.append(entry)
            elif level == "warning":
                warnings.append(entry)

        if critical_errors:
            self._add_finding(
                "DR-DISK-011",
                "Disk/Storage Errors in Event Logs",
                "HIGH",
                f"{len(critical_errors)} critical disk or storage error event(s) "
                "found in the Windows System event log (last 30 days). These "
                "indicate active disk I/O failures, NTFS corruption, RAID "
                "controller errors, or storage subsystem faults.",
                "Disk-level event log errors are the earliest indicator of "
                "imminent drive failure, filesystem corruption, or RAID "
                "degradation. Ignoring these leads to data loss, silent "
                "corruption, or unplanned downtime.",
                "Investigate each error source. For disk I/O errors (Event IDs "
                "7, 9, 11, 15, 51, 153, 154): run SMART diagnostics and plan "
                "disk replacement. For NTFS errors (55, 98, 137): run chkdsk. "
                "For RAID controller errors: check the controller management "
                "utility. Correlate with physical disk health status.",
                output="\n\n".join(critical_errors[:20]),
                confidence="Certain",
                remediation_effort="Significant",
                remediation_component="Infrastructure",
                nist_800_53=["CP-9", "CP-10", "SI-4"],
            )

        if warnings and not critical_errors:
            self._add_finding(
                "DR-DISK-012",
                "Disk/Storage Warnings in Event Logs",
                "MEDIUM",
                f"{len(warnings)} disk or storage warning event(s) found in the "
                "Windows System event log (last 30 days). These may indicate "
                "early signs of disk degradation or intermittent I/O issues.",
                "Storage warnings often precede more serious errors. Monitoring "
                "and acting on warnings prevents unplanned outages.",
                "Review the warning events and correlate with disk health data. "
                "Schedule proactive disk replacement if warnings are recurring "
                "for the same device. Enable disk health monitoring.",
                output="\n\n".join(warnings[:15]),
                confidence="Firm",
                remediation_effort="Moderate",
                remediation_component="Infrastructure",
                nist_800_53=["SI-4", "CP-9"],
            )
