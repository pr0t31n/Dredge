from analyzers.base import BaseAnalyzer


class HardwareInventoryAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_outdated_gpu_drivers()
        self._check_unauthorized_usb()
        self._check_no_ecc_memory()
        return self.findings

    def _check_outdated_gpu_drivers(self):
        hw = self._get_section("hardware_inventory", {})
        gpus = hw.get("gpu_adapters", [])
        for g in gpus:
            if not isinstance(g, dict):
                continue
            status = str(g.get("status", "")).strip()
            if status and status.lower() not in ("ok", ""):
                self._add_finding(
                    "DR-HW-001",
                    "GPU Adapter Reporting Issues",
                    "LOW",
                    f"GPU adapter '{g.get('name', '?')}' is reporting a non-OK "
                    f"status: {status}. This may indicate a driver issue or "
                    f"hardware problem.",
                    "A malfunctioning GPU can indicate driver incompatibility or "
                    "hardware degradation. On servers, unexpected GPU presence may "
                    "indicate unauthorized cryptocurrency mining hardware.",
                    "Investigate the GPU status. Update or reinstall drivers. If "
                    "the GPU is unexpected on a server, verify it is authorized.",
                    output=f"GPU: {g.get('name', '?')}\nStatus: {status}\n"
                           f"Driver: {g.get('driver_version', '?')}",
                    confidence="Certain",
                    remediation_effort="Easy",
                    remediation_component="Infrastructure",
                )

    def _check_unauthorized_usb(self):
        hw = self._get_section("hardware_inventory", {})
        usb = hw.get("usb_devices", [])
        if not usb or not self._is_server():
            return
        storage_usb = []
        for dev in usb:
            if not isinstance(dev, dict):
                continue
            cls = str(dev.get("class", "")).lower()
            name = str(dev.get("name", "")).lower()
            if "storage" in cls or "disk" in cls or "mass storage" in name:
                storage_usb.append(
                    f"{dev.get('name', '?')} — {dev.get('manufacturer', '?')}")
        if storage_usb:
            self._add_finding(
                "DR-HW-002",
                "USB Mass Storage Devices on Server",
                "MEDIUM",
                f"{len(storage_usb)} USB mass storage device(s) detected on "
                f"this server. USB storage devices on servers can be used for "
                f"unauthorized data exfiltration.",
                "USB storage devices on production servers are a data loss "
                "prevention risk. They can be used to exfiltrate sensitive data "
                "or introduce malware. Most security frameworks require USB "
                "storage to be disabled on servers.",
                "Disable USB mass storage via Group Policy: Computer "
                "Configuration > Administrative Templates > System > Removable "
                "Storage Access. Physically remove unauthorized devices.",
                output="\n".join(storage_usb),
                confidence="Certain",
                remediation_effort="Easy",
                remediation_component="Configuration",
                mitre_attack=[{"technique": "T1052.001", "tactic": "Exfiltration",
                               "name": "Exfiltration Over USB"}],
                nist_800_53=["AC-19", "SC-41"],
                pci_dss_4=["9.2.4"],
            )

    def _check_no_ecc_memory(self):
        if not self._is_server():
            return
        hw = self._get_section("hardware_inventory", {})
        ecc = hw.get("memory_ecc")
        if ecc is False:
            total = hw.get("memory_total_gb", 0)
            slots = hw.get("memory_slot_count", 0)
            self._add_finding(
                "DR-HW-003",
                "Server Running Without ECC Memory",
                "LOW",
                f"This server has {total} GB of non-ECC memory across "
                f"{slots} module(s). ECC memory detects and corrects "
                f"single-bit errors that can cause data corruption.",
                "Without ECC memory, single-bit memory errors go undetected "
                "and can corrupt data in transit, in databases, or in "
                "filesystem caches. This is especially important for servers "
                "handling critical data or running for extended periods.",
                "Replace memory modules with ECC-rated DIMMs. Ensure the "
                "motherboard and CPU support ECC. Enable ECC in BIOS settings.",
                output=f"Total RAM: {total} GB\nModules: {slots}\nECC: No",
                confidence="Firm",
                remediation_effort="Significant",
                remediation_component="Infrastructure",
            )
