from analyzers.base import BaseAnalyzer


class CredentialExposureAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_wifi_passwords()
        self._check_saved_sessions()
        self._check_credential_files()
        self._check_gpp_cpassword()
        self._check_cloud_credentials()
        self._check_vault_entries()
        self._check_dpapi()
        self._check_keepass()
        self._check_ssh_keys()
        return self.findings

    def _cred(self, key, default=None):
        section = self._get_section("credential_exposure", {})
        if not isinstance(section, dict):
            return default
        return section.get(key, default)

    def _check_wifi_passwords(self):
        profiles = self._cred("wifi_profiles", [])
        if not profiles:
            return
        cleartext = [p for p in profiles
                     if isinstance(p, dict) and p.get("key_content")]
        if not cleartext:
            return
        names = ", ".join(p.get("profile_name", "?") for p in cleartext[:10])
        self._add_finding(
            "DR-CRED-001", "WiFi Passwords Stored in Cleartext", "MEDIUM",
            f"{len(cleartext)} WiFi profile(s) have passwords stored in cleartext "
            f"on this system. Any local user or process can retrieve these passwords "
            f"using 'netsh wlan show profile name=X key=clear'.",
            "An attacker with local access can harvest WiFi credentials to pivot "
            "into wireless networks, including corporate WPA2-Enterprise or WPA-PSK "
            "networks. These credentials may also be reused for other services.",
            "Remove stored WiFi profiles that are no longer needed. Use 802.1X "
            "certificate-based authentication instead of pre-shared keys. Rotate "
            "WiFi passwords if they have been exposed.",
            output=f"Profiles with cleartext keys: {names}",
            remediation_effort="Easy",
            remediation_category="Wireless Security",
            mitre_attack=[{"technique": "T1552.001", "tactic": "Credential Access",
                           "name": "Credentials In Files"}],
            nist_800_53=["IA-5"],
        )

    def _check_saved_sessions(self):
        putty = self._cred("putty_sessions", [])
        winscp = self._cred("winscp_sessions", [])
        filezilla = self._cred("filezilla_sessions", [])
        rdp = self._cred("rdp_connections", [])
        parts = []
        if putty:
            parts.append(f"PuTTY ({len(putty)})")
        if winscp:
            parts.append(f"WinSCP ({len(winscp)})")
        if filezilla:
            parts.append(f"FileZilla ({len(filezilla)})")
        if rdp:
            parts.append(f"RDP ({len(rdp)})")
        if not parts:
            return
        self._add_finding(
            "DR-CRED-002", "Saved Remote Sessions Found", "MEDIUM",
            f"Saved remote access sessions were found for: {', '.join(parts)}. "
            f"These sessions may contain stored credentials or connection details "
            f"that could facilitate lateral movement.",
            "Saved sessions expose connection details (hostnames, usernames, and "
            "sometimes passwords) that attackers can use for lateral movement. "
            "WinSCP and FileZilla may store passwords in reversible formats.",
            "Remove unnecessary saved sessions. Configure tools to not save "
            "passwords. Use SSH key-based authentication instead of stored "
            "passwords. Audit saved sessions periodically.",
            output=f"Saved sessions: {', '.join(parts)}",
            remediation_effort="Easy",
            remediation_category="Credential Management",
            mitre_attack=[{"technique": "T1552.001", "tactic": "Credential Access",
                           "name": "Credentials In Files"}],
            nist_800_53=["IA-5"],
        )

    def _check_credential_files(self):
        cred_files = self._cred("credential_files", [])
        if not cred_files:
            return
        found = [f for f in cred_files
                 if isinstance(f, dict) and f.get("found")]
        if not found:
            return
        gpp = [f for f in found
               if "groups.xml" in f.get("path", "").lower()
               and f.get("has_cpassword")]
        non_gpp = [f for f in found
                   if f not in gpp]
        if not non_gpp:
            return
        names = ", ".join(f.get("filename", f.get("path", "?"))
                          for f in non_gpp[:10])
        self._add_finding(
            "DR-CRED-003", "Credential Files on Disk", "HIGH",
            f"{len(non_gpp)} file(s) containing potential credentials were found "
            f"on disk. These include configuration files, unattended installation "
            f"files, and application configs that may contain plaintext or "
            f"weakly-encrypted passwords.",
            "Credential files on disk provide attackers with passwords, connection "
            "strings, and service account credentials. Files like unattend.xml, "
            "web.config, and applicationHost.config are common targets during "
            "post-exploitation enumeration.",
            "Remove or secure credential files. Move secrets to a vault or "
            "secrets manager. Restrict file permissions to only required accounts. "
            "Audit for credential files regularly.",
            output=f"Files found: {names}",
            remediation_effort="Moderate",
            remediation_category="Credential Management",
            mitre_attack=[{"technique": "T1552.001", "tactic": "Credential Access",
                           "name": "Credentials In Files"}],
            nist_800_53=["IA-5", "SC-28"],
        )

    def _check_gpp_cpassword(self):
        cred_files = self._cred("credential_files", [])
        if not cred_files:
            return
        gpp_files = [f for f in cred_files
                     if isinstance(f, dict) and f.get("found")
                     and "groups.xml" in f.get("path", "").lower()
                     and f.get("has_cpassword")]
        if not gpp_files:
            return
        paths = ", ".join(f.get("path", "?") for f in gpp_files[:5])
        self._add_finding(
            "DR-CRED-004", "GPP cpassword Credential Exposure", "CRITICAL",
            f"Group Policy Preferences (GPP) XML file(s) with cpassword attribute "
            f"found. The AES-256 key used by GPP was published by Microsoft "
            f"(MS14-025), making all cpassword values trivially decryptable.",
            "GPP cpassword encryption is broken — the AES key is publicly known. "
            "Any domain user can read SYSVOL, find Groups.xml, and decrypt the "
            "embedded password. These are often domain admin or service account "
            "credentials.",
            "Delete all GPP XML files containing cpassword from SYSVOL. Apply "
            "KB2962486 to prevent new GPP passwords from being created. Rotate "
            "all passwords that were stored in GPP. Use LAPS for local admin "
            "password management instead.",
            output=f"GPP files: {paths}",
            cves="CVE-2014-1812",
            remediation_effort="Moderate",
            remediation_category="Active Directory",
            cwe=["CWE-261"],
            cvss_score=8.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            mitre_attack=[{"technique": "T1552.006", "tactic": "Credential Access",
                           "name": "Group Policy Preferences"}],
            nist_800_53=["IA-5", "SC-28"],
            pci_dss_4=["8.3.2"],
        )

    def _check_cloud_credentials(self):
        cloud = self._cred("cloud_credentials", [])
        if not cloud:
            return
        found = [c for c in cloud
                 if isinstance(c, dict) and c.get("found")]
        if not found:
            return
        names = ", ".join(c.get("provider", c.get("path", "?"))
                          for c in found[:10])
        self._add_finding(
            "DR-CRED-005", "Cloud Credential Files Found", "HIGH",
            f"{len(found)} cloud credential file(s) found on this system. These "
            f"files may contain API keys, access tokens, or service account "
            f"credentials for cloud platforms (AWS, Azure, GCP).",
            "Cloud credential files grant access to cloud infrastructure. An "
            "attacker can use these to access cloud resources, exfiltrate data "
            "from cloud storage, pivot to cloud-hosted systems, or escalate "
            "privileges within the cloud environment.",
            "Remove cloud credential files from endpoints. Use instance roles "
            "or managed identities instead of stored credentials. If files are "
            "required, restrict permissions and rotate credentials regularly.",
            output=f"Cloud credentials: {names}",
            remediation_effort="Moderate",
            remediation_category="Credential Management",
            mitre_attack=[{"technique": "T1552.001", "tactic": "Credential Access",
                           "name": "Credentials In Files"}],
            nist_800_53=["IA-5", "SC-28"],
        )

    def _check_vault_entries(self):
        vaults = self._cred("vault_entries", [])
        if not vaults:
            return
        self._add_finding(
            "DR-CRED-006", "Windows Credential Manager Entries", "INFO",
            f"{len(vaults)} credential(s) stored in Windows Credential Manager "
            f"(Vault). These are encrypted using DPAPI and tied to the user's "
            f"logon session.",
            "Windows Credential Manager entries can be extracted by an attacker "
            "with the user's session token or DPAPI master key. Tools like "
            "Mimikatz can dump these credentials from memory.",
            "Audit stored credentials periodically. Remove credentials that are "
            "no longer needed. Consider using a dedicated password manager with "
            "stronger protections.",
            output=f"Vault entries: {len(vaults)}",
            remediation_effort="Easy",
            remediation_category="Credential Management",
            mitre_attack=[{"technique": "T1555.004", "tactic": "Credential Access",
                           "name": "Windows Credential Manager"}],
        )

    def _check_dpapi(self):
        dpapi = self._cred("dpapi", {})
        if not dpapi:
            return
        master_keys = dpapi.get("master_key_count", 0)
        if not master_keys:
            return
        accessible = dpapi.get("accessible_keys", 0)
        if not accessible:
            return
        self._add_finding(
            "DR-CRED-007", "DPAPI Master Key Accessible", "MEDIUM",
            f"{accessible} DPAPI master key(s) accessible on this system. DPAPI "
            f"protects browser passwords, WiFi keys, Credential Manager entries, "
            f"and other sensitive data. Access to master keys enables decryption.",
            "DPAPI master keys protect a wide range of sensitive data including "
            "browser saved passwords, certificate private keys, and application "
            "secrets. An attacker with access to these keys can decrypt all "
            "DPAPI-protected data for the corresponding user.",
            "Ensure strong user passwords (DPAPI derives from user credentials). "
            "Enable Credential Guard where supported to protect DPAPI. Restrict "
            "local admin access to prevent credential harvesting.",
            output=f"Master keys: {master_keys}, Accessible: {accessible}",
            remediation_effort="Moderate",
            remediation_category="Credential Management",
            mitre_attack=[{"technique": "T1555", "tactic": "Credential Access",
                           "name": "Credentials from Password Stores"}],
            nist_800_53=["SC-28"],
        )

    def _check_keepass(self):
        keepass = self._cred("keepass_files", [])
        if not keepass:
            return
        paths = ", ".join(k.get("path", "?") if isinstance(k, dict) else str(k)
                          for k in keepass[:10])
        self._add_finding(
            "DR-CRED-008", "KeePass Database Files Found", "INFO",
            f"{len(keepass)} KeePass database file(s) (.kdbx) found on this "
            f"system. These files contain encrypted password vaults.",
            "KeePass databases are high-value targets. While encrypted, they can "
            "be subjected to offline brute-force or dictionary attacks if "
            "exfiltrated. Recent CVEs (CVE-2023-32784) have shown memory-based "
            "master password recovery techniques.",
            "Ensure KeePass databases use strong master passwords and key files. "
            "Keep KeePass updated to the latest version. Consider restricting "
            "database file locations and monitoring access.",
            output=f"KeePass files: {paths}",
            remediation_effort="Easy",
            remediation_category="Credential Management",
            mitre_attack=[{"technique": "T1555", "tactic": "Credential Access",
                           "name": "Credentials from Password Stores"}],
        )

    def _check_ssh_keys(self):
        keys = self._cred("ssh_keys", [])
        if not keys:
            return
        filenames = ", ".join(
            k.get("filename", k.get("path", "?")) if isinstance(k, dict) else str(k)
            for k in keys[:10]
        )
        self._add_finding(
            "DR-CRED-009", "SSH Private Keys Found", "MEDIUM",
            f"{len(keys)} SSH private key file(s) found on this system. Private "
            f"keys enable passwordless authentication to remote systems.",
            "SSH private keys allow direct authentication to remote servers. An "
            "attacker who obtains these keys can pivot to any system that trusts "
            "them. Unencrypted keys require no additional cracking.",
            "Protect private keys with strong passphrases. Remove keys that are "
            "no longer needed. Use SSH certificates with short lifetimes instead "
            "of long-lived keys. Restrict file permissions (chmod 600).",
            output=f"SSH keys: {filenames}",
            remediation_effort="Easy",
            remediation_category="Credential Management",
            mitre_attack=[{"technique": "T1552.004", "tactic": "Credential Access",
                           "name": "Private Keys"}],
            nist_800_53=["IA-5", "SC-17"],
        )
