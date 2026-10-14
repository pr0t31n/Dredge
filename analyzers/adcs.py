from analyzers.base import BaseAnalyzer


class ADCSAnalyzer(BaseAnalyzer):
    _LOW_PRIV_SIDS = {
        "S-1-1-0",
        "S-1-5-11",
        "S-1-5-32-545",
    }

    _DANGEROUS_RIGHTS = {
        "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite",
        "WriteProperty", "FullControl",
    }

    def analyze(self):
        adcs = self._get_section("adcs", {})
        if not adcs or not isinstance(adcs, dict):
            return self.findings
        if not adcs.get("available", False):
            return self.findings
        templates = adcs.get("templates", [])
        cas = adcs.get("certificate_authorities", [])
        self._check_esc1(templates)
        self._check_esc2(templates)
        self._check_esc3(templates)
        self._check_esc4(templates)
        self._check_esc6(cas)
        self._check_esc8(cas)
        return self.findings

    def _has_low_priv_enrollment(self, template):
        enrollment_rights = template.get("enrollment_rights", [])
        for entry in enrollment_rights:
            if isinstance(entry, dict):
                sid = entry.get("sid", "")
                identity = entry.get("identity", "").lower()
            elif isinstance(entry, str):
                sid = ""
                identity = entry.lower()
            else:
                continue
            if sid in self._LOW_PRIV_SIDS:
                return True
            if any(g in identity for g in ("domain users", "authenticated users",
                                           "everyone", "domain computers")):
                return True
        return False

    def _has_eku(self, template, eku_oid):
        ekus = template.get("extended_key_usage", [])
        for e in ekus:
            oid = e.get("oid", e) if isinstance(e, dict) else str(e)
            if oid == eku_oid:
                return True
        return False

    def _allows_san(self, template):
        flags = template.get("certificate_name_flag", 0)
        if isinstance(flags, int):
            return bool(flags & 0x00000001)
        if isinstance(flags, str):
            return "ENROLLEE_SUPPLIES_SUBJECT" in flags.upper()
        return False

    def _has_no_manager_approval(self, template):
        approval = template.get("requires_manager_approval", False)
        issuance = template.get("authorized_signatures_required", 0)
        return not approval and int(issuance or 0) == 0

    def _check_esc1(self, templates):
        for tpl in templates:
            if not isinstance(tpl, dict):
                continue
            name = tpl.get("name", "Unknown")
            if not self._allows_san(tpl):
                continue
            has_client_auth = (
                self._has_eku(tpl, "1.3.6.1.5.5.7.3.2") or
                self._has_eku(tpl, "1.3.6.1.4.1.311.20.2.2") or
                self._has_eku(tpl, "2.5.29.37.0")
            )
            if not has_client_auth:
                continue
            if not self._has_low_priv_enrollment(tpl):
                continue
            if not self._has_no_manager_approval(tpl):
                continue
            self._add_finding(
                "DR-ADCS-001",
                "ADCS: ESC1 - Misconfigured Certificate Template", "CRITICAL",
                f"Certificate template '{name}' allows the enrollee to supply "
                f"an arbitrary Subject Alternative Name (SAN), includes Client "
                f"Authentication EKU, and permits low-privileged enrollment "
                f"with no manager approval. This is the most critical AD CS "
                f"misconfiguration.",
                "ESC1 allows any domain user to request a certificate with an "
                "arbitrary SAN (e.g., Domain Admin UPN), then use it for "
                "authentication. This effectively grants domain admin to any "
                "enrolled user. It is actively exploited by tools like "
                "Certipy and Certify.",
                f"Remove the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag from "
                f"template '{name}'. Restrict enrollment to only required "
                f"groups. Enable manager approval for sensitive templates. "
                f"Remove unnecessary EKUs.",
                output=f"Template: {name}, SAN: enrollee-supplied, "
                       f"EKU: Client Auth, Enrollment: low-priv",
                remediation_effort="Moderate",
                remediation_category="Active Directory",
                cwe=["CWE-269"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                mitre_attack=[{"technique": "T1649", "tactic": "Credential Access",
                               "name": "Steal or Forge Authentication Certificates"}],
                nist_800_53=["AC-6", "IA-5"],
                pci_dss_4=["7.2.1"],
            )

    def _check_esc2(self, templates):
        for tpl in templates:
            if not isinstance(tpl, dict):
                continue
            name = tpl.get("name", "Unknown")
            ekus = tpl.get("extended_key_usage", [])
            eku_oids = set()
            for e in ekus:
                oid = e.get("oid", e) if isinstance(e, dict) else str(e)
                eku_oids.add(oid)
            has_any_purpose = "2.5.29.37.0" in eku_oids
            no_ekus = len(eku_oids) == 0
            if not has_any_purpose and not no_ekus:
                continue
            if not self._has_low_priv_enrollment(tpl):
                continue
            reason = "Any Purpose EKU" if has_any_purpose else "No EKU restriction"
            self._add_finding(
                "DR-ADCS-002",
                "ADCS: ESC2 - Overly Permissive Template", "HIGH",
                f"Certificate template '{name}' has {reason} and allows "
                f"low-privileged enrollment. Certificates can be used for any "
                f"purpose including client authentication, code signing, and "
                f"encryption.",
                "Templates with Any Purpose EKU or no EKU restrictions produce "
                "certificates usable for client authentication, allowing domain "
                "privilege escalation. They can also be used for code signing, "
                "enabling trusted malware execution.",
                f"Add specific EKU restrictions to template '{name}'. Remove "
                f"Any Purpose (2.5.29.37.0) OID. Restrict enrollment rights.",
                output=f"Template: {name}, Issue: {reason}",
                remediation_effort="Moderate",
                remediation_category="Active Directory",
                cwe=["CWE-269"],
                mitre_attack=[{"technique": "T1649", "tactic": "Credential Access",
                               "name": "Steal or Forge Authentication Certificates"}],
                nist_800_53=["AC-6"],
            )

    def _check_esc3(self, templates):
        for tpl in templates:
            if not isinstance(tpl, dict):
                continue
            name = tpl.get("name", "Unknown")
            if not self._has_eku(tpl, "1.3.6.1.4.1.311.20.2.1"):
                continue
            if not self._has_low_priv_enrollment(tpl):
                continue
            if not self._has_no_manager_approval(tpl):
                continue
            self._add_finding(
                "DR-ADCS-003",
                "ADCS: ESC3 - Enrollment Agent Template", "HIGH",
                f"Certificate template '{name}' has the Certificate Request "
                f"Agent EKU (1.3.6.1.4.1.311.20.2.1) with low-privileged "
                f"enrollment and no issuance requirements. This allows "
                f"enrolling on behalf of other users.",
                "An Enrollment Agent certificate allows the holder to request "
                "certificates on behalf of other users, including privileged "
                "accounts. Combined with a vulnerable template, this enables "
                "complete domain compromise.",
                f"Restrict enrollment for template '{name}' to specific groups. "
                f"Enable Application Policies issuance requirement. Configure "
                f"enrollment agent restrictions on the CA.",
                output=f"Template: {name}, EKU: Certificate Request Agent",
                remediation_effort="Moderate",
                remediation_category="Active Directory",
                cwe=["CWE-269"],
                mitre_attack=[{"technique": "T1649", "tactic": "Credential Access",
                               "name": "Steal or Forge Authentication Certificates"}],
                nist_800_53=["AC-6", "IA-5"],
            )

    def _check_esc4(self, templates):
        for tpl in templates:
            if not isinstance(tpl, dict):
                continue
            name = tpl.get("name", "Unknown")
            acl = tpl.get("acl", [])
            for ace in acl:
                if not isinstance(ace, dict):
                    continue
                identity = ace.get("identity", "").lower()
                sid = ace.get("sid", "")
                rights = ace.get("rights", "")
                is_low_priv = (
                    sid in self._LOW_PRIV_SIDS or
                    any(g in identity for g in ("domain users",
                                                "authenticated users",
                                                "everyone"))
                )
                if not is_low_priv:
                    continue
                has_dangerous = any(r in rights for r in self._DANGEROUS_RIGHTS)
                if not has_dangerous:
                    continue
                self._add_finding(
                    "DR-ADCS-004",
                    "ADCS: ESC4 - Vulnerable Template ACL", "HIGH",
                    f"Certificate template '{name}' grants dangerous rights "
                    f"({rights}) to '{ace.get('identity', sid)}'. A low-privileged "
                    f"user can modify the template to enable ESC1 conditions.",
                    "Template ACL abuse allows an attacker to modify a certificate "
                    "template's configuration — adding SAN specification, changing "
                    "EKUs, or removing approval requirements — effectively creating "
                    "an ESC1 condition on demand.",
                    f"Remove dangerous ACE from template '{name}'. Restrict "
                    f"template modification rights to CA Admins and Enterprise "
                    f"Admins only.",
                    output=f"Template: {name}, Identity: "
                           f"{ace.get('identity', sid)}, Rights: {rights}",
                    remediation_effort="Easy",
                    remediation_category="Active Directory",
                    cwe=["CWE-732"],
                    mitre_attack=[{"technique": "T1649", "tactic": "Credential Access",
                                   "name": "Steal or Forge Authentication Certificates"}],
                    nist_800_53=["AC-6", "AC-3"],
                )
                break

    def _check_esc6(self, cas):
        for ca in cas:
            if not isinstance(ca, dict):
                continue
            ca_name = ca.get("name", "Unknown")
            edit_flags = ca.get("edit_flags", 0)
            if isinstance(edit_flags, int):
                has_flag = bool(edit_flags & 0x00040000)
            elif isinstance(edit_flags, str):
                has_flag = "EDITF_ATTRIBUTESUBJECTALTNAME2" in edit_flags.upper()
            else:
                continue
            if not has_flag:
                continue
            self._add_finding(
                "DR-ADCS-005",
                "ADCS: ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2", "CRITICAL",
                f"Certificate Authority '{ca_name}' has the "
                f"EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled. This allows "
                f"any certificate request to specify an arbitrary SAN, "
                f"regardless of the template configuration.",
                "EDITF_ATTRIBUTESUBJECTALTNAME2 is a CA-level flag that "
                "overrides template settings, allowing any enrollee to request "
                "a certificate with any SAN. This makes every template on "
                "this CA vulnerable to ESC1-style attacks.",
                f"Remove the flag: certutil -config \"{ca_name}\" -setreg "
                f"policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2. "
                f"Restart the CA service.",
                output=f"CA: {ca_name}, Flag: EDITF_ATTRIBUTESUBJECTALTNAME2",
                remediation_effort="Easy",
                remediation_category="Active Directory",
                cwe=["CWE-269"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                mitre_attack=[{"technique": "T1649", "tactic": "Credential Access",
                               "name": "Steal or Forge Authentication Certificates"}],
                nist_800_53=["AC-6", "CM-6"],
                pci_dss_4=["7.2.1"],
            )

    def _check_esc8(self, cas):
        for ca in cas:
            if not isinstance(ca, dict):
                continue
            ca_name = ca.get("name", "Unknown")
            http_enrollment = ca.get("http_enrollment", False)
            ntlm_enabled = ca.get("ntlm_enabled", True)
            if not http_enrollment:
                continue
            if not ntlm_enabled:
                continue
            endpoint = ca.get("enrollment_url", "")
            self._add_finding(
                "DR-ADCS-006",
                "ADCS: ESC8 - NTLM Relay to HTTP Enrollment", "HIGH",
                f"Certificate Authority '{ca_name}' has an HTTP-based enrollment "
                f"endpoint accessible via NTLM authentication. This enables "
                f"NTLM relay attacks to request certificates as relayed users.",
                "An attacker can coerce NTLM authentication from a domain "
                "controller (e.g., via PetitPotam, PrinterBug) and relay it to "
                "the CA's HTTP enrollment endpoint to obtain a certificate as "
                "the DC's machine account, enabling DCSync.",
                f"Disable HTTP enrollment on '{ca_name}' or enforce EPA "
                f"(Extended Protection for Authentication). Enable HTTPS with "
                f"channel binding. Apply KB5005413 to mitigate NTLM relay.",
                output=f"CA: {ca_name}, HTTP Enrollment: {endpoint or 'enabled'}, "
                       f"NTLM: enabled",
                remediation_effort="Moderate",
                remediation_category="Active Directory",
                cwe=["CWE-294"],
                mitre_attack=[{"technique": "T1187", "tactic": "Credential Access",
                               "name": "Forced Authentication"}],
                nist_800_53=["IA-2", "SC-23"],
            )
