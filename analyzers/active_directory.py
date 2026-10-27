from analyzers.base import BaseAnalyzer

_OUTDATED_FUNC_LEVELS = {
    "Windows2000": "Windows 2000",
    "Windows2003": "Windows Server 2003",
    "Windows2008": "Windows Server 2008",
    "Windows2008R2": "Windows Server 2008 R2",
    "Windows2012": "Windows Server 2012",
    "Windows2012R2": "Windows Server 2012 R2",
}


class ActiveDirectoryAnalyzer(BaseAnalyzer):
    def analyze(self):
        ad = self._get_section("active_directory", {})
        if not isinstance(ad, dict) or not ad:
            return self.findings
        self._check_kerberoastable(ad)
        self._check_asrep_roastable(ad)
        self._check_unconstrained_delegation(ad)
        self._check_domain_password_policy(ad)
        self._check_ldap_signing(ad)
        self._check_kerberos_encryption(ad)
        self._check_rbcd(ad)
        self._check_functional_level(ad)
        self._check_adminsd_holder(ad)
        self._check_laps(ad)
        self._check_krbtgt(ad)
        self._check_stale_accounts(ad)
        self._check_sid_history(ad)
        self._check_fine_grained_password_policies(ad)
        self._check_gmsa(ad)
        return self.findings

    # ------------------------------------------------------------------ #
    # DR-AD-001  Kerberoastable accounts
    # ------------------------------------------------------------------ #
    def _check_kerberoastable(self, ad):
        kerberoastable = ad.get("kerberoastable_accounts",
                                ad.get("spn_accounts", []))
        if not isinstance(kerberoastable, list) or not kerberoastable:
            return
        accts = []
        for acct in kerberoastable:
            if isinstance(acct, dict):
                name = acct.get("samaccountname",
                                acct.get("name", acct.get("username", "")))
                spns = acct.get("serviceprincipalnames",
                                acct.get("spn", acct.get("spns", [])))
                if isinstance(spns, list):
                    spns = ", ".join(str(s) for s in spns[:3])
                accts.append(f"{name} (SPN: {spns})")
            elif isinstance(acct, str):
                accts.append(acct)
        output = "\n".join(accts[:20])
        priv_flag = any(
            isinstance(a, dict)
            and a.get("admincount", a.get("admin_count", 0)) == 1
            for a in kerberoastable if isinstance(a, dict))
        risk = "HIGH" if priv_flag else "MEDIUM"
        self._add_finding(
            "DR-AD-001",
            "Active Directory: Kerberoastable Accounts",
            risk,
            f"{len(kerberoastable)} user account(s) have Service Principal Names "
            f"(SPNs) set, making them vulnerable to Kerberoasting attacks. An "
            f"attacker with any domain user credential can request TGS tickets "
            f"for these accounts and crack them offline.",
            "Kerberoasting allows any authenticated domain user to request "
            "service tickets for SPN-bearing accounts and attempt offline "
            "password cracking. If the account password is weak, the attacker "
            "obtains the cleartext credential. Privileged service accounts "
            "(e.g., SQL service accounts in Domain Admins) are especially "
            "high-value targets.",
            "Set strong, complex passwords (25+ characters) on all accounts "
            "with SPNs. Migrate service accounts to Group Managed Service "
            "Accounts (gMSA) which rotate passwords automatically. Remove "
            "unnecessary SPNs. Monitor for anomalous TGS-REQ activity "
            "(Event ID 4769).",
            output=output,
            remediation_effort="Moderate",
            cwe=["CWE-521"],
            mitre_attack=[
                {"technique": "T1558.003", "tactic": "Credential Access",
                 "name": "Kerberoasting"},
            ],
            nist_800_53=["IA-5"],
        )

    # ------------------------------------------------------------------ #
    # DR-AD-002  AS-REP roastable accounts
    # ------------------------------------------------------------------ #
    def _check_asrep_roastable(self, ad):
        asrep = ad.get("asrep_roastable",
                        ad.get("no_preauth_accounts", []))
        if not isinstance(asrep, list) or not asrep:
            return
        accts = []
        for acct in asrep:
            if isinstance(acct, dict):
                name = acct.get("samaccountname",
                                acct.get("name", acct.get("username", "")))
                accts.append(name)
            elif isinstance(acct, str):
                accts.append(acct)
        output = "\n".join(accts[:20])
        self._add_finding(
            "DR-AD-002",
            "Active Directory: AS-REP Roastable Accounts",
            "HIGH",
            f"{len(asrep)} account(s) have Kerberos pre-authentication disabled "
            f"(DONT_REQUIRE_PREAUTH flag). These accounts are vulnerable to "
            f"AS-REP roasting, allowing offline password cracking without any "
            f"prior authentication.",
            "AS-REP roasting is more dangerous than Kerberoasting because it "
            "does not require any valid domain credentials to execute. An "
            "attacker can request encrypted AS-REP messages for these accounts "
            "from outside the domain and crack them offline. This is a common "
            "initial access technique in Active Directory attacks.",
            "Enable Kerberos pre-authentication on all accounts: clear the "
            "'Do not require Kerberos preauthentication' checkbox in account "
            "properties. No legitimate scenario requires this flag for "
            "standard user accounts. Audit accounts regularly for this flag. "
            "Monitor for anomalous AS-REQ traffic (Event ID 4768 with "
            "pre-auth type 0).",
            output=output,
            remediation_effort="Easy",
            cwe=["CWE-287"],
            mitre_attack=[
                {"technique": "T1558.004", "tactic": "Credential Access",
                 "name": "AS-REP Roasting"},
            ],
            nist_800_53=["IA-2", "IA-5"],
        )

    # ------------------------------------------------------------------ #
    # DR-AD-003  Unconstrained delegation
    # ------------------------------------------------------------------ #
    def _check_unconstrained_delegation(self, ad):
        unconstrained = ad.get("unconstrained_delegation",
                                ad.get("trusted_for_delegation", []))
        if not isinstance(unconstrained, list) or not unconstrained:
            return
        non_dc = []
        for entry in unconstrained:
            if isinstance(entry, dict):
                name = entry.get("samaccountname",
                                 entry.get("name", entry.get("cn", "")))
                is_dc = entry.get("is_dc", entry.get("primarygroupid", 0)) == 516
                if not is_dc:
                    non_dc.append(name)
            elif isinstance(entry, str):
                non_dc.append(entry)
        if not non_dc:
            return
        output = "\n".join(non_dc[:20])
        self._add_finding(
            "DR-AD-003",
            "Active Directory: Unconstrained Delegation",
            "HIGH",
            f"{len(non_dc)} non-domain-controller account(s) are configured "
            f"for unconstrained Kerberos delegation. These systems can "
            f"impersonate any user that authenticates to them, including "
            f"domain administrators.",
            "Unconstrained delegation allows a compromised server to reuse "
            "any user's Kerberos TGT that was forwarded during authentication. "
            "An attacker who compromises a server with unconstrained delegation "
            "can capture domain admin TGTs and use them to fully compromise "
            "the domain. This is a critical privilege escalation path in "
            "Active Directory environments.",
            "Replace unconstrained delegation with constrained delegation or "
            "resource-based constrained delegation (RBCD). Add privileged "
            "accounts to the Protected Users group or mark them as 'Account "
            "is sensitive and cannot be delegated'. Only Domain Controllers "
            "should have unconstrained delegation.",
            output=output,
            remediation_effort="Significant",
            mitre_attack=[
                {"technique": "T1558", "tactic": "Credential Access",
                 "name": "Steal or Forge Kerberos Tickets"},
                {"technique": "T1550.003", "tactic": "Lateral Movement",
                 "name": "Pass the Ticket"},
            ],
            nist_800_53=["AC-6", "AC-17"],
        )

    # ------------------------------------------------------------------ #
    # DR-AD-004  Weak domain password policy
    # ------------------------------------------------------------------ #
    def _check_domain_password_policy(self, ad):
        pw_policy = ad.get("password_policy",
                           ad.get("domain_password_policy", {}))
        if not isinstance(pw_policy, dict) or not pw_policy:
            return
        min_length = pw_policy.get("min_length",
                                   pw_policy.get("MinimumPasswordLength", 0))
        complexity = pw_policy.get("complexity_enabled",
                                   pw_policy.get("PasswordComplexity", True))
        max_age = pw_policy.get("max_age",
                                pw_policy.get("MaximumPasswordAge", 0))
        history = pw_policy.get("history_count",
                                pw_policy.get("PasswordHistorySize", 0))
        try:
            min_length = int(min_length)
        except (ValueError, TypeError):
            min_length = 0
        if isinstance(complexity, str):
            complexity = complexity.lower() not in ("0", "false", "disabled")
        try:
            max_age = int(max_age)
        except (ValueError, TypeError):
            max_age = 0
        try:
            history = int(history)
        except (ValueError, TypeError):
            history = 0

        issues = []
        if min_length < 12:
            issues.append(f"Minimum length: {min_length} (recommended >= 12)")
        if not complexity:
            issues.append("Complexity requirement: Disabled")
        if max_age == 0:
            issues.append("Maximum age: 0 (passwords never expire)")
        if history < 12:
            issues.append(f"History enforcement: {history} (recommended >= 12)")

        if not issues:
            return

        self._add_finding(
            "DR-AD-004",
            "Policy: Weak Domain Password Policy",
            "HIGH",
            "The Active Directory domain password policy does not meet "
            "recommended security standards. " + "; ".join(issues) + ".",
            "A weak domain password policy applies to all domain user accounts. "
            "Short passwords without complexity requirements can be cracked "
            "rapidly via offline attacks against NTDS.dit or captured hashes. "
            "The domain password policy is the single most impactful password "
            "control in the environment.",
            "Increase minimum password length to 12+ characters (14+ for "
            "privileged accounts). Enable complexity requirements. Set maximum "
            "password age to 60-90 days. Enforce at least 12 passwords of "
            "history. Deploy Fine-Grained Password Policies (PSOs) for "
            "privileged tiers. Implement Azure AD Password Protection for "
            "banned password lists.",
            output="\n".join(issues),
            remediation_effort="Moderate",
            cwe=["CWE-521"],
            nist_800_53=["IA-5"],
            pci_dss_4=["8.3.6"],
        )

    # ------------------------------------------------------------------ #
    # DR-AD-005  LDAP signing not enforced
    # ------------------------------------------------------------------ #
    def _check_ldap_signing(self, ad):
        ldap_signing = ad.get("ldap_signing",
                              ad.get("ldap_server_signing_requirements"))
        if ldap_signing is None:
            reg = self._get_section("registry_hardening", {})
            ldap_signing = reg.get("LDAPServerIntegrity",
                                   reg.get("ldap_signing"))
        if ldap_signing is None:
            return
        try:
            ldap_signing = int(ldap_signing)
        except (ValueError, TypeError):
            if isinstance(ldap_signing, str):
                low = ldap_signing.lower()
                if low in ("none", "disabled", "not required"):
                    ldap_signing = 0
                elif low in ("require", "required", "enforce"):
                    ldap_signing = 2
                else:
                    return
            else:
                return
        if ldap_signing < 2:
            labels = {0: "None (disabled)", 1: "Negotiate signing"}
            label = labels.get(ldap_signing, str(ldap_signing))
            self._add_finding(
                "DR-AD-005",
                "Active Directory: LDAP Signing Not Enforced",
                "MEDIUM",
                f"LDAP signing is set to '{label}' instead of 'Require signing'. "
                f"This allows LDAP traffic to be transmitted unsigned, enabling "
                f"man-in-the-middle attacks.",
                "Without enforced LDAP signing, an attacker can perform LDAP "
                "relay attacks, intercepting and modifying LDAP queries and "
                "responses. This can be used to escalate privileges, modify "
                "group memberships, or reset passwords via LDAP relay combined "
                "with NTLM relay techniques (e.g., ntlmrelayx).",
                "Set 'Domain controller: LDAP server signing requirements' to "
                "'Require signing' via Group Policy. Also enable LDAP channel "
                "binding. Test thoroughly before enforcement as it may break "
                "legacy applications using simple LDAP binds.",
                output=f"LDAP signing: {label} (value: {ldap_signing})",
                remediation_effort="Moderate",
                cwe=["CWE-294"],
                mitre_attack=[
                    {"technique": "T1557", "tactic": "Credential Access",
                     "name": "Adversary-in-the-Middle"},
                ],
                nist_800_53=["SC-8", "SC-23"],
            )

    # ------------------------------------------------------------------ #
    # DR-AD-006  Kerberos weak encryption (DES / RC4)
    # ------------------------------------------------------------------ #
    def _check_kerberos_encryption(self, ad):
        enc_types = ad.get("supported_encryption_types",
                           ad.get("kerberos_encryption_types", []))
        if isinstance(enc_types, int):
            weak = []
            if enc_types & 0x01:
                weak.append("DES-CBC-CRC")
            if enc_types & 0x02:
                weak.append("DES-CBC-MD5")
            if enc_types & 0x04:
                weak.append("RC4-HMAC")
        elif isinstance(enc_types, list):
            _WEAK = {"des-cbc-crc", "des-cbc-md5", "des", "rc4-hmac",
                      "rc4", "arcfour-hmac-md5"}
            weak = [e for e in enc_types
                    if isinstance(e, str) and e.lower() in _WEAK]
        elif isinstance(enc_types, str):
            _WEAK = {"des-cbc-crc", "des-cbc-md5", "des", "rc4-hmac",
                      "rc4", "arcfour-hmac-md5"}
            weak = [e.strip() for e in enc_types.split(",")
                    if e.strip().lower() in _WEAK]
        else:
            des_accounts = ad.get("des_enabled_accounts", [])
            if isinstance(des_accounts, list) and des_accounts:
                accts = []
                for a in des_accounts:
                    if isinstance(a, dict):
                        accts.append(a.get("samaccountname",
                                           a.get("name", str(a))))
                    else:
                        accts.append(str(a))
                self._add_finding(
                    "DR-AD-006",
                    "Authentication: Kerberos DES Encryption Enabled",
                    "MEDIUM",
                    f"{len(des_accounts)} account(s) have DES encryption enabled "
                    f"(USE_DES_KEY_ONLY flag). DES is a broken encryption "
                    f"algorithm and should never be used for Kerberos.",
                    "DES-encrypted Kerberos tickets can be cracked trivially "
                    "with modern hardware. An attacker intercepting Kerberos "
                    "traffic can decrypt tickets and extract credentials.",
                    "Clear the 'Use Kerberos DES encryption types for this "
                    "account' flag on all accounts. Ensure msDS-"
                    "SupportedEncryptionTypes is set to support only AES128 "
                    "and AES256.",
                    output="\n".join(accts[:15]),
                    remediation_effort="Moderate",
                    cwe=["CWE-327"],
                    mitre_attack=[
                        {"technique": "T1558", "tactic": "Credential Access",
                         "name": "Steal or Forge Kerberos Tickets"},
                    ],
                )
            return

        if not weak:
            return
        weak_list = ", ".join(weak)
        has_des = any("des" in w.lower() for w in weak)
        risk = "HIGH" if has_des else "MEDIUM"
        self._add_finding(
            "DR-AD-006",
            "Authentication: Kerberos Weak Encryption Types",
            risk,
            f"The domain supports weak Kerberos encryption types: {weak_list}. "
            f"DES and RC4 are cryptographically broken and should not be used "
            f"for Kerberos authentication.",
            "DES-encrypted Kerberos tickets can be cracked trivially. RC4-HMAC "
            "(NTLM-based) is vulnerable to Kerberoasting offline cracking and "
            "overpass-the-hash attacks. Allowing weak encryption types "
            "downgrades the security of the entire Kerberos infrastructure.",
            "Disable DES and RC4 encryption types in the domain. Set "
            "msDS-SupportedEncryptionTypes to support only AES128 (0x08) and "
            "AES256 (0x10). Test thoroughly — legacy systems (especially "
            "pre-2008 R2) may require RC4. Migrate legacy systems before "
            "disabling.",
            output=f"Weak encryption types: {weak_list}",
            remediation_effort="Significant",
            cwe=["CWE-327"],
            mitre_attack=[
                {"technique": "T1558.003", "tactic": "Credential Access",
                 "name": "Kerberoasting"},
            ],
            nist_800_53=["SC-12", "SC-13"],
        )

    # ------------------------------------------------------------------ #
    # DR-AD-008  Resource-Based Constrained Delegation (RBCD)
    # ------------------------------------------------------------------ #
    def _check_rbcd(self, ad):
        rbcd = ad.get("rbcd_accounts",
                      ad.get("resource_based_constrained_delegation", []))
        if not isinstance(rbcd, list) or not rbcd:
            return
        entries = []
        for entry in rbcd:
            if isinstance(entry, dict):
                target = entry.get("samaccountname",
                                   entry.get("name", entry.get("cn", "")))
                allowed = entry.get("allowed_to_act",
                                    entry.get("msds-allowedtoactonbehalfofotheridentity", ""))
                if isinstance(allowed, list):
                    allowed = ", ".join(str(a) for a in allowed[:3])
                entries.append(f"{target} <- {allowed}")
            elif isinstance(entry, str):
                entries.append(entry)
        output = "\n".join(entries[:20])
        self._add_finding(
            "DR-AD-008",
            "Active Directory: RBCD Configured",
            "MEDIUM",
            f"{len(rbcd)} account(s) have Resource-Based Constrained Delegation "
            f"configured (msDS-AllowedToActOnBehalfOfOtherIdentity). RBCD allows "
            f"specified principals to impersonate users to the target service.",
            "RBCD is a common privilege escalation vector. If an attacker can "
            "write to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute "
            "of a target (via WRITE permission on the computer object), they "
            "can configure RBCD to impersonate any user (including Domain "
            "Admin) to that target's services. This is the basis of the "
            "RBCD/S4U2Self/S4U2Proxy attack chain.",
            "Review all RBCD configurations for legitimacy. Ensure that only "
            "authorized principals have WRITE access to computer objects' "
            "msDS-AllowedToActOnBehalfOfOtherIdentity attribute. Monitor "
            "changes to this attribute via Event ID 5136. Remove unnecessary "
            "RBCD configurations.",
            output=output,
            remediation_effort="Moderate",
            mitre_attack=[
                {"technique": "T1558", "tactic": "Credential Access",
                 "name": "Steal or Forge Kerberos Tickets"},
                {"technique": "T1134.001", "tactic": "Privilege Escalation",
                 "name": "Token Impersonation/Theft"},
            ],
            nist_800_53=["AC-6", "AC-17"],
        )

    # ------------------------------------------------------------------ #
    # DR-AD-009  Domain functional level outdated
    # ------------------------------------------------------------------ #
    def _check_functional_level(self, ad):
        domain_fl = ad.get("domain_functional_level",
                           ad.get("domain_level", ""))
        forest_fl = ad.get("forest_functional_level",
                           ad.get("forest_level", ""))
        if not domain_fl and not forest_fl:
            return
        outdated = []
        for label, fl_value in [("Domain", domain_fl), ("Forest", forest_fl)]:
            if not fl_value or not isinstance(fl_value, str):
                continue
            fl_normalized = fl_value.replace(" ", "")
            for key, display in _OUTDATED_FUNC_LEVELS.items():
                if key.lower() in fl_normalized.lower():
                    outdated.append(f"{label} functional level: {fl_value} ({display})")
                    break
        if not outdated:
            return
        output = "\n".join(outdated)
        self._add_finding(
            "DR-AD-009",
            "Active Directory: Domain Functional Level Outdated",
            "MEDIUM",
            "The Active Directory domain or forest functional level is running "
            "at an outdated version. " + "; ".join(outdated) + ".",
            "Outdated functional levels prevent the use of modern Active "
            "Directory security features including: Protected Users group "
            "(2012 R2+), Authentication Policies and Silos (2012 R2+), "
            "gMSA improvements, Kerberos armoring (FAST), and AES-only "
            "Kerberos enforcement. Older levels also correspond to "
            "operating systems that may be end-of-life.",
            "Raise the domain and forest functional levels after ensuring all "
            "Domain Controllers are running a supported Windows Server version. "
            "This is a one-way operation — test in a lab environment first. "
            "Target at minimum Windows Server 2016 functional level.",
            output=output,
            remediation_effort="Significant",
            nist_800_53=["SA-22", "CM-6"],
        )

    # ------------------------------------------------------------------ #
    # DR-AD-010  AdminSDHolder protected users
    # ------------------------------------------------------------------ #
    def _check_adminsd_holder(self, ad):
        protected = ad.get("adminsd_holder",
                           ad.get("admincount_users", []))
        if not isinstance(protected, list) or not protected:
            return
        accts = []
        non_privileged = []
        for entry in protected:
            if isinstance(entry, dict):
                name = entry.get("samaccountname",
                                 entry.get("name", entry.get("cn", "")))
                admin_count = entry.get("admincount", 1)
                member_of = entry.get("memberof",
                                      entry.get("groups", []))
                accts.append(name)
                priv_groups = {"domain admins", "enterprise admins",
                               "schema admins", "administrators",
                               "account operators", "server operators",
                               "print operators", "backup operators"}
                if isinstance(member_of, list):
                    in_priv = any(
                        isinstance(g, str) and
                        any(pg in g.lower() for pg in priv_groups)
                        for g in member_of)
                    if not in_priv and admin_count == 1:
                        non_privileged.append(name)
                elif not member_of:
                    non_privileged.append(name)
            elif isinstance(entry, str):
                accts.append(entry)

        if non_privileged:
            output = "\n".join(non_privileged[:20])
            self._add_finding(
                "DR-AD-010",
                "Active Directory: AdminSDHolder Orphaned Accounts",
                "LOW",
                f"{len(non_privileged)} account(s) have AdminCount=1 set but "
                f"are not current members of any privileged group. These are "
                f"orphaned AdminSDHolder protections from former privilege.",
                "Orphaned AdminSDHolder flags indicate accounts that were "
                "previously in privileged groups. The AdminCount flag persists "
                "after removal, and the AdminSDHolder ACL propagation may have "
                "left non-standard permissions. Attackers target these accounts "
                "as they may retain residual privileges or weaker ACLs.",
                "Clear the AdminCount attribute on accounts no longer in "
                "privileged groups. Reset the ACL on these accounts to inherit "
                "from the parent OU. Use the AdminSDHolder cleanup script to "
                "automate this process. Monitor AdminCount changes with "
                "Event ID 5136.",
                output=f"Orphaned accounts ({len(non_privileged)}):\n{output}",
                remediation_effort="Moderate",
                nist_800_53=["AC-6"],
            )
        elif accts:
            self._add_finding(
                "DR-AD-010",
                "Active Directory: AdminSDHolder Protected Users",
                "INFO",
                f"{len(accts)} account(s) are protected by AdminSDHolder "
                f"(AdminCount=1). These accounts have their ACLs overwritten "
                f"every 60 minutes by the SDProp process.",
                "AdminSDHolder-protected accounts are high-value targets. Their "
                "ACLs are locked down by SDProp, but this also means manual "
                "permission changes are reverted. Knowing which accounts are "
                "protected helps identify the full set of privileged identities.",
                "Review the list of AdminSDHolder-protected accounts to ensure "
                "only authorized identities are in privileged groups. Remove "
                "unnecessary members from privileged groups to reduce the "
                "protected set.",
                output=f"Protected accounts ({len(accts)}):\n" +
                       "\n".join(accts[:20]),
                remediation_effort="Moderate",
                nist_800_53=["AC-6", "AC-2"],
            )

    # ------------------------------------------------------------------ #
    # DR-AD-011 / DR-AD-015 / DR-AD-016  LAPS checks
    # ------------------------------------------------------------------ #
    def _check_laps(self, ad):
        laps = self._get_section("laps_config", {})
        if not isinstance(laps, dict):
            return
        if not laps.get("available", True):
            return
        legacy = laps.get("legacy_laps_installed", False)
        windows_laps = laps.get("windows_laps_installed", False)
        if not legacy and not windows_laps:
            self._add_finding(
                "DR-AD-011", "Active Directory: LAPS Not Deployed", "HIGH",
                "Local Administrator Password Solution (LAPS) is not deployed. "
                "Local administrator accounts likely share the same password "
                "across multiple machines.",
                "Without LAPS, compromising one local admin password grants access "
                "to every machine sharing that password, enabling rapid lateral "
                "movement across the domain.",
                "Deploy Microsoft LAPS (legacy or Windows LAPS) to automatically "
                "rotate local administrator passwords and store them securely in "
                "Active Directory.",
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1078.002", "tactic": "Persistence",
                               "name": "Domain Accounts"}],
                nist_800_53=["IA-5", "AC-6"],
                pci_dss_4=["8.3.6"],
            )
            return

        policy = laps.get("laps_policy", {})
        if isinstance(policy, dict) and policy:
            issues = []
            pw_len = policy.get("PasswordLength")
            pw_age = policy.get("PasswordAgeDays")
            pw_complex = policy.get("PasswordComplexity")
            try:
                if pw_len is not None and int(pw_len) < 15:
                    issues.append(f"PasswordLength={pw_len} (recommended >= 20)")
            except (ValueError, TypeError):
                pass
            try:
                if pw_age is not None and int(pw_age) > 30:
                    issues.append(f"PasswordAgeDays={pw_age} (recommended <= 15)")
            except (ValueError, TypeError):
                pass
            try:
                if pw_complex is not None and int(pw_complex) < 4:
                    issues.append(f"PasswordComplexity={pw_complex} (recommended 4)")
            except (ValueError, TypeError):
                pass
            if issues:
                self._add_finding(
                    "DR-AD-015",
                    "Active Directory: LAPS Weak Password Policy",
                    "MEDIUM",
                    "LAPS is deployed but the password policy is weaker than "
                    "recommended. " + "; ".join(issues) + ".",
                    "Short or simple LAPS-managed passwords, or infrequent "
                    "rotation, undermine the protection LAPS provides. A weak "
                    "LAPS password can be brute-forced if the ms-Mcs-AdmPwd "
                    "attribute is ever exposed or intercepted.",
                    "Set LAPS PasswordLength to 20+, PasswordAgeDays to 15, "
                    "and PasswordComplexity to 4 (upper + lower + digits + "
                    "specials) via Group Policy.",
                    output="\n".join(issues),
                    remediation_effort="Easy",
                    nist_800_53=["IA-5"],
                    pci_dss_4=["8.3.6"],
                )

        admpwd_readable = laps.get("admpwd_readable")
        if admpwd_readable is True:
            self._add_finding(
                "DR-AD-016",
                "Active Directory: LAPS Password Readable by Non-Administrators",
                "HIGH",
                "The LAPS-managed local administrator password (ms-Mcs-AdmPwd) "
                "is readable by the context under which data collection ran. If "
                "this was a standard user account, the LAPS ACLs are misconfigured.",
                "If non-administrative users can read ms-Mcs-AdmPwd, any "
                "compromised domain user can retrieve the local administrator "
                "password for every LAPS-managed machine in the domain, enabling "
                "immediate lateral movement with local admin privileges.",
                "Restrict read access to ms-Mcs-AdmPwd to only the designated "
                "LAPS admin groups using Set-AdmPwdReadPasswordPermission. "
                "Audit current permissions with Find-AdmPwdExtendedRights.",
                output="ms-Mcs-AdmPwd: readable by collection context",
                remediation_effort="Easy",
                mitre_attack=[{"technique": "T1078.002", "tactic": "Persistence",
                               "name": "Domain Accounts"}],
                nist_800_53=["AC-3", "AC-6"],
                pci_dss_4=["7.2.1"],
            )

    def _check_krbtgt(self, ad):
        krbtgt_last_set = ad.get("krbtgt_password_last_set")
        if not krbtgt_last_set:
            return
        try:
            from datetime import datetime, timezone
            last = datetime.fromisoformat(str(krbtgt_last_set).replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - last).days
            if age_days > 180:
                self._add_finding(
                    "DR-AD-012", "Active Directory: krbtgt Key Not Rotated", "MEDIUM",
                    f"The krbtgt account password has not been changed in {age_days} "
                    f"days. Microsoft recommends rotating it at least every 180 days.",
                    "The krbtgt account key is used to sign all Kerberos tickets. If "
                    "compromised via a Golden Ticket attack, the attacker maintains "
                    "persistent domain access until the key is rotated twice.",
                    "Rotate the krbtgt password twice (with a delay of at least "
                    "10 hours between resets to allow replication). Monitor for "
                    "authentication failures after rotation.",
                    output=f"krbtgt password age: {age_days} days",
                    remediation_effort="Moderate",
                    mitre_attack=[{"technique": "T1558.001", "tactic": "Credential Access",
                                   "name": "Golden Ticket"}],
                    nist_800_53=["IA-5"],
                )
        except Exception:
            pass

    def _check_stale_accounts(self, ad):
        users = ad.get("users", [])
        if not isinstance(users, list):
            return
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        stale = []
        for u in users:
            if not isinstance(u, dict):
                continue
            last_logon = u.get("last_logon")
            if not last_logon:
                continue
            try:
                ll = datetime.fromisoformat(str(last_logon).replace("Z", "+00:00"))
                if (now - ll).days > 90 and u.get("enabled", True):
                    stale.append(u.get("samaccountname", u.get("name", "?")))
            except Exception:
                continue
        if len(stale) > 5:
            self._add_finding(
                "DR-AD-013", "Account Management: Stale Domain Accounts", "LOW",
                f"{len(stale)} enabled domain accounts have not logged in for over "
                f"90 days. Stale accounts increase the attack surface.",
                "Stale accounts are prime targets for password spraying and "
                "credential stuffing attacks because their passwords may be weak "
                "or predictable, and compromise may go unnoticed.",
                "Review and disable accounts not used in 90+ days. Implement an "
                "automated account lifecycle process with regular reviews.",
                output=f"Stale accounts ({len(stale)}):\n" +
                       "\n".join(stale[:20]),
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1078.002", "tactic": "Persistence",
                               "name": "Domain Accounts"}],
                nist_800_53=["AC-2"],
            )

    def _check_sid_history(self, ad):
        users = ad.get("users", [])
        if not isinstance(users, list):
            return
        sid_hist_users = []
        for u in users:
            if not isinstance(u, dict):
                continue
            sh = u.get("sid_history", [])
            if isinstance(sh, list) and len(sh) > 0:
                sid_hist_users.append(u.get("samaccountname", u.get("name", "?")))
        if sid_hist_users:
            self._add_finding(
                "DR-AD-014", "Active Directory: SID History Abuse Risk", "MEDIUM",
                f"{len(sid_hist_users)} account(s) have SID History entries. SID "
                f"History can be abused to impersonate accounts from trusted domains.",
                "An attacker with write access to AD can inject arbitrary SIDs into "
                "an account's SID History, granting that account the privileges of "
                "the injected SID — including Domain Admin from a trusted domain.",
                "Remove unnecessary SID History entries. Monitor for SID History "
                "changes (Event ID 4765). Implement SID Filtering on domain trusts.",
                output=f"Accounts with SID History:\n" +
                       "\n".join(sid_hist_users[:20]),
                remediation_effort="Moderate",
                mitre_attack=[{"technique": "T1134.005", "tactic": "Defense Evasion",
                               "name": "SID-History Injection"}],
                nist_800_53=["AC-6"],
            )

    # ------------------------------------------------------------------ #
    # DR-AD-017  Fine-Grained Password Policies
    # ------------------------------------------------------------------ #
    def _check_fine_grained_password_policies(self, ad):
        if not self.os_info.get("is_domain_joined"):
            return
        fgpps = ad.get("fine_grained_password_policies",
                        ad.get("pso_policies", []))
        if isinstance(fgpps, list) and fgpps:
            return
        self._add_finding(
            "DR-AD-017",
            "Active Directory: Fine-Grained Password Policies Not Deployed",
            "LOW",
            "No Fine-Grained Password Policies (FGPPs / Password Settings "
            "Objects) are deployed in the domain. All accounts must use the "
            "single Default Domain Policy for password requirements.",
            "Without FGPPs, service accounts and privileged accounts cannot "
            "have stricter password requirements than standard users. "
            "Privileged accounts should require longer passwords and shorter "
            "rotation intervals than the baseline domain policy.",
            "Create FGPPs (Password Settings Objects) for privileged tiers: "
            "Domain Admins with 25+ character minimum, service accounts with "
            "20+ character minimum, and standard users with 12+ minimum. "
            "Apply via Security Groups in ADAC or PowerShell "
            "New-ADFineGrainedPasswordPolicy.",
            remediation_effort="Moderate",
            nist_800_53=["IA-5", "AC-2"],
            pci_dss_4=["8.3.6"],
        )

    # ------------------------------------------------------------------ #
    # DR-AD-018  Group Managed Service Accounts (gMSA)
    # ------------------------------------------------------------------ #
    def _check_gmsa(self, ad):
        if not self.os_info.get("is_domain_joined"):
            return
        kerberoastable = ad.get("kerberoastable_accounts",
                                ad.get("spn_accounts", []))
        if not isinstance(kerberoastable, list) or not kerberoastable:
            return
        gmsa = ad.get("gmsa_accounts",
                       ad.get("managed_service_accounts", []))
        if isinstance(gmsa, list) and gmsa:
            return
        self._add_finding(
            "DR-AD-018",
            "Active Directory: Group Managed Service Accounts Not Utilized",
            "LOW",
            f"The domain has {len(kerberoastable)} Kerberoastable service "
            f"account(s) with SPNs but no Group Managed Service Accounts "
            f"(gMSAs) are deployed.",
            "gMSAs automatically rotate 120-character, cryptographically random "
            "passwords every 30 days. Without gMSAs, service accounts use "
            "static human-managed passwords that are vulnerable to "
            "Kerberoasting offline cracking. gMSA eliminates this entire "
            "attack class for accounts that support it.",
            "Migrate service accounts to gMSAs where the application supports "
            "it (SQL Server, IIS, scheduled tasks, Windows services). Create "
            "gMSAs with New-ADServiceAccount -DNSHostName ... "
            "-PrincipalsAllowedToRetrieveManagedPassword. Test each "
            "application with the gMSA before removing the legacy SPN account.",
            remediation_effort="Significant",
            mitre_attack=[{"technique": "T1558.003", "tactic": "Credential Access",
                           "name": "Kerberoasting"}],
            nist_800_53=["IA-5", "AC-2"],
        )
