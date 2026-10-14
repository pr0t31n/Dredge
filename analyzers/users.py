from analyzers.base import BaseAnalyzer


class UserAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_builtin_admin()
        self._check_guest()
        self._check_password_never_expires()
        self._check_excessive_admins()
        self._check_password_policy()
        self._check_lockout_policy()
        return self.findings

    # ------------------------------------------------------------------ #
    # DR-USR-001  Default Administrator account enabled
    # ------------------------------------------------------------------ #
    def _check_builtin_admin(self):
        accounts = self._get_section("user_accounts", {})
        local_users = accounts.get("local_users", [])
        if not isinstance(local_users, list):
            return
        for user in local_users:
            if not isinstance(user, dict):
                continue
            sid = user.get("sid", "")
            enabled = user.get("enabled", False)
            if isinstance(sid, str) and sid.endswith("-500") and enabled:
                name = user.get("name", "Administrator")
                self._add_finding(
                    "DR-USR-001",
                    "Account Management: Built-in Administrator Enabled",
                    "MEDIUM",
                    f"The built-in Administrator account (SID ending in -500) is "
                    f"enabled with the name '{name}'. This well-known account is "
                    f"the primary target for brute-force and credential-stuffing "
                    f"attacks.",
                    "The built-in Administrator account is exempt from account "
                    "lockout policies by default, allowing unlimited authentication "
                    "attempts. It is a well-known target for brute-force attacks, "
                    "pass-the-hash, and credential replay. Compromise of this "
                    "account grants full control of the local system.",
                    "Disable the built-in Administrator account and create named "
                    "individual administrator accounts for auditing purposes. If "
                    "it must remain enabled for break-glass scenarios, rename it, "
                    "set a strong unique password (25+ chars), and monitor its "
                    "usage with alerting.",
                    output=f"Account: {name}\nSID: {sid}\nEnabled: {enabled}",
                    remediation_effort="Easy",
                    nist_800_53=["AC-2", "AC-6"],
                    mitre_attack=[
                        {"technique": "T1078.001", "tactic": "Persistence",
                         "name": "Default Accounts"},
                    ],
                )
                break

    # ------------------------------------------------------------------ #
    # DR-USR-002  Guest account enabled
    # ------------------------------------------------------------------ #
    def _check_guest(self):
        accounts = self._get_section("user_accounts", {})
        local_users = accounts.get("local_users", [])
        if not isinstance(local_users, list):
            return
        for user in local_users:
            if not isinstance(user, dict):
                continue
            sid = user.get("sid", "")
            enabled = user.get("enabled", False)
            if isinstance(sid, str) and sid.endswith("-501") and enabled:
                name = user.get("name", "Guest")
                self._add_finding(
                    "DR-USR-002",
                    "Account Management: Guest Account Enabled",
                    "HIGH",
                    f"The Guest account ('{name}') is enabled, providing a path "
                    f"for unauthenticated access to the system. The Guest account "
                    f"is a well-known Windows built-in account (SID -501).",
                    "The Guest account allows anonymous or low-privilege access "
                    "without requiring a password. Attackers can use it as a "
                    "foothold for privilege escalation, local enumeration, and "
                    "information gathering. It can also be abused in SMB null "
                    "session attacks and relay scenarios.",
                    "Disable the Guest account immediately: "
                    "net user Guest /active:no. Verify via Group Policy that "
                    "'Accounts: Guest account status' is set to Disabled.",
                    output=f"Account: {name}\nSID: {sid}\nEnabled: {enabled}",
                    remediation_effort="Easy",
                    nist_800_53=["AC-2"],
                    mitre_attack=[
                        {"technique": "T1078.001", "tactic": "Persistence",
                         "name": "Default Accounts"},
                    ],
                )
                break

    # ------------------------------------------------------------------ #
    # DR-USR-003  Users with password never expires
    # ------------------------------------------------------------------ #
    def _check_password_never_expires(self):
        accounts = self._get_section("user_accounts", {})
        local_users = accounts.get("local_users", [])
        if not isinstance(local_users, list):
            return
        no_expire = []
        for user in local_users:
            if not isinstance(user, dict):
                continue
            if not user.get("enabled", False):
                continue
            if user.get("password_never_expires", False):
                name = user.get("name", "")
                sid = user.get("sid", "")
                no_expire.append(f"{name} (SID: {sid})" if sid else name)
        if no_expire:
            acct_list = "\n".join(no_expire[:15])
            self._add_finding(
                "DR-USR-003",
                "Account Management: Password Never Expires",
                "MEDIUM",
                f"{len(no_expire)} enabled account(s) have passwords set to never "
                f"expire. These accounts can retain the same password indefinitely, "
                f"regardless of the domain or local password policy.",
                "Accounts with non-expiring passwords may retain compromised or "
                "weak credentials indefinitely. If a password is leaked through "
                "a breach, phishing, or keylogging, the attacker has unlimited "
                "time to exploit it. This violates the principle of credential "
                "rotation and increases the window for credential-based attacks.",
                "Enable password expiration for all interactive user accounts. "
                "For service accounts, migrate to Group Managed Service Accounts "
                "(gMSA) which handle automatic credential rotation. If password "
                "expiration cannot be enabled, enforce multi-factor authentication.",
                output=f"Accounts with non-expiring passwords ({len(no_expire)}):\n{acct_list}",
                remediation_effort="Easy",
                nist_800_53=["IA-5"],
                mitre_attack=[
                    {"technique": "T1078", "tactic": "Persistence",
                     "name": "Valid Accounts"},
                ],
            )

    # ------------------------------------------------------------------ #
    # DR-USR-004  Excessive local administrators (> 3)
    # ------------------------------------------------------------------ #
    def _check_excessive_admins(self):
        accounts = self._get_section("user_accounts", {})
        admin_group = accounts.get("administrators_group", [])
        if not isinstance(admin_group, list):
            return
        if len(admin_group) > 3:
            members = []
            for m in admin_group[:15]:
                if isinstance(m, str):
                    members.append(m)
                elif isinstance(m, dict):
                    members.append(m.get("name", str(m)))
                else:
                    members.append(str(m))
            member_list = "\n".join(members)
            self._add_finding(
                "DR-USR-004",
                "Account Management: Excessive Local Administrators",
                "MEDIUM",
                f"The local Administrators group has {len(admin_group)} members. "
                f"Best practice recommends no more than 3 members to limit the "
                f"attack surface.",
                "Every local administrator account is a potential path to full "
                "system compromise. Excessive administrators increase the blast "
                "radius of credential theft, reduce accountability (harder to "
                "audit who did what), and violate the principle of least privilege. "
                "Each additional admin credential is another target for "
                "pass-the-hash and credential replay attacks.",
                "Reduce local administrator membership to only essential accounts. "
                "Use LAPS (Local Administrator Password Solution) for the built-in "
                "admin account. Implement JIT/PAM solutions for temporary "
                "privilege elevation instead of persistent admin group membership.",
                output=f"Administrator group members ({len(admin_group)}):\n{member_list}",
                remediation_effort="Moderate",
                nist_800_53=["AC-6", "AC-2"],
                mitre_attack=[
                    {"technique": "T1078.003", "tactic": "Privilege Escalation",
                     "name": "Local Accounts"},
                ],
            )

    # ------------------------------------------------------------------ #
    # DR-USR-005  Weak password policy (min length < 12)
    # ------------------------------------------------------------------ #
    def _check_password_policy(self):
        policy = self._get_section("security_policy", {})
        pw_policy = policy.get("password_policy", {})
        if not isinstance(pw_policy, dict):
            return
        min_length = pw_policy.get("min_length", 0)
        complexity = pw_policy.get("complexity_enabled", True)
        max_age = pw_policy.get("max_age", 0)
        history = pw_policy.get("history_count", pw_policy.get("enforce_history", 0))
        try:
            min_length = int(min_length)
        except (ValueError, TypeError):
            min_length = 0
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
            issues.append(f"Minimum password length: {min_length} (recommended >= 12)")
        if not complexity:
            issues.append("Password complexity requirement: Disabled")
        if max_age == 0:
            issues.append("Maximum password age: 0 (passwords never expire)")
        if history < 12:
            issues.append(f"Password history: {history} (recommended >= 12)")

        if not issues:
            return

        self._add_finding(
            "DR-USR-005",
            "Policy: Weak Password Policy",
            "HIGH",
            "The local password policy does not meet minimum security "
            "requirements. " + "; ".join(issues) + ".",
            "Weak password policies allow users to set easily guessable "
            "passwords that can be cracked through brute force, dictionary "
            "attacks, or password spraying in minutes. Short passwords with "
            "no complexity requirements are trivially crackable with modern "
            "GPU-based tools (hashcat, John the Ripper).",
            "Set minimum password length to at least 12 characters (14+ for "
            "privileged accounts). Enable complexity requirements. Set maximum "
            "password age to 60-90 days. Enforce at least 12 passwords of "
            "history. Consider implementing a banned password list and "
            "Azure AD Password Protection.",
            output="\n".join(issues),
            remediation_effort="Easy",
            cwe=["CWE-521"],
            nist_800_53=["IA-5"],
            pci_dss_4=["8.3.6"],
        )

    # ------------------------------------------------------------------ #
    # DR-USR-006  Account lockout not configured or threshold too high
    # ------------------------------------------------------------------ #
    def _check_lockout_policy(self):
        policy = self._get_section("security_policy", {})
        lockout = policy.get("lockout_policy", {})
        if not isinstance(lockout, dict):
            return
        threshold = lockout.get("threshold", 0)
        duration = lockout.get("duration", 0)
        reset_counter = lockout.get("reset_counter",
                                    lockout.get("observation_window", 0))
        try:
            threshold = int(threshold)
        except (ValueError, TypeError):
            threshold = 0
        try:
            duration = int(duration)
        except (ValueError, TypeError):
            duration = 0
        try:
            reset_counter = int(reset_counter)
        except (ValueError, TypeError):
            reset_counter = 0

        issues = []
        if threshold == 0:
            issues.append("Lockout threshold: 0 (unlimited attempts allowed)")
        elif threshold > 10:
            issues.append(f"Lockout threshold: {threshold} (too permissive, "
                          f"recommended 5-10)")
        if threshold > 0 and duration < 15:
            issues.append(f"Lockout duration: {duration} min (recommended >= 15)")
        if threshold > 0 and reset_counter < 15:
            issues.append(f"Reset counter: {reset_counter} min (recommended >= 15)")

        if not issues:
            return

        risk = "HIGH" if threshold == 0 else "MEDIUM"
        self._add_finding(
            "DR-USR-006",
            "Authentication: Account Lockout Not Configured",
            risk,
            "The account lockout policy is not configured or is too permissive. "
            + "; ".join(issues) + ".",
            "Without effective account lockout, attackers can perform unlimited "
            "brute-force and password-spraying attempts against user accounts "
            "without triggering any defensive response. A threshold above 10 "
            "provides minimal protection as automated tools can easily stay "
            "below it with slow-rate attacks.",
            "Configure account lockout threshold to 5-10 failed attempts. Set "
            "lockout duration to at least 15 minutes. Set the observation "
            "window (reset counter) to 15 minutes. Consider implementing "
            "smart lockout via Azure AD for adaptive protection.",
            output="\n".join(issues),
            remediation_effort="Easy",
            nist_800_53=["AC-7"],
            pci_dss_4=["8.3.4"],
            mitre_attack=[
                {"technique": "T1110", "tactic": "Credential Access",
                 "name": "Brute Force"},
            ],
        )
