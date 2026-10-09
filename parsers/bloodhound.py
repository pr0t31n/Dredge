import uuid
import datetime
import json
import os
import zipfile
import tempfile

_ADMIN_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "server operators",
    "backup operators", "print operators",
}

_STALE_DAYS = 90


class BloodHoundParser:
    def __init__(self, file_path, hostname="", ip=""):
        self.file_path = file_path
        self.hostname = hostname
        self.ip = ip
        self.findings = []

    def _add_finding(self, catalogue_id, title, risk, description, impact,
                     remediation, **kwargs):
        finding = {
            "id": str(uuid.uuid4()),
            "tool": "dredge",
            "catalogue_id": catalogue_id,
            "title": title,
            "datetime": datetime.datetime.now().isoformat(),
            "ip": self.ip,
            "port": kwargs.get("port", 0),
            "hostname": self.hostname,
            "risk": risk,
            "command": kwargs.get("command", ""),
            "description": description,
            "impact": impact,
            "sources": kwargs.get("sources", "dredge"),
            "affected": kwargs.get("affected", self.hostname or self.ip),
            "remediation": remediation,
            "exploitdb": kwargs.get("exploitdb", False),
            "metasploit": kwargs.get("metasploit", False),
            "exploit_details": kwargs.get("exploit_details", []),
            "scope": kwargs.get("scope", "endpoint"),
            "output": kwargs.get("output", ""),
            "output_file": kwargs.get("output_file", ""),
            "cves": kwargs.get("cves", ""),
            "service": kwargs.get("service", ""),
            "owasp": kwargs.get("owasp", ""),
            "nist": kwargs.get("nist", ""),
            "cwe": kwargs.get("cwe", []),
            "cvss_score": kwargs.get("cvss_score", None),
            "cvss_vector": kwargs.get("cvss_vector", ""),
            "confidence": kwargs.get("confidence", "Certain"),
            "remediation_effort": kwargs.get("remediation_effort", ""),
            "remediation_component": kwargs.get("remediation_component", ""),
            "remediation_category": kwargs.get("remediation_category", ""),
            "mitre_attack": kwargs.get("mitre_attack", []),
            "nist_800_53": kwargs.get("nist_800_53", []),
            "nist_csf2": kwargs.get("nist_csf2", []),
            "pci_dss_4": kwargs.get("pci_dss_4", []),
        }
        self.findings.append(finding)

    def parse(self):
        if not os.path.exists(self.file_path):
            return self.findings

        try:
            data = self._load_data()
        except Exception:
            return self.findings

        if not isinstance(data, dict):
            return self.findings

        users = data.get("users", [])
        computers = data.get("computers", [])
        groups = data.get("groups", [])

        self._check_kerberoastable(users)
        self._check_asrep_roastable(users)
        self._check_unconstrained_delegation(computers)
        self._check_stale_accounts(users, computers)
        self._check_sid_history(users)
        self._check_laps(computers)
        self._check_excessive_admins(users, groups)
        self._check_adminsdh_orphans(users, groups)
        self._check_rbcd(computers)

        return self.findings

    # ── Data loading ────────────────────────────────────────────────────
    def _load_data(self):
        if os.path.isdir(self.file_path):
            return self._load_directory(self.file_path)

        if zipfile.is_zipfile(self.file_path):
            return self._load_zip(self.file_path)

        with open(self.file_path, encoding="utf-8") as f:
            loaded = json.load(f)

        if isinstance(loaded, dict):
            return loaded
        return {}

    def _load_zip(self, zip_path):
        result = {}
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                lower = name.lower()
                if not lower.endswith(".json"):
                    continue
                basename = os.path.basename(lower)
                key = self._json_basename_to_key(basename)
                if not key:
                    continue
                try:
                    with zf.open(name) as member:
                        loaded = json.loads(member.read().decode("utf-8"))
                    if isinstance(loaded, dict) and "data" in loaded:
                        result[key] = loaded["data"]
                    elif isinstance(loaded, list):
                        result[key] = loaded
                except Exception:
                    continue
        return result

    def _load_directory(self, path):
        result = {}
        try:
            entries = os.listdir(path)
        except OSError:
            return result

        for fname in entries:
            lower = fname.lower()
            if not lower.endswith(".json"):
                continue
            key = self._json_basename_to_key(lower)
            if not key or key in result:
                continue
            fpath = os.path.join(path, fname)
            try:
                with open(fpath, encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict) and "data" in loaded:
                    result[key] = loaded["data"]
                elif isinstance(loaded, list):
                    result[key] = loaded
            except Exception:
                continue
        return result

    def _json_basename_to_key(self, basename):
        for key in ("users", "computers", "groups", "domains",
                     "sessions", "ous", "gpos"):
            if key in basename:
                return key
        return ""

    # ── Property helpers ────────────────────────────────────────────────
    def _get_prop(self, obj, *keys):
        props = obj.get("Properties", obj.get("properties", obj))
        if isinstance(props, dict):
            for k in keys:
                v = props.get(k)
                if v is not None:
                    return v
        for k in keys:
            v = obj.get(k)
            if v is not None:
                return v
        return None

    def _get_name(self, obj):
        return (self._get_prop(obj, "name", "Name", "samaccountname") or
                obj.get("ObjectIdentifier", "unknown"))

    # ── Kerberoastable → DR-AD-005 ──────────────────────────────────────
    def _check_kerberoastable(self, users):
        spn_users = []
        for u in users:
            if self._get_prop(u, "hasspn", "HasSPN"):
                name = self._get_name(u)
                admin = self._get_prop(u, "admincount", "AdminCount")
                marker = " [ADMIN]" if admin else ""
                spn_users.append(f"{name}{marker}")
        if spn_users:
            self._add_finding(
                "DR-AD-005",
                "Kerberoastable Accounts Found",
                "MEDIUM",
                f"{len(spn_users)} user account(s) have SPNs set, making them "
                f"vulnerable to Kerberoasting attacks.",
                "Kerberoasting allows any authenticated user to request service "
                "tickets and crack them offline. Admin-flagged accounts are "
                "especially dangerous.",
                "Set strong passwords (25+ chars) on SPN accounts. Migrate to "
                "Group Managed Service Accounts (gMSA).",
                output="\n".join(spn_users[:30]),
            )

    # ── AS-REP Roastable → DR-AD-006 ───────────────────────────────────
    def _check_asrep_roastable(self, users):
        roastable = []
        for u in users:
            if self._get_prop(u, "dontreqpreauth", "DontRequirePreAuth"):
                roastable.append(self._get_name(u))
        if roastable:
            self._add_finding(
                "DR-AD-006",
                "AS-REP Roastable Accounts Found",
                "HIGH",
                f"{len(roastable)} account(s) have Kerberos pre-authentication "
                f"disabled, making them vulnerable to AS-REP roasting.",
                "AS-REP roasting allows offline password cracking without valid "
                "domain credentials, often used for initial access.",
                "Enable Kerberos pre-authentication for all accounts. Use "
                "strong passwords (25+ chars) for any account that requires "
                "pre-auth disabled.",
                output="\n".join(roastable[:30]),
            )

    # ── Unconstrained Delegation → DR-AD-003 ───────────────────────────
    def _check_unconstrained_delegation(self, computers):
        delegated = []
        for c in computers:
            if self._get_prop(c, "unconstraineddelegation",
                              "UnconstrainedDelegation"):
                name = self._get_name(c)
                if not self._get_prop(c, "isdc", "IsDC"):
                    delegated.append(name)
        if delegated:
            self._add_finding(
                "DR-AD-003",
                "Unconstrained Delegation on Non-DC Computers",
                "HIGH",
                f"{len(delegated)} non-DC computer(s) have unconstrained "
                f"delegation enabled.",
                "Unconstrained delegation allows the computer to impersonate "
                "any user who authenticates to it. An attacker who compromises "
                "such a machine can harvest TGTs for privilege escalation.",
                "Replace unconstrained delegation with constrained delegation "
                "or resource-based constrained delegation (RBCD).",
                output="\n".join(delegated[:20]),
                mitre_attack=[{"technique": "T1558.001",
                               "tactic": "Credential Access",
                               "name": "Golden Ticket"}],
            )

    # ── Stale Accounts → DR-AD-013 ─────────────────────────────────────
    def _check_stale_accounts(self, users, computers):
        now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
        stale = []
        for obj in list(users) + list(computers):
            last_logon = self._get_prop(obj, "lastlogontimestamp",
                                         "LastLogonTimestamp", "lastlogon")
            if last_logon is None:
                continue
            if isinstance(last_logon, (int, float)):
                if last_logon > 1e12:
                    last_logon = last_logon / 1000
                if last_logon < 1e9:
                    continue
                age_days = (now_ts - last_logon) / 86400
            else:
                continue
            if age_days > _STALE_DAYS:
                name = self._get_name(obj)
                stale.append(f"{name} ({int(age_days)}d)")

        if stale:
            self._add_finding(
                "DR-AD-013",
                "Stale Domain Accounts",
                "LOW",
                f"{len(stale)} account(s) have not logged in for over "
                f"{_STALE_DAYS} days.",
                "Stale accounts can be exploited for domain persistence or to "
                "bypass security monitoring.",
                "Disable or delete stale accounts. Implement an automated "
                "cleanup policy.",
                output="\n".join(stale[:30]),
            )

    # ── SID History → DR-AD-014 ─────────────────────────────────────────
    def _check_sid_history(self, users):
        sid_history_users = []
        for u in users:
            sh = self._get_prop(u, "sidhistory", "SIDHistory")
            if sh and isinstance(sh, list) and len(sh) > 0:
                sid_history_users.append(
                    f"{self._get_name(u)} ({len(sh)} SID(s))")

        if sid_history_users:
            self._add_finding(
                "DR-AD-014",
                "Accounts with SID History",
                "MEDIUM",
                f"{len(sid_history_users)} account(s) have SID History set.",
                "SID History can be abused to impersonate accounts from "
                "trusted domains or gain unauthorized access to resources "
                "that trust the historical SID.",
                "Remove unnecessary SID History entries. Enable SID Filtering "
                "on domain trusts.",
                output="\n".join(sid_history_users[:20]),
                mitre_attack=[{"technique": "T1134.005",
                               "tactic": "Privilege Escalation",
                               "name": "SID-History Injection"}],
            )

    # ── LAPS Not Deployed → DR-AD-011 ──────────────────────────────────
    def _check_laps(self, computers):
        total = 0
        no_laps = 0
        for c in computers:
            total += 1
            laps_exp = self._get_prop(
                c, "laps", "LAPS", "ms-mcs-admpwdexpirationtime",
                "msmcsadmpwdexpirationtime")
            if not laps_exp:
                no_laps += 1

        if total > 0 and no_laps > (total * 0.5):
            self._add_finding(
                "DR-AD-011",
                "LAPS Not Deployed",
                "MEDIUM",
                f"{no_laps} of {total} computer account(s) have no LAPS "
                f"expiration timestamp, indicating LAPS is not deployed.",
                "Without LAPS, local administrator passwords are often shared "
                "across machines, enabling lateral movement after a single "
                "password compromise.",
                "Deploy Microsoft LAPS (or Windows LAPS) to all domain-joined "
                "computers to randomize local admin passwords.",
                output=f"Computers without LAPS: {no_laps}/{total}",
            )

    # ── Excessive Admins ────────────────────────────────────────────────
    def _check_excessive_admins(self, users, groups):
        admin_members = set()
        for g in groups:
            gname = (self._get_name(g) or "").lower()
            if gname.split("@")[0] in _ADMIN_GROUPS:
                members = g.get("Members", g.get("members", []))
                for m in members:
                    mid = m.get("ObjectIdentifier", m.get("MemberId", ""))
                    mtype = m.get("ObjectType", m.get("MemberType", ""))
                    if mtype.lower() in ("user", ""):
                        admin_members.add(mid)

        if len(admin_members) > 10:
            self._add_finding(
                "DR-AD-010",
                "Excessive Domain Admin Accounts",
                "MEDIUM",
                f"{len(admin_members)} user(s) are members of privileged "
                f"domain groups (Domain Admins, Enterprise Admins, etc.).",
                "Excessive privileged accounts increase the attack surface. "
                "Each account is a potential target for credential theft.",
                "Reduce membership in privileged groups to the minimum "
                "required. Implement a tiered administration model.",
                output=f"Privileged users: {len(admin_members)}",
            )

    # ── AdminSDHolder Orphans ───────────────────────────────────────────
    def _check_adminsdh_orphans(self, users, groups):
        admin_group_members = set()
        for g in groups:
            gname = (self._get_name(g) or "").lower()
            if gname.split("@")[0] in _ADMIN_GROUPS:
                for m in g.get("Members", g.get("members", [])):
                    mid = m.get("ObjectIdentifier", m.get("MemberId", ""))
                    if mid:
                        admin_group_members.add(mid)

        orphans = []
        for u in users:
            if self._get_prop(u, "admincount", "AdminCount"):
                uid = u.get("ObjectIdentifier", "")
                if uid and uid not in admin_group_members:
                    orphans.append(self._get_name(u))

        if orphans:
            self._add_finding(
                "DR-AD-010",
                "AdminSDHolder Orphaned Accounts",
                "LOW",
                f"{len(orphans)} account(s) have AdminCount=1 but are not "
                f"members of any privileged group.",
                "AdminSDHolder orphans retain elevated permissions from former "
                "group membership, creating hidden privilege escalation paths.",
                "Clear AdminCount and reset ACL inheritance on orphaned "
                "accounts.",
                output="\n".join(orphans[:20]),
            )

    # ── RBCD ────────────────────────────────────────────────────────────
    def _check_rbcd(self, computers):
        rbcd = []
        for c in computers:
            allowed = self._get_prop(
                c, "allowedtoact", "AllowedToAct",
                "msds-allowedtoactonbehalfofotheridentity")
            if allowed and isinstance(allowed, list) and len(allowed) > 0:
                rbcd.append(
                    f"{self._get_name(c)} ({len(allowed)} principal(s))")

        if rbcd:
            self._add_finding(
                "DR-AD-008",
                "Resource-Based Constrained Delegation Configured",
                "MEDIUM",
                f"{len(rbcd)} computer(s) have RBCD configured.",
                "Misconfigured RBCD can allow an attacker who controls a "
                "delegated principal to impersonate any user to the target "
                "service.",
                "Audit RBCD configurations and ensure only authorized "
                "principals are listed.",
                output="\n".join(rbcd[:20]),
            )
