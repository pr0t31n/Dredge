from analyzers.base import BaseAnalyzer

_UNNECESSARY_SERVER_ROLES = {
    "dhcp server", "dns server", "active directory domain services",
    "hyper-v", "web server (iis)", "file and storage services",
    "network policy and access services", "print and document services",
    "remote desktop services", "windows server update services",
    "fax server", "remote access",
}


class ServerSoftwareAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_sql_mixed_auth()
        self._check_iis_default_site()
        self._check_unnecessary_roles()
        self._check_web_server_on_workstation()
        return self.findings

    def _check_sql_mixed_auth(self):
        server_sw = self._get_section("server_software", {})
        sql = server_sw.get("sql_server", {})
        if not isinstance(sql, dict):
            return
        installed = sql.get("installed", False)
        if not installed:
            return

        auth_mode = sql.get("authentication_mode", "").lower()
        if auth_mode in ("mixed", "sql and windows", "mixed mode"):
            version = sql.get("version", "Unknown")
            instance = sql.get("instance", "MSSQLSERVER")
            self._add_finding(
                "DR-SRV-001",
                "Authentication: SQL Server Mixed Authentication",
                "HIGH",
                f"SQL Server instance '{instance}' (version {version}) is configured "
                f"with mixed authentication mode, allowing both Windows and SQL "
                f"authentication. SQL authentication transmits credentials that may "
                f"be weaker and harder to audit than Windows/Kerberos authentication.",
                "Mixed mode enables SQL logins (like 'sa') which are frequently "
                "targeted by brute-force attacks. SQL passwords are not subject to "
                "Active Directory password policies, may be stored in application "
                "config files, and bypass centralized authentication controls.",
                "Switch to Windows Authentication mode unless SQL authentication is "
                "strictly required by an application. If mixed mode must remain, "
                "disable the 'sa' account, enforce strong passwords on all SQL "
                "logins, and enable SQL Server Audit for login events.",
                output=f"Instance: {instance}\nVersion: {version}\n"
                       f"Auth mode: {auth_mode}",
                service="mssql",
                remediation_effort="Moderate",
                nist_800_53=["IA-2", "IA-5"],
                pci_dss_4=["8.3.1"],
            )

    def _check_iis_default_site(self):
        server_sw = self._get_section("server_software", {})
        iis = server_sw.get("iis", {})
        if not isinstance(iis, dict):
            return
        installed = iis.get("installed", False)
        if not installed:
            return

        sites = iis.get("sites", [])
        if not isinstance(sites, list):
            return

        default_found = False
        for site in sites:
            if not isinstance(site, dict):
                continue
            name = site.get("name", "").lower()
            if name in ("default web site", "default website"):
                state = site.get("state", "").lower()
                if state in ("started", "running", ""):
                    default_found = True
                    break

        if default_found:
            iis_version = iis.get("version", "Unknown")
            self._add_finding(
                "DR-SRV-002",
                "Service Hardening: IIS Default Site",
                "MEDIUM",
                f"IIS (version {iis_version}) is running with the default web site "
                f"active. The default site exposes server information, may serve "
                f"default pages, and typically lacks application-specific hardening.",
                "The default IIS site reveals the web server platform, may expose "
                "debug pages or sample applications, and often lacks proper access "
                "controls. Attackers use default sites to fingerprint the server "
                "and find known vulnerabilities.",
                "Remove or stop the 'Default Web Site' if it is not needed. For "
                "production sites, create named sites with specific bindings and "
                "remove all default content, sample applications, and documentation.",
                output=f"IIS version: {iis_version}\nDefault Web Site: Running",
                service="iis",
                remediation_effort="Easy",
                nist_800_53=["CM-7"],
                cwe=["CWE-1188"],
            )

    def _check_unnecessary_roles(self):
        if self._is_server():
            return

        server_sw = self._get_section("server_software", {})
        roles = server_sw.get("installed_roles", [])
        if not isinstance(roles, list):
            return

        found_roles = []
        for role in roles:
            if isinstance(role, str):
                role_name = role
            elif isinstance(role, dict):
                role_name = role.get("name", "")
            else:
                continue
            if role_name.lower() in _UNNECESSARY_SERVER_ROLES:
                found_roles.append(role_name)

        if found_roles:
            role_list = ", ".join(found_roles[:10])
            self._add_finding(
                "DR-SRV-003",
                "Service Hardening: Unnecessary Server Roles",
                "MEDIUM",
                f"The following server roles are installed on this workstation: "
                f"{role_list}. Server roles on workstations expand the attack "
                f"surface with services not intended for endpoint use.",
                "Each server role introduces additional listening services, open "
                "ports, and potential vulnerabilities. On a workstation, these roles "
                "are rarely monitored or patched with the same rigor as production "
                "servers.",
                "Remove unnecessary server roles via Server Manager or DISM. "
                "Workstations should not run server infrastructure services.",
                output=f"Server roles on workstation:\n{role_list}",
                remediation_effort="Moderate",
                nist_800_53=["CM-7"],
            )

    def _check_web_server_on_workstation(self):
        if self._is_server():
            return

        server_sw = self._get_section("server_software", {})
        web_servers = []

        iis = server_sw.get("iis", {})
        if isinstance(iis, dict) and iis.get("installed", False):
            web_servers.append("IIS")

        apache = server_sw.get("apache", {})
        if isinstance(apache, dict) and apache.get("installed", False):
            web_servers.append("Apache")

        nginx = server_sw.get("nginx", {})
        if isinstance(nginx, dict) and nginx.get("installed", False):
            web_servers.append("Nginx")

        installed_sw = self._get_section("installed_software", [])
        if isinstance(installed_sw, list):
            for sw in installed_sw:
                if not isinstance(sw, dict):
                    continue
                name = sw.get("name", "").lower()
                for ws_name in ("xampp", "wamp", "mamp", "laragon"):
                    if ws_name in name and ws_name.upper() not in web_servers:
                        web_servers.append(name)

        if web_servers:
            ws_list = ", ".join(web_servers[:5])
            self._add_finding(
                "DR-SRV-004",
                "Service Hardening: Web Server on Workstation",
                "MEDIUM",
                f"A web server is running on this workstation: {ws_list}. "
                f"Web servers on endpoints are often development installations "
                f"with default configurations and no hardening.",
                "Web servers on workstations are typically unmonitored, lack WAF "
                "protection, may expose sensitive development data, and are "
                "frequently misconfigured with directory listing, debug modes, "
                "or default credentials enabled.",
                "Remove web server software from workstations. Use dedicated "
                "servers or containerized development environments for web "
                "development. If a local dev server is required, ensure it binds "
                "only to localhost (127.0.0.1).",
                output=f"Web servers on workstation: {ws_list}",
                remediation_effort="Easy",
                nist_800_53=["CM-7"],
            )
