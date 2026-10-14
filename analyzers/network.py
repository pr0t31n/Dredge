from analyzers.base import BaseAnalyzer

_HIGH_RISK_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC", 136: "Profile Naming",
    137: "NetBIOS Name", 138: "NetBIOS Datagram", 139: "NetBIOS Session",
    445: "SMB", 1433: "MSSQL", 1434: "MSSQL Browser",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis", 27017: "MongoDB", 11211: "Memcached",
}

_PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
               "9.9.9.9", "208.67.222.222", "208.67.220.220",
               "77.88.8.8", "77.88.8.1", "94.140.14.14", "94.140.15.15"}

_LOOPBACK = {"0.0.0.0", "::", "127.0.0.1", "::1", "*"}


class NetworkAnalyzer(BaseAnalyzer):
    def analyze(self):
        self._check_suspicious_connections()
        self._check_high_risk_ports()
        self._check_proxy()
        self._check_dns_external()
        return self.findings

    # ------------------------------------------------------------------ #
    # DR-NET-001  Suspicious outbound connections
    # ------------------------------------------------------------------ #
    def _check_suspicious_connections(self):
        if not self.ti:
            return
        conns = self._get_section("active_connections", [])
        if not isinstance(conns, list):
            return
        suspicious = []
        for conn in conns:
            if not isinstance(conn, dict):
                continue
            remote_ip = conn.get("remote_address", "")
            if not remote_ip or remote_ip in _LOOPBACK:
                continue
            if self.ti.is_known_bad_ip(remote_ip):
                info = self.ti.get_bad_ip_info(remote_ip)
                proc = conn.get("process", conn.get("owning_process", "unknown"))
                remote_port = conn.get("remote_port", "?")
                local_port = conn.get("local_port", "?")
                threat_type = info.get("type", "unknown") if info else "unknown"
                suspicious.append(
                    f"{proc} -> {remote_ip}:{remote_port} "
                    f"(local :{local_port}, threat: {threat_type})")
        if suspicious:
            output = "\n".join(suspicious[:20])
            self._add_finding(
                "DR-NET-001",
                "Network: Suspicious Outbound Connection",
                "HIGH",
                f"{len(suspicious)} active connection(s) to known malicious or "
                f"suspicious IP addresses were detected. These addresses appear in "
                f"threat intelligence feeds as indicators of compromise.",
                "Active connections to known-bad infrastructure strongly suggest "
                "malware beaconing, command-and-control communication, or data "
                "exfiltration. Each connection represents a potential active "
                "compromise that requires immediate investigation.",
                "Immediately investigate each suspicious connection. Identify the "
                "responsible process, capture forensic artifacts (memory dump, "
                "process tree, loaded DLLs), isolate the system if active C2 is "
                "confirmed, and block the destination IPs at the perimeter firewall.",
                output=output,
                remediation_effort="Significant",
                cwe=["CWE-506"],
                mitre_attack=[
                    {"technique": "T1071", "tactic": "Command and Control",
                     "name": "Application Layer Protocol"},
                    {"technique": "T1041", "tactic": "Exfiltration",
                     "name": "Exfiltration Over C2 Channel"},
                ],
                nist_800_53=["SI-4", "IR-5"],
            )

    # ------------------------------------------------------------------ #
    # DR-NET-002  High-risk ports open
    # ------------------------------------------------------------------ #
    def _check_high_risk_ports(self):
        ports = self._get_section("open_ports", [])
        if not isinstance(ports, list):
            return
        found = []
        for entry in ports:
            if not isinstance(entry, dict):
                continue
            port = entry.get("port", 0)
            try:
                port = int(port)
            except (ValueError, TypeError):
                continue
            state = str(entry.get("state", "")).lower()
            if state not in ("listen", "listening", ""):
                continue
            if port in _HIGH_RISK_PORTS:
                svc = _HIGH_RISK_PORTS[port]
                proc = entry.get("process", entry.get("owning_process", ""))
                label = f"{port}/{svc}"
                if proc:
                    label += f" ({proc})"
                found.append(label)
        if found:
            port_list = ", ".join(found[:15])
            self._add_finding(
                "DR-NET-002",
                "Network: High-Risk Port Exposed",
                "MEDIUM",
                f"The following high-risk ports are open and listening: {port_list}. "
                f"These ports correspond to services commonly targeted during "
                f"penetration tests and real-world attacks.",
                "High-risk ports expose services that are frequently targeted for "
                "initial access, lateral movement, credential theft, or data "
                "exfiltration. Open database ports (MSSQL, MySQL, PostgreSQL, "
                "MongoDB) risk direct data access. Telnet, FTP, and VNC transmit "
                "credentials in cleartext. SMB and RDP are primary lateral "
                "movement vectors.",
                "Close unnecessary high-risk ports. For required services, restrict "
                "access via host-based firewall rules to authorized source IPs only, "
                "ensure patching is current, enforce strong authentication, and "
                "enable logging/monitoring.",
                output=f"High-risk ports open ({len(found)}):\n" + "\n".join(found),
                remediation_effort="Moderate",
                nist_800_53=["SC-7", "CM-7"],
                mitre_attack=[
                    {"technique": "T1021", "tactic": "Lateral Movement",
                     "name": "Remote Services"},
                ],
            )

    # ------------------------------------------------------------------ #
    # DR-NET-003  System proxy configured
    # ------------------------------------------------------------------ #
    def _check_proxy(self):
        net_config = self._get_section("network_config", {})
        proxy = net_config.get("proxy", {})
        if not isinstance(proxy, dict):
            return
        proxy_enabled = proxy.get("enabled", False)
        proxy_server = proxy.get("server", proxy.get("proxy_server", ""))
        if not proxy_enabled and not proxy_server:
            return
        if proxy_enabled or proxy_server:
            auto_config = proxy.get("auto_config_url", proxy.get("pac_url", ""))
            override = proxy.get("override", proxy.get("bypass_list", ""))
            parts = [f"Proxy server: {proxy_server}"]
            if auto_config:
                parts.append(f"PAC URL: {auto_config}")
            if override:
                parts.append(f"Bypass list: {override}")
            output = "\n".join(parts)
            self._add_finding(
                "DR-NET-003",
                "Network: Proxy Configured",
                "MEDIUM",
                f"A system-wide proxy is configured: {proxy_server or auto_config}. "
                f"All HTTP/HTTPS traffic may be routed through this proxy server, "
                f"which can intercept, inspect, or modify traffic in transit.",
                "A configured proxy can intercept all web traffic including "
                "authentication tokens, session cookies, API keys, and sensitive "
                "data. If the proxy is malicious or compromised, it enables "
                "man-in-the-middle attacks, credential theft, and traffic "
                "manipulation. Even a legitimate corporate proxy reduces the "
                "confidentiality of encrypted traffic if TLS inspection is enabled.",
                "Verify the proxy configuration is authorized and expected. Confirm "
                "the proxy server belongs to the organization's infrastructure. If "
                "unexpected, investigate for potential malware-installed proxies. "
                "Review proxy PAC files for suspicious redirect rules.",
                output=output,
                remediation_effort="Easy",
                cwe=["CWE-300"],
                mitre_attack=[
                    {"technique": "T1090", "tactic": "Command and Control",
                     "name": "Proxy"},
                ],
                nist_800_53=["SC-8"],
            )

    # ------------------------------------------------------------------ #
    # DR-NET-004  DNS pointing to external servers when domain-joined
    # ------------------------------------------------------------------ #
    def _check_dns_external(self):
        net_config = self._get_section("network_config", {})
        dns_servers = net_config.get("dns_servers", [])
        if not isinstance(dns_servers, list) or not dns_servers:
            return
        domain = net_config.get("domain", "")
        if not domain:
            sys_info = self._get_section("system_info", {})
            domain = sys_info.get("domain", "")
        if not domain or domain.lower() in ("workgroup", ""):
            return
        external = [d for d in dns_servers if isinstance(d, str) and d in _PUBLIC_DNS]
        if not external:
            return
        all_external = all(
            isinstance(d, str) and d in _PUBLIC_DNS for d in dns_servers)
        risk = "HIGH" if all_external else "MEDIUM"
        desc_qualifier = "All" if all_external else "Some"
        self._add_finding(
            "DR-NET-004",
            "Network: External DNS on Domain Host",
            risk,
            f"{desc_qualifier} DNS servers on this domain-joined system ({domain}) "
            f"are public external resolvers: {', '.join(external)}. Domain-joined "
            f"systems should use internal Active Directory DNS servers for proper "
            f"service location (SRV records) and Group Policy resolution.",
            "Using external DNS on a domain-joined machine bypasses the internal "
            "DNS infrastructure, breaking Active Directory service discovery and "
            "potentially routing DNS queries (including internal hostnames) to "
            "external resolvers. This may indicate DNS hijacking, misconfiguration "
            "after a network change, or malware altering DNS settings to redirect "
            "traffic through attacker-controlled infrastructure.",
            "Configure DNS to use only the domain's Active Directory DNS servers. "
            "Apply DNS settings via DHCP or Group Policy to prevent local overrides. "
            "Investigate why external DNS was configured — check for unauthorized "
            "changes or malware persistence.",
            output=f"Domain: {domain}\nDNS servers: {', '.join(str(d) for d in dns_servers)}\n"
                   f"External: {', '.join(external)}",
            remediation_effort="Easy",
            nist_800_53=["SC-20", "SC-21"],
            mitre_attack=[
                {"technique": "T1584.002", "tactic": "Resource Development",
                 "name": "DNS Server"},
            ],
        )
