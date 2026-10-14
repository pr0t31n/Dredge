from urllib.parse import urlparse
from analyzers.base import BaseAnalyzer

_BROWSER_SECTIONS = {
    "chrome":  "browser_chrome",
    "edge":    "browser_edge",
    "firefox": "browser_firefox",
}


class BrowserAnalyzer(BaseAnalyzer):
    def analyze(self):
        for browser_name, section_key in _BROWSER_SECTIONS.items():
            section = self._get_section(section_key, {})
            if not isinstance(section, dict) or not section:
                continue
            self._check_extensions(browser_name, section)
            self._check_proxy(browser_name, section)
            self._check_bookmarks(browser_name, section)
        return self.findings

    # ------------------------------------------------------------------ #
    # DR-BRW-001  Unknown / suspicious browser extension
    # ------------------------------------------------------------------ #
    def _check_extensions(self, browser, section):
        extensions = section.get("extensions", [])
        if not isinstance(extensions, list):
            return
        suspicious = []
        unknown = []
        for ext in extensions:
            if not isinstance(ext, dict):
                continue
            ext_id = ext.get("id", ext.get("extension_id", ""))
            ext_name = ext.get("name", "")
            if not ext_id:
                continue
            if self.ti:
                result = self.ti.is_known_extension(browser, ext_id)
                if isinstance(result, dict):
                    if result.get("malicious"):
                        reason = result.get("reason", "listed as malicious")
                        suspicious.append(
                            f"[MALICIOUS] {ext_name} (ID: {ext_id}) — {reason}")
                        continue
                    if result.get("known"):
                        continue
            enabled = ext.get("enabled", True)
            if enabled:
                version = ext.get("version", "?")
                unknown.append(f"{ext_name} (ID: {ext_id}, v{version})")

        if suspicious:
            output = "\n".join(suspicious[:15])
            self._add_finding(
                "DR-BRW-001",
                f"Browser: Malicious Extension Detected ({browser.title()})",
                "HIGH",
                f"{len(suspicious)} browser extension(s) in {browser.title()} "
                f"match known malicious extensions in the threat intelligence "
                f"database. These extensions may be stealing credentials, "
                f"injecting ads, or exfiltrating browsing data.",
                "Malicious browser extensions can intercept all web traffic "
                "including passwords, session tokens, banking credentials, "
                "and form data. They can inject content into pages, redirect "
                "searches, cryptomine, and exfiltrate browsing history. They "
                "persist across browser restarts and are often difficult for "
                "users to identify.",
                f"Remove the malicious extension(s) from {browser.title()} "
                f"immediately. Check other browsers on the system for the same "
                f"extensions. Review browsing history for credential exposure. "
                f"Force password resets for any accounts accessed while the "
                f"extension was installed. Deploy browser extension whitelisting "
                f"via Group Policy.",
                output=output,
                remediation_effort="Easy",
                cwe=["CWE-506"],
                mitre_attack=[
                    {"technique": "T1176", "tactic": "Persistence",
                     "name": "Browser Extensions"},
                ],
                nist_800_53=["SI-3", "CM-7"],
            )

        if unknown:
            output = "\n".join(unknown[:20])
            self._add_finding(
                "DR-BRW-001",
                f"Browser: Unrecognized Extension ({browser.title()})",
                "LOW",
                f"{len(unknown)} browser extension(s) in {browser.title()} are "
                f"not recognized by the threat intelligence database. These may "
                f"be legitimate but should be reviewed.",
                "Unrecognized extensions may be legitimate productivity tools "
                "or may be potentially unwanted programs (PUPs), adware, or "
                "data collectors that have not yet been classified. Without "
                "an extension whitelist, any installed extension has access "
                "to browsing data based on its declared permissions.",
                f"Review each unrecognized extension in {browser.title()}. "
                f"Check extension permissions, publisher reputation, and user "
                f"ratings. Implement a browser extension whitelist policy via "
                f"Group Policy to only allow approved extensions.",
                output=output,
                remediation_effort="Easy",
                nist_800_53=["CM-7"],
            )

    # ------------------------------------------------------------------ #
    # DR-BRW-002  Browser proxy configured
    # ------------------------------------------------------------------ #
    def _check_proxy(self, browser, section):
        proxy = section.get("proxy", section.get("proxy_settings", {}))
        if isinstance(proxy, str) and proxy:
            self._add_finding(
                "DR-BRW-002",
                f"Browser: Proxy Configured ({browser.title()})",
                "MEDIUM",
                f"{browser.title()} is configured to use a proxy: {proxy}. "
                f"This may intercept and inspect all browser traffic.",
                "A browser-level proxy can intercept all HTTP/HTTPS traffic "
                "from the browser, including login credentials, session "
                "tokens, and sensitive data. If the proxy is malicious, "
                "it enables credential theft and traffic manipulation.",
                f"Verify the proxy configuration in {browser.title()} is "
                f"authorized and expected. If proxy is not required, remove "
                f"it. Investigate whether malware or a malicious extension "
                f"configured the proxy.",
                output=f"Browser: {browser.title()}\nProxy: {proxy}",
                remediation_effort="Easy",
                cwe=["CWE-300"],
                mitre_attack=[
                    {"technique": "T1090", "tactic": "Command and Control",
                     "name": "Proxy"},
                ],
            )
            return

        if not isinstance(proxy, dict) or not proxy:
            return
        proxy_enabled = proxy.get("enabled", False)
        proxy_server = proxy.get("server", proxy.get("http", ""))
        pac_url = proxy.get("pac_url", proxy.get("auto_config_url", ""))
        if not proxy_enabled and not proxy_server and not pac_url:
            return
        parts = []
        if proxy_server:
            parts.append(f"Proxy server: {proxy_server}")
        if pac_url:
            parts.append(f"PAC URL: {pac_url}")
        proxy_type = proxy.get("type", proxy.get("mode", ""))
        if proxy_type:
            parts.append(f"Type: {proxy_type}")
        output = f"Browser: {browser.title()}\n" + "\n".join(parts)
        self._add_finding(
            "DR-BRW-002",
            f"Browser: Proxy Configured ({browser.title()})",
            "MEDIUM",
            f"{browser.title()} has a proxy configured at the browser level, "
            f"separate from system proxy settings. This proxy intercepts "
            f"all browser traffic. " + (f"Server: {proxy_server}" if proxy_server
                                        else f"PAC: {pac_url}"),
            "A browser-level proxy can intercept all HTTP/HTTPS traffic "
            "from the browser, including login credentials, session tokens, "
            "and sensitive data. Browser-level proxies may bypass system "
            "proxy settings, making them harder to detect. If the proxy is "
            "malicious, it enables credential theft and traffic manipulation.",
            f"Verify the proxy configuration in {browser.title()} is "
            f"authorized and expected. Compare with system proxy settings. "
            f"If a browser-specific proxy is not required, remove it. "
            f"Investigate whether malware or a malicious extension set it.",
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
    # DR-BRW-003  Suspicious bookmark (known bad domain)
    # ------------------------------------------------------------------ #
    def _check_bookmarks(self, browser, section):
        if not self.ti:
            return
        bookmarks = section.get("bookmarks", [])
        if not isinstance(bookmarks, list):
            return
        suspicious = []
        for bm in bookmarks:
            if isinstance(bm, dict):
                url = bm.get("url", "")
                name = bm.get("name", bm.get("title", ""))
            elif isinstance(bm, str):
                url = bm
                name = ""
            else:
                continue
            if not url:
                continue
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
            except Exception:
                continue
            if not host:
                continue
            if self.ti.is_known_bad_ip(host):
                info = self.ti.get_bad_ip_info(host)
                threat_type = info.get("type", "suspicious") if info else "suspicious"
                label = name if name else url[:80]
                suspicious.append(
                    f"{label}\n  URL: {url}\n  Host: {host} ({threat_type})")

        if not suspicious:
            return
        output = "\n".join(suspicious[:10])
        self._add_finding(
            "DR-BRW-003",
            f"Browser: Suspicious Bookmark ({browser.title()})",
            "MEDIUM",
            f"{len(suspicious)} bookmark(s) in {browser.title()} link to "
            f"domains or IPs associated with known malicious infrastructure "
            f"in the threat intelligence database.",
            "Bookmarks to malicious domains may indicate the user regularly "
            "visits compromised or phishing sites. This could be a watering "
            "hole attack vector, a phishing landing page saved by a targeted "
            "user, or a bookmark planted by malware for persistence or "
            "redirection.",
            f"Investigate each suspicious bookmark. Check if the user "
            f"intentionally saved it or if it was created by malware. "
            f"Review browser history for visits to the bookmarked URLs. "
            f"Remove the bookmarks and block the domains at the DNS/proxy "
            f"level. Scan the system for malware that may have created them.",
            output=output,
            remediation_effort="Easy",
            mitre_attack=[
                {"technique": "T1189", "tactic": "Initial Access",
                 "name": "Drive-by Compromise"},
            ],
            nist_800_53=["SI-3", "SC-7"],
        )
