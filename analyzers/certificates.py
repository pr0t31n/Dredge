from datetime import datetime, timezone
from analyzers.base import BaseAnalyzer

_WEAK_SIG_ALGORITHMS = {
    "sha1withrsaencryption", "sha1rsa", "sha1",
    "md5withrsaencryption", "md5rsa", "md5",
    "md2withrsaencryption", "md2rsa", "md2",
    "sha1withdsa", "dsawithsha1",
    "sha1withecdsa",
}


class CertificateAnalyzer(BaseAnalyzer):
    def analyze(self):
        certs = self._get_section("certificates", [])
        if isinstance(certs, dict):
            certs = certs.get("certificates", certs.get("items", []))
        if not isinstance(certs, list):
            return self.findings
        now = datetime.now(timezone.utc)
        for cert in certs:
            if not isinstance(cert, dict):
                continue
            self._check_expired(cert, now)
            self._check_expiring_soon(cert, now)
            self._check_self_signed(cert)
            self._check_weak_signature(cert)
            self._check_weak_key(cert)
        return self.findings

    def _parse_date(self, date_str):
        if not date_str or not isinstance(date_str, str):
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d",
                    "%m/%d/%Y %H:%M:%S",
                    "%m/%d/%Y",
                    "%b %d %H:%M:%S %Y %Z",
                    "%b %d %H:%M:%S %Y"):
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(
                date_str.replace("Z", "+00:00").strip())
        except (ValueError, TypeError):
            return None

    def _cert_label(self, cert):
        subject = cert.get("subject", cert.get("subject_cn", ""))
        if isinstance(subject, dict):
            subject = subject.get("CN", subject.get("cn", str(subject)))
        thumbprint = cert.get("thumbprint", cert.get("fingerprint", ""))
        store = cert.get("store", cert.get("store_name", ""))
        parts = []
        if subject:
            parts.append(f"Subject: {subject}")
        if thumbprint:
            parts.append(f"Thumbprint: {thumbprint[:16]}...")
        if store:
            parts.append(f"Store: {store}")
        return " | ".join(parts) if parts else "Unknown certificate"

    # ------------------------------------------------------------------ #
    # DR-CERT-001  Expired certificate
    # ------------------------------------------------------------------ #
    def _check_expired(self, cert, now):
        not_after = cert.get("not_after", cert.get("expiry",
                     cert.get("valid_to", cert.get("expiration_date", ""))))
        expiry = self._parse_date(not_after)
        if expiry is None:
            return
        if expiry >= now:
            return
        days_expired = (now - expiry).days
        label = self._cert_label(cert)
        subject = cert.get("subject", cert.get("subject_cn", ""))
        if isinstance(subject, dict):
            subject = subject.get("CN", subject.get("cn", str(subject)))
        self._add_finding(
            "DR-CERT-001",
            "Expired Certificate",
            "MEDIUM",
            f"Certificate '{subject}' expired {days_expired} day(s) ago on "
            f"{not_after}. Expired certificates cause service disruptions and "
            f"security warnings.",
            "Expired certificates break TLS/SSL connections, causing service "
            "outages and security warnings that train users to click through "
            "certificate errors. Applications relying on certificate-based "
            "authentication will fail. Expired code-signing certificates may "
            "allow unsigned or tampered code to run if validation is bypassed.",
            "Renew the expired certificate immediately. Implement certificate "
            "lifecycle management with automated renewal alerts (at 90, 60, "
            "and 30 days before expiry). Use ACME/Let's Encrypt for automated "
            "renewal where applicable. Remove expired certificates from trust "
            "stores if no longer needed.",
            output=f"{label}\nExpired: {not_after} ({days_expired} days ago)",
            remediation_effort="Easy",
            cwe=["CWE-324"],
            nist_800_53=["SC-17"],
        )

    # ------------------------------------------------------------------ #
    # DR-CERT-002  Certificate expiring within 90 days
    # ------------------------------------------------------------------ #
    def _check_expiring_soon(self, cert, now):
        not_after = cert.get("not_after", cert.get("expiry",
                     cert.get("valid_to", cert.get("expiration_date", ""))))
        expiry = self._parse_date(not_after)
        if expiry is None:
            return
        if expiry < now:
            return
        days_remaining = (expiry - now).days
        if days_remaining > 90:
            return
        label = self._cert_label(cert)
        subject = cert.get("subject", cert.get("subject_cn", ""))
        if isinstance(subject, dict):
            subject = subject.get("CN", subject.get("cn", str(subject)))
        risk = "MEDIUM" if days_remaining <= 30 else "LOW"
        self._add_finding(
            "DR-CERT-002",
            "Certificate Expiring Soon",
            risk,
            f"Certificate '{subject}' expires in {days_remaining} day(s) on "
            f"{not_after}. Certificates expiring within 90 days require "
            f"attention to prevent service disruptions.",
            "Certificates that expire without renewal cause unexpected service "
            "outages, broken authentication, and security warnings. "
            "Last-minute renewals often result in emergency changes with "
            "higher risk of misconfiguration.",
            "Renew the certificate before it expires. Implement automated "
            "certificate monitoring and renewal. Add the certificate to "
            "your organization's certificate management system. Set "
            "calendar reminders at 90, 60, and 30 days before expiry.",
            output=f"{label}\nExpires: {not_after} ({days_remaining} days remaining)",
            remediation_effort="Easy",
            nist_800_53=["SC-17"],
        )

    # ------------------------------------------------------------------ #
    # DR-CERT-003  Self-signed certificate in trust store
    # ------------------------------------------------------------------ #
    def _check_self_signed(self, cert):
        issuer = cert.get("issuer", cert.get("issuer_cn", ""))
        subject = cert.get("subject", cert.get("subject_cn", ""))
        if isinstance(issuer, dict):
            issuer_cn = issuer.get("CN", issuer.get("cn", str(issuer)))
        else:
            issuer_cn = str(issuer)
        if isinstance(subject, dict):
            subject_cn = subject.get("CN", subject.get("cn", str(subject)))
        else:
            subject_cn = str(subject)
        self_signed_flag = cert.get("self_signed",
                                    cert.get("is_self_signed", None))
        if self_signed_flag is True:
            is_self_signed = True
        elif self_signed_flag is False:
            return
        elif issuer_cn and subject_cn:
            is_self_signed = issuer_cn.strip().lower() == subject_cn.strip().lower()
        else:
            return
        if not is_self_signed:
            return
        store = str(cert.get("store", cert.get("store_name", ""))).lower()
        in_trust_store = any(s in store for s in
                             ("root", "trust", "ca", "authroot", "my"))
        if not in_trust_store and store:
            return
        label = self._cert_label(cert)
        self._add_finding(
            "DR-CERT-003",
            "Self-Signed Certificate in Trust Store",
            "MEDIUM",
            f"A self-signed certificate '{subject_cn}' is installed in the "
            f"certificate trust store. Self-signed certificates bypass the "
            f"PKI chain-of-trust model and cannot be verified against a "
            f"trusted Certificate Authority.",
            "Self-signed certificates in the trust store enable man-in-the-"
            "middle attacks. An attacker who installs a self-signed CA "
            "certificate can intercept and decrypt TLS traffic, forge "
            "code-signing signatures, or impersonate any server. They may "
            "also indicate a rogue or unauthorized Certificate Authority "
            "has been added to the system.",
            "Review all self-signed certificates in the trust store. Remove "
            "any that are not authorized by the organization's PKI policy. "
            "Replace self-signed certificates with CA-issued certificates "
            "from the organization's internal PKI or a trusted public CA. "
            "Monitor the Root and Intermediate CA stores for unauthorized "
            "additions.",
            output=f"{label}\nIssuer: {issuer_cn}\nSubject: {subject_cn}\n"
                   f"Store: {store}",
            remediation_effort="Easy",
            cwe=["CWE-295"],
            mitre_attack=[
                {"technique": "T1553.004", "tactic": "Defense Evasion",
                 "name": "Install Root Certificate"},
            ],
            nist_800_53=["SC-17", "IA-5"],
        )

    # ------------------------------------------------------------------ #
    # DR-CERT-004  Weak signature algorithm (SHA1 / MD5)
    # ------------------------------------------------------------------ #
    def _check_weak_signature(self, cert):
        sig_alg = cert.get("signature_algorithm",
                           cert.get("sig_algorithm",
                           cert.get("signature_hash_algorithm", "")))
        if not sig_alg or not isinstance(sig_alg, str):
            return
        normalized = sig_alg.strip().lower().replace("-", "").replace("_", "").replace(" ", "")
        if normalized not in _WEAK_SIG_ALGORITHMS:
            return
        label = self._cert_label(cert)
        subject = cert.get("subject", cert.get("subject_cn", ""))
        if isinstance(subject, dict):
            subject = subject.get("CN", subject.get("cn", str(subject)))
        is_md5 = "md5" in normalized or "md2" in normalized
        risk = "HIGH" if is_md5 else "MEDIUM"
        self._add_finding(
            "DR-CERT-004",
            "Weak Certificate Signature Algorithm",
            risk,
            f"Certificate '{subject}' uses the weak signature algorithm "
            f"'{sig_alg}'. {'MD5 and MD2 are' if is_md5 else 'SHA-1 is'} "
            f"cryptographically broken and vulnerable to collision attacks.",
            "Certificates signed with weak hash algorithms can be forged "
            "by generating hash collisions. An attacker can create a "
            "fraudulent certificate that appears legitimate, enabling "
            "man-in-the-middle attacks, code-signing forgery, and "
            "impersonation. Major browsers and operating systems have "
            "deprecated SHA-1 certificates since 2017.",
            f"Replace the certificate with one signed using SHA-256 or "
            f"stronger. Re-issue from the same CA with a modern signature "
            f"algorithm. Update any applications or services that depend on "
            f"the old certificate. If the issuing CA only supports weak "
            f"algorithms, migrate to a modern CA.",
            output=f"{label}\nSignature algorithm: {sig_alg}",
            remediation_effort="Easy",
            cwe=["CWE-328"],
            nist_800_53=["SC-13"],
        )

    # ------------------------------------------------------------------ #
    # DR-CERT-005  Weak key size (< 2048 bit)
    # ------------------------------------------------------------------ #
    def _check_weak_key(self, cert):
        key_size = cert.get("key_size", cert.get("key_length",
                   cert.get("public_key_size", cert.get("bits", 0))))
        try:
            key_size = int(key_size)
        except (ValueError, TypeError):
            return
        if key_size <= 0 or key_size >= 2048:
            return
        key_alg = cert.get("key_algorithm", cert.get("public_key_algorithm", "RSA"))
        label = self._cert_label(cert)
        subject = cert.get("subject", cert.get("subject_cn", ""))
        if isinstance(subject, dict):
            subject = subject.get("CN", subject.get("cn", str(subject)))
        risk = "HIGH" if key_size <= 1024 else "MEDIUM"
        self._add_finding(
            "DR-CERT-005",
            "Weak Certificate Key Size",
            risk,
            f"Certificate '{subject}' uses a {key_size}-bit {key_alg} key. "
            f"Keys shorter than 2048 bits are considered weak and can be "
            f"factored with modern computing resources.",
            f"A {key_size}-bit key can be broken using distributed computing "
            f"or cloud resources. 1024-bit RSA keys have been publicly "
            f"factored, and NIST has deprecated keys shorter than 2048 bits "
            f"since 2013. An attacker who factors the key can forge "
            f"signatures, decrypt traffic, and impersonate the certificate "
            f"holder.",
            "Replace the certificate with one using at least a 2048-bit RSA "
            "key (3072-bit or 4096-bit recommended for long-lived "
            "certificates). For new deployments, consider ECDSA P-256 or "
            "P-384 keys which provide equivalent security at smaller sizes. "
            "Update the certificate on all services and endpoints.",
            output=f"{label}\nKey size: {key_size}-bit {key_alg}\n"
                   f"Minimum recommended: 2048-bit",
            remediation_effort="Easy",
            cwe=["CWE-326"],
            nist_800_53=["SC-12", "SC-13"],
        )
