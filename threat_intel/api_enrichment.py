import json
import urllib.request
import urllib.error


def check_virustotal(sha256, api_key):
    if not api_key or not sha256:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        link = f"https://www.virustotal.com/gui/file/{sha256}"
        return {"malicious": malicious, "total": total, "permalink": link}
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            OSError, KeyError):
        return None


def check_abuseipdb(ip, api_key):
    if not api_key or not ip:
        return None
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={
        "Key": api_key,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        d = data.get("data", {})
        return {
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", ""),
            "usage_type": d.get("usageType", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "total_reports": d.get("totalReports", 0),
        }
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            OSError, KeyError):
        return None


def enrich_findings(findings, vt_api_key="", abuseipdb_key=""):
    if not vt_api_key and not abuseipdb_key:
        return findings

    enriched_ips = {}

    for finding in findings:
        if abuseipdb_key:
            ip = finding.get("ip", "")
            if ip and ip not in enriched_ips:
                result = check_abuseipdb(ip, abuseipdb_key)
                if result:
                    enriched_ips[ip] = result

        if vt_api_key and finding.get("output", ""):
            pass

    for finding in findings:
        ip = finding.get("ip", "")
        if ip in enriched_ips:
            abuse = enriched_ips[ip]
            if abuse.get("abuse_confidence", 0) > 50:
                finding.setdefault("output", "")
                finding["output"] += (
                    f"\n[AbuseIPDB] Confidence: {abuse['abuse_confidence']}%, "
                    f"Reports: {abuse['total_reports']}, ISP: {abuse.get('isp', '')}")

    return findings
