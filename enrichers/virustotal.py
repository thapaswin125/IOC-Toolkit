"""
VirusTotal v3 API enricher.
Supports: IP addresses, domains, file hashes (MD5/SHA1/SHA256), URLs.
Free tier: 4 requests/min, 500/day.
"""

import requests
from typing import Optional


class VirusTotalEnricher:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key})

    def _get(self, endpoint: str) -> Optional[dict]:
        try:
            resp = self.session.get(f"{self.BASE_URL}/{endpoint}", timeout=15)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {"error": "not_found"}
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def enrich_ip(self, ip: str) -> dict:
        data = self._get(f"ip_addresses/{ip}")
        return self._parse_result(data, ioc_type="ip")

    def enrich_domain(self, domain: str) -> dict:
        data = self._get(f"domains/{domain}")
        return self._parse_result(data, ioc_type="domain")

    def enrich_hash(self, file_hash: str) -> dict:
        data = self._get(f"files/{file_hash}")
        return self._parse_result(data, ioc_type="hash")

    def enrich_url(self, url: str) -> dict:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        data = self._get(f"urls/{url_id}")
        return self._parse_result(data, ioc_type="url")

    def _parse_result(self, data: Optional[dict], ioc_type: str) -> dict:
        if not data or "error" in data:
            return {
                "source": "VirusTotal",
                "error": data.get("error", "unknown") if data else "no_response",
            }

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        result = {
            "source": "VirusTotal",
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "total_engines": total,
            "detection_ratio": f"{malicious + suspicious}/{total}" if total else "N/A",
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags", []),
        }

        if ioc_type == "ip":
            result["country"] = attrs.get("country")
            result["asn"] = attrs.get("asn")
            result["as_owner"] = attrs.get("as_owner")
            result["network"] = attrs.get("network")

        elif ioc_type == "domain":
            result["registrar"] = attrs.get("registrar")
            result["creation_date"] = attrs.get("creation_date")
            result["categories"] = attrs.get("categories", {})

        elif ioc_type == "hash":
            result["file_name"] = attrs.get("meaningful_name")
            result["file_type"] = attrs.get("type_description")
            result["file_size"] = attrs.get("size")
            result["sha256"] = attrs.get("sha256")

        return result
