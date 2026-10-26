"""
AbuseIPDB v2 API enricher.
Supports: IP addresses only.
Free tier: 1,000 checks/day.
"""

import requests
from typing import Optional


class AbuseIPDBEnricher:
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Key": self.api_key,
            "Accept": "application/json",
        })

    def enrich_ip(self, ip: str, max_age_days: int = 90) -> dict:
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/check",
                params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except requests.exceptions.HTTPError as e:
            return {"source": "AbuseIPDB", "error": str(e)}
        except Exception as e:
            return {"source": "AbuseIPDB", "error": str(e)}

        return {
            "source": "AbuseIPDB",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "distinct_users_reporting": data.get("numDistinctUsers"),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "is_public": data.get("isPublic"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
