"""
AlienVault OTX (Open Threat Exchange) API enricher.
Supports: IP addresses, domains, file hashes, URLs.
Free tier: generous limits with a free account.
"""

import requests
from typing import Optional


class OTXEnricher:
    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"X-OTX-API-KEY": self.api_key})

    def _get(self, path: str) -> Optional[dict]:
        try:
            resp = self.session.get(f"{self.BASE_URL}/{path}", timeout=15)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {"error": "not_found"}
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def enrich_ip(self, ip: str) -> dict:
        general = self._get(f"indicators/IPv4/{ip}/general")
        geo = self._get(f"indicators/IPv4/{ip}/geo")
        return self._parse_ip(general, geo)

    def enrich_domain(self, domain: str) -> dict:
        general = self._get(f"indicators/domain/{domain}/general")
        return self._parse_domain(general)

    def enrich_hash(self, file_hash: str) -> dict:
        general = self._get(f"indicators/file/{file_hash}/general")
        return self._parse_hash(general)

    def enrich_url(self, url: str) -> dict:
        general = self._get(f"indicators/url/{url}/general")
        return self._parse_url(general)

    def _parse_ip(self, general: Optional[dict], geo: Optional[dict]) -> dict:
        if not general or "error" in general:
            return {"source": "OTX", "error": general.get("error", "unknown") if general else "no_response"}

        pulse_info = general.get("pulse_info", {})
        result = {
            "source": "OTX",
            "pulse_count": pulse_info.get("count", 0),
            "pulse_names": [p.get("name") for p in pulse_info.get("pulses", [])[:5]],
            "malware_families": list({
                tag for p in pulse_info.get("pulses", [])
                for tag in p.get("malware_families", [])
            })[:10],
            "adversary": list({
                p.get("adversary") for p in pulse_info.get("pulses", []) if p.get("adversary")
            })[:5],
        }
        if geo and "error" not in geo:
            result["country_name"] = geo.get("country_name")
            result["city"] = geo.get("city")
            result["asn"] = geo.get("asn")
        return result

    def _parse_domain(self, general: Optional[dict]) -> dict:
        if not general or "error" in general:
            return {"source": "OTX", "error": general.get("error", "unknown") if general else "no_response"}

        pulse_info = general.get("pulse_info", {})
        return {
            "source": "OTX",
            "pulse_count": pulse_info.get("count", 0),
            "pulse_names": [p.get("name") for p in pulse_info.get("pulses", [])[:5]],
            "malware_families": list({
                tag for p in pulse_info.get("pulses", [])
                for tag in p.get("malware_families", [])
            })[:10],
            "alexa_rank": general.get("alexa"),
        }

    def _parse_hash(self, general: Optional[dict]) -> dict:
        if not general or "error" in general:
            return {"source": "OTX", "error": general.get("error", "unknown") if general else "no_response"}

        pulse_info = general.get("pulse_info", {})
        return {
            "source": "OTX",
            "pulse_count": pulse_info.get("count", 0),
            "pulse_names": [p.get("name") for p in pulse_info.get("pulses", [])[:5]],
            "malware_families": list({
                tag for p in pulse_info.get("pulses", [])
                for tag in p.get("malware_families", [])
            })[:10],
        }

    def _parse_url(self, general: Optional[dict]) -> dict:
        if not general or "error" in general:
            return {"source": "OTX", "error": general.get("error", "unknown") if general else "no_response"}

        pulse_info = general.get("pulse_info", {})
        return {
            "source": "OTX",
            "pulse_count": pulse_info.get("count", 0),
            "pulse_names": [p.get("name") for p in pulse_info.get("pulses", [])[:5]],
        }
