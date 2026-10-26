"""
IOC type classification and file parsing.
Detects: IPv4, IPv6, domain, MD5, SHA1, SHA256, URL.
"""

import re
from typing import Tuple, List

# Regex patterns
RE_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
RE_IPV6 = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    r"|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$"
    r"|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$"
)
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_URL = re.compile(r"^https?://", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def classify_ioc(value: str) -> Tuple[str, str]:
    """
    Returns (ioc_type, normalized_value).
    ioc_type is one of: ip, domain, md5, sha1, sha256, url, unknown.
    """
    value = value.strip()

    if RE_IPV4.match(value) or RE_IPV6.match(value):
        return "ip", value
    if RE_SHA256.match(value):
        return "sha256", value.lower()
    if RE_SHA1.match(value):
        return "sha1", value.lower()
    if RE_MD5.match(value):
        return "md5", value.lower()
    if RE_URL.match(value):
        return "url", value
    if RE_DOMAIN.match(value):
        return "domain", value.lower()

    return "unknown", value


def parse_ioc_file(filepath: str) -> List[Tuple[str, str]]:
    """
    Read a file of IOCs (one per line, # comments ignored).
    Returns list of (ioc_type, value) tuples, skipping unknowns.
    """
    results = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ioc_type, value = classify_ioc(line)
            if ioc_type != "unknown":
                results.append((ioc_type, value))
            else:
                print(f"[WARN] Could not classify IOC, skipping: {value}")
    return results
