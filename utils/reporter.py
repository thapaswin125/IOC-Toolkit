"""
Risk scoring and report formatting.
Produces colored terminal output and structured JSON reports.
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any


class RiskScorer:
    """
    Aggregates enrichment results from multiple sources and produces a
    composite risk score (0-100) and verdict.
    """

    VERDICT_THRESHOLDS = {
        "MALICIOUS": 70,
        "SUSPICIOUS": 35,
        "CLEAN": 0,
    }

    def score(self, ioc_value: str, ioc_type: str, enrichments: List[dict]) -> dict:
        score = 0
        signals = []

        for result in enrichments:
            source = result.get("source", "unknown")
            if "error" in result:
                continue

            if source == "VirusTotal":
                malicious = result.get("malicious_engines", 0)
                suspicious = result.get("suspicious_engines", 0)
                total = result.get("total_engines", 1) or 1
                if malicious > 0:
                    vt_score = min(60, int((malicious / total) * 100))
                    score += vt_score
                    signals.append(f"VT: {malicious} malicious engines ({result.get('detection_ratio')})")
                if suspicious > 0:
                    score += min(15, suspicious * 3)
                    signals.append(f"VT: {suspicious} suspicious engines")

            elif source == "AbuseIPDB":
                abuse_score = result.get("abuse_confidence_score", 0) or 0
                if abuse_score > 0:
                    score += int(abuse_score * 0.4)
                    signals.append(f"AbuseIPDB confidence: {abuse_score}%")
                if result.get("total_reports", 0):
                    signals.append(f"AbuseIPDB: {result['total_reports']} reports from {result.get('distinct_users_reporting', 0)} users")
                if result.get("is_tor"):
                    score += 10
                    signals.append("AbuseIPDB: Tor exit node")

            elif source == "OTX":
                pulse_count = result.get("pulse_count", 0) or 0
                if pulse_count > 0:
                    score += min(30, pulse_count * 3)
                    signals.append(f"OTX: found in {pulse_count} threat pulse(s)")
                adversaries = result.get("adversary", [])
                if adversaries:
                    score += 10
                    signals.append(f"OTX adversary attribution: {', '.join(adversaries)}")
                malware = result.get("malware_families", [])
                if malware:
                    signals.append(f"OTX malware families: {', '.join(malware[:3])}")

        score = min(100, score)

        if score >= self.VERDICT_THRESHOLDS["MALICIOUS"]:
            verdict = "MALICIOUS"
        elif score >= self.VERDICT_THRESHOLDS["SUSPICIOUS"]:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "ioc": ioc_value,
            "type": ioc_type,
            "risk_score": score,
            "verdict": verdict,
            "signals": signals,
            "enrichments": enrichments,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }


# ANSI color codes
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_VERDICT_COLORS = {
    "MALICIOUS": _RED,
    "SUSPICIOUS": _YELLOW,
    "CLEAN": _GREEN,
}


def format_terminal_report(results: List[dict]) -> str:
    lines = []
    lines.append(f"\n{_BOLD}{'=' * 60}{_RESET}")
    lines.append(f"{_BOLD}  IOC Enrichment Report  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}{_RESET}")
    lines.append(f"{_BOLD}{'=' * 60}{_RESET}\n")

    for r in results:
        verdict = r.get("verdict", "UNKNOWN")
        color = _VERDICT_COLORS.get(verdict, _RESET)
        score = r.get("risk_score", 0)

        lines.append(f"{_BOLD}{_CYAN}IOC:{_RESET}     {r['ioc']}")
        lines.append(f"{_BOLD}Type:{_RESET}    {r['type']}")
        lines.append(f"{_BOLD}Score:{_RESET}   {color}{score}/100{_RESET}")
        lines.append(f"{_BOLD}Verdict:{_RESET} {color}{_BOLD}{verdict}{_RESET}")

        if r.get("signals"):
            lines.append(f"{_BOLD}Signals:{_RESET}")
            for signal in r["signals"]:
                lines.append(f"  • {signal}")

        lines.append("")  # blank line between IOCs

    # Summary table
    total = len(results)
    malicious = sum(1 for r in results if r.get("verdict") == "MALICIOUS")
    suspicious = sum(1 for r in results if r.get("verdict") == "SUSPICIOUS")
    clean = sum(1 for r in results if r.get("verdict") == "CLEAN")

    lines.append(f"{_BOLD}{'─' * 60}{_RESET}")
    lines.append(f"{_BOLD}Summary:{_RESET} {total} IOCs — "
                 f"{_RED}{malicious} MALICIOUS{_RESET} | "
                 f"{_YELLOW}{suspicious} SUSPICIOUS{_RESET} | "
                 f"{_GREEN}{clean} CLEAN{_RESET}")
    lines.append(f"{_BOLD}{'─' * 60}{_RESET}\n")

    return "\n".join(lines)


def write_json_report(results: List[dict], output_path: str) -> None:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_iocs": len(results),
        "summary": {
            "malicious": sum(1 for r in results if r.get("verdict") == "MALICIOUS"),
            "suspicious": sum(1 for r in results if r.get("verdict") == "SUSPICIOUS"),
            "clean": sum(1 for r in results if r.get("verdict") == "CLEAN"),
        },
        "results": results,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
