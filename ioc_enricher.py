#!/usr/bin/env python3
"""
IOC Enrichment Pipeline
=======================
Enrich indicators of compromise (IPs, domains, hashes, URLs) against
VirusTotal, AbuseIPDB, and AlienVault OTX in parallel.

Usage:
    python ioc_enricher.py -i examples/sample_iocs.txt
    python ioc_enricher.py --ioc 8.8.8.8
    python ioc_enricher.py -i iocs.txt --output report.json --no-color
"""

import argparse
import os
import sys
import concurrent.futures
from typing import List, Tuple

from dotenv import load_dotenv

from enrichers import VirusTotalEnricher, AbuseIPDBEnricher, OTXEnricher
from utils import classify_ioc, parse_ioc_file, RiskScorer, format_terminal_report, write_json_report

load_dotenv()


def get_api_keys() -> dict:
    keys = {
        "virustotal": os.getenv("VT_API_KEY"),
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
        "otx": os.getenv("OTX_API_KEY"),
    }
    missing = [k for k, v in keys.items() if not v]
    if missing:
        print(f"[WARN] Missing API keys for: {', '.join(missing)}. Those sources will be skipped.")
        print("       See .env.example for setup instructions.\n")
    return keys


def enrich_single(
    ioc_type: str,
    ioc_value: str,
    vt: VirusTotalEnricher,
    abuseipdb: AbuseIPDBEnricher,
    otx: OTXEnricher,
    keys: dict,
) -> List[dict]:
    """Run all applicable enrichers for a single IOC, returning a list of results."""
    enrichments = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {}

        if keys.get("virustotal"):
            if ioc_type == "ip":
                futures["vt"] = executor.submit(vt.enrich_ip, ioc_value)
            elif ioc_type == "domain":
                futures["vt"] = executor.submit(vt.enrich_domain, ioc_value)
            elif ioc_type in ("md5", "sha1", "sha256"):
                futures["vt"] = executor.submit(vt.enrich_hash, ioc_value)
            elif ioc_type == "url":
                futures["vt"] = executor.submit(vt.enrich_url, ioc_value)

        if keys.get("abuseipdb") and ioc_type == "ip":
            futures["abuseipdb"] = executor.submit(abuseipdb.enrich_ip, ioc_value)

        if keys.get("otx"):
            if ioc_type == "ip":
                futures["otx"] = executor.submit(otx.enrich_ip, ioc_value)
            elif ioc_type == "domain":
                futures["otx"] = executor.submit(otx.enrich_domain, ioc_value)
            elif ioc_type in ("md5", "sha1", "sha256"):
                futures["otx"] = executor.submit(otx.enrich_hash, ioc_value)
            elif ioc_type == "url":
                futures["otx"] = executor.submit(otx.enrich_url, ioc_value)

        for name, future in futures.items():
            try:
                enrichments.append(future.result(timeout=30))
            except Exception as e:
                enrichments.append({"source": name, "error": str(e)})

    return enrichments


def main():
    parser = argparse.ArgumentParser(
        description="IOC Enrichment Pipeline — enrich IPs, domains, hashes, and URLs against threat intel sources.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ioc_enricher.py --ioc 185.220.101.45
  python ioc_enricher.py --ioc evilcorp.com
  python ioc_enricher.py -i examples/sample_iocs.txt
  python ioc_enricher.py -i iocs.txt --output report.json
  python ioc_enricher.py -i iocs.txt --sources vt otx
        """,
    )
    parser.add_argument("--ioc", "-I", help="Single IOC to enrich (IP, domain, hash, or URL)")
    parser.add_argument("--input", "-i", help="File containing IOCs, one per line")
    parser.add_argument("--output", "-o", help="Write JSON report to this file")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=["vt", "abuseipdb", "otx"],
        default=["vt", "abuseipdb", "otx"],
        help="Enrichment sources to use (default: all)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")

    args = parser.parse_args()

    if not args.ioc and not args.input:
        parser.print_help()
        sys.exit(1)

    keys = get_api_keys()

    # Mask sources the user didn't request
    active_sources = set(args.sources)
    if "vt" not in active_sources:
        keys["virustotal"] = None
    if "abuseipdb" not in active_sources:
        keys["abuseipdb"] = None
    if "otx" not in active_sources:
        keys["otx"] = None

    vt = VirusTotalEnricher(keys.get("virustotal") or "")
    abuseipdb = AbuseIPDBEnricher(keys.get("abuseipdb") or "")
    otx = OTXEnricher(keys.get("otx") or "")
    scorer = RiskScorer()

    # Build IOC list
    iocs: List[Tuple[str, str]] = []
    if args.ioc:
        ioc_type, ioc_value = classify_ioc(args.ioc)
        if ioc_type == "unknown":
            print(f"[ERROR] Could not classify IOC: {args.ioc}")
            sys.exit(1)
        iocs.append((ioc_type, ioc_value))

    if args.input:
        try:
            iocs.extend(parse_ioc_file(args.input))
        except FileNotFoundError:
            print(f"[ERROR] IOC file not found: {args.input}")
            sys.exit(1)

    if not iocs:
        print("[ERROR] No valid IOCs to process.")
        sys.exit(1)

    print(f"[*] Processing {len(iocs)} IOC(s) across {len([k for k in [keys.get('virustotal'), keys.get('abuseipdb'), keys.get('otx')] if k])} source(s)...\n")

    all_results = []
    for ioc_type, ioc_value in iocs:
        print(f"  → Enriching {ioc_type}: {ioc_value}")
        enrichments = enrich_single(ioc_type, ioc_value, vt, abuseipdb, otx, keys)
        scored = scorer.score(ioc_value, ioc_type, enrichments)
        all_results.append(scored)

    # Terminal output
    if not args.no_color:
        print(format_terminal_report(all_results))
    else:
        for r in all_results:
            print(f"{r['ioc']} | {r['type']} | Score: {r['risk_score']}/100 | Verdict: {r['verdict']}")
            for signal in r.get("signals", []):
                print(f"  • {signal}")
            print()

    # JSON output
    if args.output:
        write_json_report(all_results, args.output)
        print(f"[*] JSON report written to: {args.output}")

    # Exit with non-zero code if any IOC is malicious (useful in CI/SOAR pipelines)
    if any(r.get("verdict") == "MALICIOUS" for r in all_results):
        sys.exit(2)


if __name__ == "__main__":
    main()
