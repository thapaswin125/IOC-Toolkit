# IOC-Toolkit

# IOC Enrichment Pipeline

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Sources](https://img.shields.io/badge/sources-VirusTotal%20%7C%20AbuseIPDB%20%7C%20OTX-orange)

A Python-based threat intelligence enrichment pipeline that fans out indicators of compromise (IOCs) to multiple free threat intel APIs in parallel, aggregates the results, and produces risk-scored verdicts with structured JSON output.

Built for SOC analysts and detection engineers who need fast, automated IOC triage without paying for a commercial TIP.

---

## Project Timeline

- **June 2026** — The initial IOC enrichment pipeline was developed.
- **October 2026** — The project was consolidated under the `thapaswin125/IOC-Toolkit` repository and published as the current milestone.

Commit dates remain unchanged so the repository history accurately reflects when work was performed.

---

## Features

- **Multi-source enrichment** — VirusTotal v3, AbuseIPDB v2, AlienVault OTX, queried concurrently
- **Automatic IOC classification** — detects IPv4, domain, MD5, SHA1, SHA256, and URL without manual tagging
- **Composite risk scoring** — 0–100 score aggregated across sources with a CLEAN / SUSPICIOUS / MALICIOUS verdict
- **Colored terminal output** — human-readable report with per-IOC signal breakdown
- **JSON report export** — structured output suitable for ingestion into SIEM or ticketing systems
- **SOAR/CI-friendly** — exits with code `2` if any IOC scores MALICIOUS; use in automated pipelines
- **Batch processing** — process hundreds of IOCs from a file in a single run
- **Selective sources** — run only the sources you want with `--sources`

---

## Supported IOC Types

| Type | VirusTotal | AbuseIPDB | OTX |
|------|-----------|-----------|-----|
| IPv4 | ✅ | ✅ | ✅ |
| Domain | ✅ | — | ✅ |
| MD5 / SHA1 / SHA256 | ✅ | — | ✅ |
| URL | ✅ | — | ✅ |

---

## Quickstart

### 1. Clone and install

```bash
git clone https://github.com/thapaswin125/IOC-Toolkit.git
cd IOC-Toolkit
pip install -r requirements.txt
```

### 2. Configure API keys

All three APIs are free to register for:

| Source | Registration | Free Tier |
|--------|-------------|-----------|
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | Free account | 4 req/min, 500/day |
| [AbuseIPDB](https://www.abuseipdb.com/account/api) | Free account | 1,000 checks/day |
| [AlienVault OTX](https://otx.alienvault.com/api) | Free account | Generous limits |

```bash
cp .env.example .env
# Edit .env and add your keys
```

### 3. Run

```bash
# Enrich a single IOC
python ioc_enricher.py --ioc 185.220.101.45

# Enrich a file of IOCs
python ioc_enricher.py -i examples/sample_iocs.txt

# Write results to JSON
python ioc_enricher.py -i examples/sample_iocs.txt --output report.json

# Use specific sources only
python ioc_enricher.py --ioc evilcorp.ru --sources vt otx

# Disable color (for logging/piping)
python ioc_enricher.py -i iocs.txt --no-color
```

---

## Example Output

```
============================================================
  IOC Enrichment Report  —  2026-06-13 18:00:00 UTC
============================================================

IOC:     185.220.101.45
Type:    ip
Score:   87/100
Verdict: MALICIOUS
Signals:
  • VT: 14 malicious engines (14/93)
  • AbuseIPDB confidence: 100%
  • AbuseIPDB: 2341 reports from 487 users
  • AbuseIPDB: Tor exit node
  • OTX: found in 23 threat pulse(s)
  • OTX adversary attribution: APT28
  • OTX malware families: Cobalt Strike, Emotet

────────────────────────────────────────────────────────────
Summary: 9 IOCs — 2 MALICIOUS | 3 SUSPICIOUS | 4 CLEAN
────────────────────────────────────────────────────────────
```

See [`examples/sample_output.json`](examples/sample_output.json) for a full JSON report.

---

## IOC File Format

One IOC per line. Comments start with `#`. Mixed types are supported.

```
# Suspicious IPs
185.220.101.45
45.142.212.100

# Domains
evil-c2.ru
phishing-bank-login.com

# File hashes
44d88612fea8a8f36de82e1278abb02f
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

## Risk Scoring

The composite score (0–100) is calculated from signals across all sources:

| Signal | Score Contribution |
|--------|-------------------|
| VT malicious engine hits | Up to +60 (weighted by ratio) |
| VT suspicious engine hits | Up to +15 |
| AbuseIPDB confidence score | Up to +40 (scaled) |
| Tor exit node flag | +10 |
| OTX pulse matches | Up to +30 |
| OTX adversary attribution | +10 |

**Verdicts:** CLEAN (0–34) · SUSPICIOUS (35–69) · MALICIOUS (70–100)

---

## SOAR Integration

The tool exits with code `2` when any IOC is MALICIOUS, making it easy to wire into automated pipelines:

```bash
python ioc_enricher.py -i alert_iocs.txt --output enriched.json --no-color
if [ $? -eq 2 ]; then
    # Trigger escalation playbook
    echo "Malicious IOC detected — escalating"
fi
```

JSON output can be passed directly to SOAR platforms like Tines or Torq as a webhook payload.

---

## Project Structure

```
IOC-Toolkit/
├── ioc_enricher.py        # CLI entrypoint
├── enrichers/
│   ├── virustotal.py      # VirusTotal v3 API
│   ├── abuseipdb.py       # AbuseIPDB v2 API
│   └── otx.py             # AlienVault OTX API
├── utils/
│   ├── ioc_parser.py      # IOC type classification
│   └── reporter.py        # Risk scoring + output formatting
├── examples/
│   ├── sample_iocs.txt    # Sample IOC file
│   └── sample_output.json # Sample JSON report
├── .env.example           # API key template
├── requirements.txt
└── README.md
```

---

## License

MIT
