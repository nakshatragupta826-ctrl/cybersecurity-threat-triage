# Multi-Agent Cybersecurity Intelligence & Dynamic Threat Triage System

A Python cybersecurity project that combines installed-software vulnerability discovery, threat-intelligence enrichment, multi-agent analysis, and dynamic risk prioritization in a Streamlit dashboard.

It supports two workflows:

- **Manual CVE analysis:** provide a CVE ID to investigate its vulnerability details, threat evidence, and risk.
- **Automatic software scanning:** inventory supported software on a Windows endpoint, compare installed versions with local NVD vulnerability data, and send matching CVEs into the deeper triage pipeline.

> **Status:** Core workflows have been implemented and tested in the development environment. Detection depends on product coverage, the freshness and completeness of local vulnerability feeds, upstream data quality, and availability of external services. This is an educational/defensive project, not a replacement for a commercial vulnerability-management platform.

## Features

- Windows installed-software inventory using uninstall-registry entries.
- Product and version normalization.
- Version-aware matching against local NVD JSON feeds.
- NVD feed caching to reduce repeated loading during a scan session.
- Threat-intelligence enrichment using Exa and the project's vulnerability-data integrations.
- CISA Known Exploited Vulnerabilities (KEV) evidence where available.
- Three-agent triage workflow:
  1. **Threat Intelligence Analyst** — summarizes vulnerability and exploitation evidence.
  2. **Risk Assessment Agent** — assesses severity and dynamic risk factors.
  3. **Reflection Agent** — reviews the analysis for consistency and completeness.
- Dynamic risk fusion combining base CVSS severity with exploit-maturity and evidence-recency signals.
- P0–P3 priority classification.
- SQLite persistence for scan and triage records.
- Streamlit dashboard for software scanning, manual CVE analysis, activity logs, and results.
- Scheduled automatic scanning while the dashboard session remains active.
- Evaluation support for a labelled CVE set.

## How it works

### Manual CVE analysis

```text
CVE ID entered by user
        |
        v
Vulnerability details and threat evidence
        |
        v
Threat Intelligence Analyst
        |
        v
Risk Assessment Agent
        |
        v
Reflection Agent
        |
        v
Dynamic risk fusion and priority
        |
        v
SQLite database and dashboard
```

Manual mode answers: **“Given this CVE, what is its current threat context and risk?”**

### Automatic software scanning

```text
Windows installed-software inventory
        |
        v
Normalize product name and version
        |
        v
Map to vendor/product identifiers
        |
        v
Compare installed version with NVD affected-version configurations
        |
        v
Only matching CVEs proceed to deeper triage
        |
        v
Threat evidence + agents + risk fusion
        |
        v
Save results and show dashboard activity
```

Automatic mode answers: **“Given the software installed on this endpoint, which known vulnerabilities may affect those versions?”**

A result such as `0 new CVE(s) triaged` means that the scan did not add any new matching CVEs to triage during that pass. It does **not** prove that the machine is free of all vulnerabilities; coverage and feed limitations apply.

## Technology stack

- Python 3.11 (tested development version)
- Streamlit
- CrewAI
- Groq through LiteLLM
- Exa threat-intelligence search
- National Vulnerability Database (NVD) JSON feeds
- CISA KEV evidence where available
- SQLite
- Windows registry for installed-software inventory

## Repository layout

Main modules in the current development setup include:

```text
final-system/
├── dashboard.py
├── scanner.py
├── pipeline.py
├── risk_fusion.py
├── config.py
├── db.py
├── agents.py
├── crew.py
├── requirements.txt
├── tools/
│   ├── product_normalizer.py
│   ├── software_inventory.py
│   └── vulnerability_discovery.py
├── .env.example
├── .gitignore
└── README.md
```

Adjust this diagram if the files in your repository differ.

## Requirements

- Windows 10/11 is the intended endpoint-scanning environment.
- Python 3.11
- Git
- Internet access for external threat-intelligence and LLM integrations.
- API credentials for the providers enabled in your configuration.

The dashboard or analysis components may run elsewhere, but installed-software discovery is Windows-specific.

## Setup

### 1. Clone the repository

Replace the placeholders with your GitHub username and repository name:

```powershell
git clone https://github.com/<your-github-username>/<your-repository-name>.git
cd <your-repository-name>
```

### 2. Create and activate a virtual environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use the virtual environment's Python directly:

```powershell
.\.venv\Scripts\python.exe --version
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure API keys

If `.env.example` is included, create a local `.env`:

```powershell
Copy-Item .env.example .env
```

The development setup uses these variables:

```dotenv
GROQ_API_KEY=your_groq_api_key
EXA_API_KEY=your_exa_api_key
```

Use real values only in your local `.env`. **Never commit `.env`, API keys, tokens, or credentials.** If a secret was ever committed, revoke or rotate it; deleting it in a later commit does not remove it from Git history.

If `config.py` or an integration requires other variables, add their names (never their values) to `.env.example` and document them.

### 5. Prepare NVD feeds

The scanner uses local NVD JSON feeds for version-aware matching. The development setup used compressed feeds for 2025 and 2026. Obtain the required feeds from the official source and place them at the paths expected by `tools/vulnerability_discovery.py`.

Official source: [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)

Large feed files are intentionally excluded from Git. Check `tools/vulnerability_discovery.py` for the exact filenames and paths expected by your local code.

### 6. Run the dashboard

From the repository root:

```powershell
streamlit run dashboard.py
```

Open the local URL printed by Streamlit, usually `http://localhost:8501`.

Scheduled automatic scanning requires the dashboard session to remain active.

### 7. Run a one-time software scan

```powershell
python scanner.py --once
```

This runs a single installed-software scan using the configured local feeds and integrations.

## Risk fusion

The risk-fusion module combines a vulnerability's base CVSS score with dynamic signals, including exploit maturity and the age of threat evidence. The current implementation applies evidence-age decay, caps the fused score at 10, and maps the result to a priority band.

The fused score is a project-specific prioritization aid; it is **not** an official CVSS score. Check `risk_fusion.py` for the current weights and P0–P3 thresholds.

## Evaluation

The development evaluation used a labelled set of 40 CVEs and reported:

| Metric | Result |
|---|---:|
| Accuracy | 87.5% |
| Precision | 85.7% |
| Recall | 90.0% |
| F1 score | 87.8% |

These figures describe that particular evaluation set and its labels; they are not a guarantee of real-world detection performance. If publishing these metrics, document the dataset selection, labelling method, test script, and limitations.

## Security and limitations

- This is a student/research project, not a certified vulnerability scanner.
- Coverage is limited to supported products and version formats.
- A clean scan does not prove that an endpoint is secure.
- NVD feed freshness and affected-version configurations influence detection.
- External API failures, rate limits, and model responses can affect analysis.
- AI-generated summaries may be incomplete or incorrect. Verify important findings against vendor advisories and trusted primary sources.
- Do not use the generated priority as the sole basis for production remediation decisions.
- Test only on systems you own or are explicitly authorized to assess.

## Troubleshooting

### No matching vulnerabilities detected

Check that the application and version appear in inventory, the product is supported by `tools/product_normalizer.py`, the expected NVD feeds are present, and the CVE's affected-version configuration includes the installed version. A CVE can exist in NVD without affecting the installed version.

### API-key or LLM errors

Check that `.env` exists, its variable names match `config.py`, and the credentials are valid. Never paste keys into issues, screenshots, or public logs.

### Missing NVD feed files

Check the filenames and paths expected by `tools/vulnerability_discovery.py`, then download the feeds from the official NVD source.

### Dashboard changes do not appear

Stop Streamlit with `Ctrl+C` in the terminal and restart:

```powershell
streamlit run dashboard.py
```

## Possible future improvements

- Broaden software and package-manager coverage.
- Add scheduled feed refresh and feed-integrity checks.
- Add unit and integration tests for affected-version matching.
- Add evidence-linked remediation reports.
- Improve audit logging and scan error reporting.
- Evaluate on a larger, independently labelled CVE dataset.
- Include evidence provenance and confidence in agent outputs.
- Add packaging and deployment guidance for controlled environments.

## Contributing

Issues and pull requests are welcome. Do not include secrets, personal data, or sensitive endpoint details in reports. Provide reproducible test cases with environment-specific details redacted.

## License

No license has been selected yet. Until a license is added, assume the repository is **all rights reserved** by default. Before publishing publicly, choose a license and add a `LICENSE` file. MIT is a common permissive choice for student projects, but only use it if you have the right to license all included code and assets.
