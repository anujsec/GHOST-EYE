# GHOST-EYE v2.1 Enhancements

## Overview

This upgrade transforms Ghost-Eye into a comprehensive attack-surface discovery pipeline while maintaining the fast-first architecture. The new version introduces:

- **Deep Crawling & Crawlers Integration** (Katana, enhanced historical URLs)
- **API Endpoint Discovery** (Dedicated API identification stage)
- **Port & Service Discovery** (naabu + optional nmap)
- **Source Map Analysis** (Extract and analyze source maps)
- **Content Discovery** (ffuf / feroxbuster with intelligent targeting)
- **URL Normalization & Deduplication** (uro integration)
- **Enhanced Reporting** (Prioritized attack surface, source attribution)
- **Tool Auto-Detection** (Automated tool availability checking)

## New Architecture

### Enhanced Pipeline Flow

```
TARGET
  ↓
SEED EXPANSION (org reconnaissance)
  ↓
SUBDOMAIN DISCOVERY (passive + optional brute force)
  ↓
DNS RESOLUTION (collect A/AAAA/CNAME/MX/TXT)
  ↓
HTTP DISCOVERY (probe live hosts, technology detection)
  ↓
HISTORICAL URL DISCOVERY (gau/wamore/waybackurls)
  ↓
DEEP CRAWLING (Katana with depth control)
  ↓
JAVASCRIPT ANALYSIS (extract endpoints, find source maps)
  ↓
API ENDPOINT DISCOVERY (identify /api patterns, group by host)
  ↓
CONTENT DISCOVERY (ffuf/feroxbuster on tier1 hosts)
  ↓
PORT/SERVICE DISCOVERY (naabu + optional nmap)
  ↓
URL NORMALIZATION (uro-based deduplication)
  ↓
NUCLEI SCANNING (template-based vulnerability checks)
  ↓
PRIORITIZED REPORTING (attack surface summary)
```

### Fast vs Deep Mode

#### FAST MODE (Default)
- ✓ subfinder passive enumeration
- ✓ Lightweight DNS resolution
- ✓ httpx probing
- ✓ Lightweight Katana crawling (depth 1, tier1+tier2 only)
- ✓ Basic JS analysis (up to 150 files)
- ✓ Simple secrets detection
- ✓ Small Nuclei tag set (exposures,misconfig,default-login,takeover)
- ✗ Port scanning
- ✗ Content discovery
- ✗ Service detection
- ✗ Source maps
- **Duration:** ~5-15 minutes per domain

#### DEEP MODE (`--deep`)
- ✓ amass org-level pivots
- ✓ CT enrichment
- ✓ DNS brute force + permutations
- ✓ Deep Katana crawling (depth 3, all tiers)
- ✓ Comprehensive JS analysis (up to 1000 files)
- ✓ Source map discovery
- ✓ ffuf/feroxbuster content discovery (bounded to top hosts)
- ✓ naabu port scanning
- ✓ Optional nmap service detection
- ✓ Extended Nuclei tags (+cve,vuln)
- ✓ URL normalization with uro
- **Duration:** ~30-60+ minutes per domain

## New Modules

### `tool_check.py`
Automatic tool availability detection. Run before scanning:

```python
from tool_check import print_tool_status
print_tool_status()
```

Output shows which tools are installed and any missing dependencies.

### `reporting.py`
Enhanced attack-surface reporting with:
- Endpoint categorization (admin, auth, api, upload, etc.)
- Finding prioritization by severity + template type
- Attack surface summary generation
- Source attribution for each discovery

### `pipeline_extensions.py`
Additional pipeline phases:
- `run_port_discovery()` — naabu/nmap integration
- `run_content_discovery_enhanced()` — ffuf/feroxbuster
- `run_source_map_discovery()` — Extract .map files
- `extract_api_endpoints()` — Identify API patterns
- `normalize_and_dedupe_urls()` — uro-based normalization

## New Tool Integrations

### Port Scanning
- **naabu** — Fast port discovery (enabled in --deep mode)
- **nmap** — Service detection (optional, only with `--service-detect`)

### Content Discovery
- **ffuf** — Faster, simpler content discovery (recommended)
- **feroxbuster** — Alternative with more options

### URL Optimization
- **uro** — Intelligent URL normalization & deduplication
- Fallback: Basic normalization if uro unavailable

### JavaScript Analysis
- **jsluice** — Enhanced JS analysis (optional)
- Fallback: Regex-based extraction

### Historical URLs
- **wamore** — Enhanced historical URL discovery
- Fallback: gau if wamore unavailable

## Configuration

Add to `config.yaml`:

```yaml
port_discovery:
  enabled: false           # On with --deep
  max_hosts: 50           # Limit scan targets
  service_detection: false # Requires --service-detect flag

content_discovery:
  tool: ffuf              # ffuf or feroxbuster
  # ... existing options

url_normalization:
  use_uro: true          # Use uro if available
```

## Updated Outputs

New files in the run directory:

```
runs/[org]/[timestamp]/
├── subdomains.txt                    # All discovered subdomains
├── dns.jsonl                         # DNS records (A/AAAA/CNAME/MX/TXT)
├── httpx.jsonl                       # Live hosts + tech detection
├── historical_urls.txt               # URLs from Wayback, gau, etc.
├── crawled_urls.txt                  # URLs discovered by Katana
├── api_endpoints.json                # Grouped API endpoints by host
├── open_ports.json                   # Open ports + services (if --deep)
├── source_maps.txt                   # Discovered source map URLs
├── js_files.txt                      # JavaScript file list
├── js_endpoints.txt                  # Extracted endpoints + content discovery results
├── secrets.jsonl                     # Detected secrets in JS
├── nuclei.jsonl                      # Vulnerability scan results
├── attack_surface_report.md          # Prioritized attack surface summary
└── summary.json                      # Statistics + delta report
```

## Enhanced Reporting

The final report now includes:

1. **Discovery Summary**
   - Subdomains (total, resolved)
   - HTTP Services (live hosts, tech stack)
   - URLs (live, historical, unique paths, unique params)
   - JavaScript (files, endpoints, source maps)
   - Network (open ports, services)

2. **Vulnerabilities** (by severity)
   - Critical, High, Medium, Low, Info

3. **Interesting Attack Surface Items**
   - Authentication endpoints
   - API endpoints (grouped by host)
   - Admin/control panels
   - Upload functionality
   - GraphQL endpoints
   - Exposed documentation

4. **Source Attribution**
   - Every finding tagged with its source (e.g., [NUCLEI], [KATANA], [FFUF])

## Command Examples

### Check tool status before running
```bash
python recon.py --check-tools
```

### Fast scan (default)
```bash
python recon.py example.com
```

### Deep comprehensive scan
```bash
python recon.py example.com --deep
```

### Deep scan with service detection
```bash
python recon.py example.com --deep --service-detect
```

### Deep scan with content discovery
```bash
python recon.py example.com --deep --content-discovery
```

### Deep scan with everything
```bash
python recon.py example.com --deep --screenshots --service-detect --content-discovery
```

## Tool Installation Guide

### Required
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Recommended (for deep mode)
```bash
# Crawler
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Historical URLs
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/xnl-h4ck3r/wamore@latest

# Advanced discovery
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/d3mondev/puredns/v2@latest

# Port scanning
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Content discovery
go install github.com/ffuf/ffuf@latest
go install github.com/epi052/feroxbuster@latest

# URL normalization
go install github.com/s0md3v/uro@latest

# JavaScript analysis (optional)
go install github.com/xnl-h4ck3r/jsluice@latest
```

### Optional
```bash
# Service detection (slow)
brew install nmap

# Screenshots
go install github.com/sensepost/gowitness@latest

# Secrets scanning (secondary check)
pip install trufflehog
```

## Performance Notes

1. **Concurrency is bounded** — Never creates unlimited threads
2. **Per-task timeouts** — Each subprocess has a timeout to prevent hangs
3. **Fast mode is genuinely fast** — No expensive operations in default run
4. **Deep mode is comprehensive** — For authorized targets only
5. **Caching works** — Results are cached with TTL; subsequent runs are faster

## Safety & Scope

Ghost-Eye is designed for **authorized security testing only**:

- ✓ Bug bounty reconnaissance
- ✓ Authorized penetration testing
- ✓ Internal security assessment

The tool:
- ✗ Does NOT attempt to bypass rate limits or WAFs
- ✗ Does NOT perform credential attacks
- ✗ Does NOT exploit vulnerabilities automatically
- ✗ Does NOT scan unauthorized third-party infrastructure

**Always have explicit written authorization before running this tool against any target.**

## Delta Tracking

Ghost-Eye preserves history and only reports **what's new**:

- New subdomains
- New live hosts
- New endpoints
- New vulnerabilities

Run it regularly on authorized targets — it will tell you what changed since last time.

## Example Complete Flow

```bash
# Install dependencies
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# ... (install other tools)

# First run
python recon.py example.com --deep

# Review results
cat runs/example.com/*/attack_surface_report.md

# Second run (reports only deltas)
python recon.py example.com --deep

# Look for "[+] NEW" sections in output
```

---

## Implementation Details

### URL Normalization Strategy

Basic normalization (always):
- Remove fragments
- Lowercase scheme + host
- Normalize port defaults (80→http, 443→https)
- Sort query parameters

Enhanced with uro (if available):
- Intelligent parameter removal
- Semantic path normalization
- Deduplication of parameter-only variations

### API Endpoint Detection

Patterns matched:
- `/api/`, `/api/v1/`, `/api/v2/`, etc.
- `/graphql`, `/graphql/`
- `/rest/`, `/rest/api/`
- `/oauth/`, `/oauth2/`
- `/auth/`, `/authentication/`
- `/services/`, `/methods/`, `/functions/`
- And more custom patterns

### Endpoint Categorization

Automatic categorization:
- Admin (admin, manager, control, dashboard)
- Auth (auth, login, signin, oauth, saml)
- API (/api patterns)
- Upload (upload, file, media, image)
- Webhooks (webhook, hook, notify)
- GraphQL (/graphql)
- Metrics (metrics, stats, analytics)
- Health (health, status, ping)
- Docs (swagger, openapi, api-docs)

---

**Ghost-Eye v2.1** is a production-ready reconnaissance framework for authorized security testing.
