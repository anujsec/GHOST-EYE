# GHOST-EYE CURRENT ARCHITECTURE ANALYSIS

## Project Structure
```
ghost-eye/
├── recon.py              # Entry point, CLI, terminal UI
├── pipeline.py           # Main orchestration (650+ lines)
├── tools.py              # Subprocess wrappers + tool detection
├── db.py                 # SQLite history + delta tracking
├── cache.py              # TTL-based caching decorator
├── executor.py           # Parallel execution + timeout handling
├── scoring.py            # Host prioritization heuristics
├── target.py             # Domain parsing + normalization
├── notify.py             # Notification formatting (webhooks)
├── config.example.yaml   # Configuration template
├── requirements.txt      # Python dependencies
├── README.md             # Documentation
└── REVIEW.md             # Applied bug fixes + improvements
```

## Current Execution Pipeline

### Phase 1: Seed Expansion (Fast)
- CRT.sh lookup
- Optional: asnmap, amass_intel (only with --deep)
→ Output: root_domains

### Phase 2: Subdomain Enumeration (Parallel)
- subfinder + amass_passive (concurrent per domain)
- Optional: DNS brute force (--deep only, needs wordlists)
- Optional: Permutations (--deep only)
→ Output: subdomains.txt

### Phase 3: DNS Resolution (Parallel, Cached)
- dnsx or puredns_resolve
- Returns A, AAAA, CNAME records (some fields skipped in fast mode)
→ Output: dns.jsonl (JSONL format issue - uses Python repr())

### Phase 4: HTTP Probing (Parallel, Scored)
- httpx with status/title/tech/server/length/redirect
- Deep mode adds: cdn/cname/favicon_hash/tls_grab
- Host prioritization via scoring.py
- Optional: Screenshots (background thread)
→ Output: httpx.jsonl

### Phase 5: URL Discovery (Parallel)
- gau + waybackurls (concurrent)
- katana crawling (depth: 1 in fast, 3 in deep; bounded to tier1+2 in fast)
- Only crawls tier1 hosts in fast mode to save time
→ Output: urls.txt

### Phase 6: JavaScript Analysis (Bounded Parallel)
- Extract JS files from httpx responses
- Analyze with regex extraction + optional trufflehog
- Extract endpoints from JS
- Secrets scanning (AWS keys, JWTs, etc.)
→ Output: js_endpoints.txt, secrets.jsonl

### Phase 7: Nuclei Scanning (Parallel, Staged)
- Default tags: exposures,misconfig,default-login,takeover
- Deep mode adds: cve,vuln
→ Output: nuclei.jsonl

### Phase 8: Reporting + Delta Tracking
- Diff against last run
- Announce changes via notifications
- Save summary.json

## Current Tools Integrated

**Passive enumeration:** subfinder, amass (passive), crt.sh, asnmap
**DNS:** dnsx, puredns_resolve
**HTTP:** httpx
**Crawling:** katana, gau, waybackurls
**JS analysis:** regex-based endpoint extraction, trufflehog (optional)
**Content discovery:** feroxbuster (optional, --deep only)
**Vulnerability scanning:** nuclei
**Screenshots:** gowitness
**Parameter finding:** arjun (available but not integrated)

## Performance Characteristics

### What Made v1 Slow
1. All phases ran sequentially
2. Every host got maximum data collection
3. JS analysis looped (not parallelized)
4. Screenshots blocked the pipeline
5. No caching between runs

### What v2 Fixed
1. **Concurrency:** Independent phases run in parallel
2. **Prioritization:** Only expensive tasks run on top hosts (fast mode)
3. **Bounded parallelism:** JS analysis uses ThreadPoolExecutor with configurable workers
4. **Background tasks:** Screenshots run async, joined at end
5. **Caching:** TTL-based caching for crt.sh, DNS, gau/waybackurls
6. **Staging:** Nuclei templates grouped by severity

## Output Structure

```
runs/
└── [org_name]/
    └── [timestamp]/
        ├── subdomains.txt
        ├── dns.jsonl
        ├── httpx.jsonl
        ├── urls.txt
        ├── js_endpoints.txt
        ├── secrets.jsonl
        ├── nuclei.jsonl
        └── summary.json
```

## Known Issues (From REVIEW.md)

1. ✅ Config file wasn't being read (FIXED in recon.py)
2. ✅ Per-task timeout not enforced (FIXED in executor.py)
3. ✅ Failed crt.sh results cached (FIXED in cache.py)
4. ✅ Cache.enabled flag ignored (FIXED in cache.py)
5. ✅ JSONL output uses Python repr() instead of JSON (FIXED in pipeline.py)
6. ✅ New findings reported incorrectly (FIXED in pipeline.py)

## What's Missing for Full Attack Surface Discovery

1. **Historical URL Enrichment:** gau/waybackurls exist but could be enhanced
2. **Deep Crawling:** katana is integrated but could be more aggressive in deep mode
3. **API Endpoint Discovery:** No dedicated API enumeration stage
4. **Content Discovery:** feroxbuster exists but is minimal/optional
5. **Port/Service Discovery:** No naabu or nmap integration
6. **Source Maps:** No source map discovery or analysis
7. **URL Normalization:** Basic normalization exists but no deduplication layer
8. **Endpoint Extraction:** Only from JS; no dedicated path extraction
9. **Technology Profiling:** Uses httpx tech detection but could be richer
10. **Report Quality:** Summary is basic JSON; no comprehensive prioritized report

## Concurrency Model

- `ThreadPoolExecutor` for most phases
- Configurable workers per phase (discovery_workers, dns_workers, js_workers, etc.)
- Per-task timeout enforcement
- No unlimited thread creation
- Background screenshot thread (daemon)

## Database Model

**Schema:** org → table_name → asset_key
- `assets` table: current state (UNIQUE on org+table_name+asset_key)
- `history` table: append-only historical records per run
- `diff_since_last()`: Compares historical records to detect deltas
- Fixed in v2: v1 could not correctly reconstruct previous state

## Testing

- REVIEW.md mentions a two-run mocked smoke test
- No formal test suite visible
- JSONL output files should be parseable (now that repr() is fixed)

---

## Summary: What to Enhance

**A. Add deeper discovery stages:**
- Enhanced historical URL discovery (gau/wamore)
- Dedicated content discovery (ffuf/feroxbuster)
- Port/service discovery (naabu/nmap)
- Source map discovery

**B. Improve existing stages:**
- Better JS endpoint extraction (jsluice, etc.)
- Dedicated API endpoint discovery
- URL normalization + deduplication

**C. Enhance reporting:**
- Prioritized attack surface summary
- Source attribution for every discovery
- Better visualization of findings

**D. Keep Fast vs Deep clear:**
- Fast mode: lightweight discovery only
- Deep mode: comprehensive + expensive tools

**E. Maintain existing strengths:**
- Concurrency model
- Caching + TTL
- Delta tracking
- Tool auto-detection
- Config flexibility
