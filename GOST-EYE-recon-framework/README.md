# recon-framework v2

A fast, parallel, delta-first recon pipeline. Point it at a domain, it runs
concurrently instead of sequentially, keeps a SQLite history so it only
tells you what **changed** since last time, and never requires editing a
config file for normal use.

> **Only point this at scope you are explicitly authorized to test** —
> a program's published bounty scope, or a target you hold written
> authorization for. This tool does not attempt to evade rate limits,
> WAFs, auth, or other defensive controls, and respects the rate limits
> you configure.

## Quick start

```bash
pip install -r requirements.txt
python recon.py example.com
```

That's it. No config file required. `rich` (for nicer terminal output) is
optional — everything falls back to plain `print()` if it isn't installed.

```bash
python recon.py                          # interactive: prompts for target + mode
python recon.py example.com              # fast mode (default)
python recon.py --target example.com     # same, explicit flag
python recon.py example.com --deep       # expensive pivots, brute force, wider nuclei tags
python recon.py example.com --screenshots
python recon.py example.com --no-nuclei
python recon.py example.com --bruteforce # DNS brute force without full --deep
```

Target input is normalized automatically — `example.com`, `https://example.com`,
`http://example.com/`, `HTTPS://WWW.Example.com/path?x=1` all resolve to a
clean root hostname. The organization label (used for run folders and
notifications) is derived from the domain unless you pass `--org`.

## What changed from v1, and why it's faster

**v1** ran five layers strictly sequentially — seed expansion, then
subdomain enum, then probing, then content discovery, then nuclei — and
every layer collected the maximum possible data for every host, every time.

**v2:**

| Change | Why it's faster |
|---|---|
| Independent phases run concurrently (`ThreadPoolExecutor` via `core/executor.py`) | crt.sh, subfinder, and amass no longer wait on each other; same for gau/waybackurls per domain |
| Fast mode is the default; `--deep` opts into expensive stages | ASN/org pivots, DNS brute force, permutations, and full content discovery are off unless asked for |
| `httpx` has fast/deep field profiles | fast mode skips favicon hash, TLS grab, and response hashing — the expensive-per-host fields |
| Host **prioritization** (`core/scoring.py`) | `api.*`, `admin.*`, `staging.*`, unusual status codes, interesting tech, and hosts new since last run get crawled/content-discovered/nuclei'd first; ordinary hosts are deprioritized in fast mode instead of treated equally |
| JS analysis is bounded parallel (`core/executor.map_parallel`) | v1 looped through up to 500 JS files sequentially; v2 processes them with a configurable worker pool |
| Screenshots run in a background thread, joined only at the very end | v1 blocked the whole pipeline on `gowitness`; v2 kicks it off after HTTP probing and only waits for it after everything else is done |
| Caching (`core/cache.py`, TTL-based SQLite) | crt.sh, DNS resolution, and gau/waybackurls results are skipped on subsequent runs within their TTL window |
| `db.py` batches writes (`executemany` + SQLite upsert) instead of one write per subprocess result | fewer round trips, and a real bug fix — see below |
| Nuclei is staged: `exposures,misconfig,default-login,takeover` by default, `+cve,vuln` only with `--deep` | avoids the most expensive template categories unless asked for |


## Install

```bash
pip install -r requirements.txt

# Go-based recon tools — install what you plan to use; the pipeline skips
# anything missing with a warning instead of crashing.
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/sensepost/gowitness@latest
go install github.com/owasp-amass/amass/v4/...@master

# optional
pip install trufflehog   # only used as a secondary check, see above
# gitleaks, feroxbuster, dnsvalidator: see their own release binaries
```

Configure API keys for `subfinder`/`amass` in their own config files
(`~/.config/subfinder/provider-config.yaml`, `~/.config/amass/config.ini`) —
more keys = dramatically better passive coverage. Nothing else needs setup
for a default fast run.

## Fast vs Deep mode

| | Fast (default) | `--deep` |
|---|---|---|
| ASN / amass org intel | off | on |
| DNS brute force + permutations | off | on (needs `wordlists.subdomains` + `resolvers.validated` in config) |
| httpx fields | status/title/tech/server/length/redirect | + cdn/cname/hash/favicon/tls |
| katana crawl depth | 1, tier1+tier2 hosts only | 3, all tiers |
| JS files analyzed | up to 150 | up to 1000 |
| content discovery (feroxbuster) | off | on, bounded to top 10 hosts |
| nuclei tags | `exposures,misconfig,default-login,takeover` | + `cve,vuln` |

`--bruteforce` turns on just the DNS brute-force stage without the rest of
`--deep`. `--screenshots` and `--no-nuclei` work in either mode.

## Changing concurrency / config

Nothing in `config.yaml` is required, but if you want to override defaults:

```bash
cp config.example.yaml config.yaml
```

Then edit what you need — e.g. to raise JS analysis parallelism:

```yaml
concurrency:
  js_workers: 20
```

or point brute force / content discovery at wordlists:

```yaml
wordlists:
  subdomains: /opt/wordlists/n0kovo_subdomains.txt
  content: /opt/wordlists/raft-medium-directories.txt
resolvers:
  validated: /opt/resolvers/resolvers.txt
```

Resolver hygiene (run before using `--bruteforce`/`--deep`):
```bash
dnsvalidator -tL resolvers_raw.txt -threads 50 -o resolvers.txt
```

## Enabling notifications

```yaml
notifications:
  slack_webhook: "https://hooks.slack.com/services/..."
  discord_webhook: "https://discord.com/api/webhooks/..."
  telegram_bot_token: ""
  telegram_chat_id: ""
```

You only get notified on real deltas (new subdomain, new live host, changed
tech/response, new endpoint, new finding) — not a full dump every run.
High/critical nuclei findings and possible subdomain takeovers are always
pushed immediately regardless of the diff state.

## Output structure

```text
runs/
  Example/
    20260917T090623/
      summary.json
      subdomains.txt
      dns.jsonl
      httpx.jsonl
      urls.txt
      js_endpoints.txt
      secrets.jsonl        (only if anything was found)
      takeovers.jsonl      (only if anything was found)
      nuclei.jsonl
      screenshots/         (only with --screenshots)
```

Everything also lives in `data/recon.db` (SQLite) for cross-run querying:

```bash
sqlite3 data/recon.db "SELECT asset_key, attrs FROM assets WHERE table_name='http_probes' AND attrs LIKE '%WordPress%';"
sqlite3 data/recon.db "SELECT asset_key FROM assets WHERE table_name='subdomains' AND first_seen > strftime('%s','now','-7 days');"
```

## Continuous scheduling

Same cron approach as before — passive stages are cheap and safe to run
often, active/brute-force stages should run less frequently:

```cron
0 * * * *  cd /path/to/recon-framework && python3 recon.py example.com --no-nuclei --yes >> logs/cron.log 2>&1
0 3 * * *  cd /path/to/recon-framework && python3 recon.py example.com --deep --yes >> logs/cron.log 2>&1
```

`--yes`/`-y` makes it fail fast instead of hanging on an interactive
prompt — required for cron/CI since nothing there can answer one.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

75 tests, all mocked at the `tools.py` function boundary — no real
subprocess execution or third-party network calls happen in the test
suite. Covers: target normalization (all the URL/scheme/trailing-slash
variants), cache TTL behavior, host scoring/tiering, the executor's
concurrency and timeout/failure isolation, the notification formatter,
and an end-to-end pipeline smoke test (fast mode, deep mode, `--no-nuclei`,
`--screenshots`, partial tool failure, and delta-only behavior across two
runs) with every `tools.py` call mocked out.

## Project layout

```text
recon-framework/
├── recon.py              CLI entrypoint, config loading, arg parsing
├── config.example.yaml
├── core/
│   ├── ui.py              banner, live phase spinner, summary panel (rich optional)
│   ├── target.py          target normalization + org-name derivation
│   ├── cache.py            TTL cache (its own SQLite file, separate from asset history)
│   ├── scoring.py          host prioritization / tiering (scan order, never "vulnerable")
│   ├── executor.py         bounded ThreadPoolExecutor wrapper, per-task timeout/failure isolation
│   └── pipeline.py         the actual phase graph — start here to understand the flow
├── db.py                  SQLite persistence + diffing (assets + append-only history)
├── notify.py               Slack/Discord/Telegram
├── tools.py                 subprocess/network wrappers around every external tool
├── tests/                  75 tests, fully mocked
├── data/                   recon.db, cache.db (gitignored)
└── runs/                   per-target, per-timestamp raw output (gitignored)
```

Kept flatter than a `core/` + `modules/` split — five phase functions in one
readable `pipeline.py` was less indirection than eight single-purpose
module files for a tool this size.

## Notes

- Every tool wrapper checks `shutil.which()` first and skips with a warning
  rather than crashing if a binary isn't installed.
- `content_discovery` and screenshot stages are both bounded to a
  configurable number of top-priority hosts, never run against every live
  host by default.
- Nuclei rate limit / concurrency defaults are intentionally conservative
  (`rate_limit: 50`, `concurrency: 25`) — check the program's rules of
  engagement before raising them.
- Favicon-hash pivoting (Shodan/Censys/FOFA) and tracker-ID pivoting
  (BuiltWith) aren't wrapped — they're paid APIs with different auth per
  provider. Same pattern as everything else in `tools.py`
  (`which_or_warn` → call → return parsed list) if you want to add them.
