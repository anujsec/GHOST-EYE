# GHOST-EYE — code review + patches

**Everything below is already applied** in the accompanying tree — it is a
complete, runnable `ghost-eye/` you can drop over your working copy. This
document is the explanation of what changed and why, not a to-do list.

Rewritten: `recon.py`, `core/executor.py`, `core/cache.py`. New: `core/ui.py`.
Patched in place: `core/pipeline.py`, `db.py`, `tools.py`.

Verified with a two-run mocked smoke test: every external tool stubbed at the
`tools.py` boundary, run 1 reports deltas, run 2 reports zero across all four
counters, `.jsonl` artifacts parse with `json.loads`, and `prune_history()`
completes instead of raising.

Ordered by severity.

---

## 1. `-c/--config` was parsed and then ignored — **fixed in recon.py**

`main()` called `merge_defaults({})` unconditionally. `config.yaml` was never
read, so webhooks, wordlists, resolvers and concurrency overrides did nothing —
`--deep` would always warn "brute force requested but wordlists/resolvers not
configured" no matter what was in the file. `load_config()` now loads it.

## 2. `per_task_timeout` was never enforced — **fixed in executor.py**

`as_completed()` was called without a timeout, so one wedged subprocess hung the
whole run. Details in the module docstring.

## 3. Failed crt.sh lookups were cached for 6 hours — **fixed in cache.py**

`crtsh()` returns `[]` on failure and the old `set()` happily stored it. Empty
results are no longer cached.

## 4. `cache.enabled: false` didn't disable the decorated cache — **fixed in cache.py**

`@cached(..., enabled=True)` bound the flag at import time. Wire the runtime
switch in at the top of `run_pipeline`:

```python
# core/pipeline.py, just after `cache_enabled = cfg["cache"]["enabled"]`
cache_enabled = cfg["cache"]["enabled"]
cache_mod.set_enabled(cache_enabled)
cache_mod.purge_expired()
```

## 5. The `.jsonl` output files are not JSON

`"\n".join(str(r) for r in dns_records)` writes Python `repr()` — single quotes,
`None`/`True` instead of `null`/`true`. Every `.jsonl` artifact in `runs/` is
unparseable by `jq`, and the README advertises them as JSONL.

```python
# core/pipeline.py — add near _to_json()
def _jsonl(rows) -> str:
    import json
    return "\n".join(json.dumps(r, default=str) for r in rows)
```

Then replace all five call sites:

```python
tools.save_raw(rd, "dns.jsonl",       _jsonl(dns_records))
tools.save_raw(rd, "takeovers.jsonl", _jsonl(takeover_hits))
tools.save_raw(rd, "httpx.jsonl",     _jsonl(probes))
tools.save_raw(rd, "secrets.jsonl",   _jsonl(secrets_found))
tools.save_raw(rd, "nuclei.jsonl",    _jsonl(findings))
```

## 6. `new_findings` reported every finding as new

Defeats the point of a delta-first tool — a stable target shows "+12 new
findings" on every run forever.

```python
# core/pipeline.py, in the summary dict
"new_findings": len(finding_diff["new"]) if cfg["nuclei"]["enabled"] else 0,
```

`finding_diff` is scoped inside the `if cfg["nuclei"]["enabled"]:` block, so
initialise it alongside `findings = []`:

```python
findings = []
finding_diff = {"new": [], "removed": [], "changed": []}
```

## 7. `VACUUM` inside an open transaction raises

`prune_history()` runs `DELETE` (which implicitly opens a transaction under
sqlite3's default `isolation_level=""`) and then `VACUUM`, which SQLite refuses
inside a transaction.

```python
# db.py
def prune_history(org: str, older_than_days: int = 90, vacuum: bool = True):
    """Optional retention control — history is append-only and will grow otherwise."""
    cutoff = time.time() - older_than_days * 86400
    with get_db() as conn:
        conn.execute("DELETE FROM history WHERE org=? AND recorded_at < ?", (org, cutoff))
    if vacuum:
        # VACUUM cannot run inside a transaction, so it needs its own
        # autocommit connection (isolation_level=None).
        conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        try:
            conn.execute("VACUUM")
        finally:
            conn.close()
```

## 8. Scoring silently loses its signal

`probe_by_host` is keyed by `p.get("input") or p.get("url")` — httpx sets
`input` to the bare hostname. `tier_hosts()` is then called with `live_urls`
(full `https://host` URLs), so every lookup misses and every host scores on its
name alone: status code and detected tech never contribute to tiering.

```python
# core/pipeline.py, phase 4 — index under both keys
probe_by_host = {}
for p in probes:
    for key in (p.get("input"), p.get("url")):
        if key:
            probe_by_host[key] = p
```

Same class of bug with `new_sub_keys` (hostnames) being passed as the
`new_hosts` set for a URL-keyed tiering call in the screenshots block — the
"+10 if new" bonus never fires there. Use the URL-derived set, or normalise
both sides.

## 9. DNS timeout formula collapses to its floor

```python
timeout=max(120, len(to_resolve) // max(1, conc["dns_workers"]))
```

5,000 subdomains / 50 workers = 100, so `max(120, 100)` = 120s — the same
timeout as for 10 hosts, and dnsx gets killed mid-run on large targets. Scale
it properly and give it a ceiling:

```python
dns_timeout = min(1800, max(120, (len(to_resolve) * 2) // max(1, conc["dns_workers"])))
fresh = tools.dnsx(to_resolve, timeout=dns_timeout)
```

## 10. `asnmap` runs and its output is thrown away

```python
if not exp_results["asnmap"].ok:
    warnings.append("asnmap failed or unavailable")
```

There's no `else` — in `--deep` you pay for the ASN lookup and discard the
result. Either feed it in or drop the call:

```python
if exp_results["asnmap"].ok:
    seed_domains.update(exp_results["asnmap"].value or [])
else:
    warnings.append("asnmap failed or unavailable")
```

(`normalize_targets()` runs over `seed_domains` afterwards and will reject CIDR
ranges, so filter to hostnames first if asnmap returns netblocks.)

## 11. Encoding crashes on Windows / non-UTF-8 locales

`Path.write_text()` uses the platform default encoding. A JS bundle or a nuclei
title containing non-ASCII kills the run at write time.

```python
# tools.py
def save_raw(run_dir: Path, name: str, content: str):
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / name).write_text(content, encoding="utf-8")
```

Same fix in `gowitness_screenshot` (`tmp.write_text(...)`) and in
`analyze_js_url` (`fname.write_text(body, encoding="utf-8")`).

## 12. Unbounded JS download

`analyze_js_url` reads whatever the server sends. One 500 MB sourcemap-laden
bundle and the worker pool eats memory until the process dies. Cap the read:

```python
# tools.py
MAX_BODY_BYTES = 8 * 1024 * 1024  # 8 MB is generous for a JS bundle

def _http_get_with_backoff(url, timeout=20, retries=3, max_bytes=MAX_BODY_BYTES):
    delay = 1.0
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ghost-eye/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(max_bytes)
        except urllib.error.HTTPError as e:
            # 404/403 won't succeed on retry — don't burn three attempts on it
            if 400 <= e.code < 500:
                return None
            if attempt == retries:
                return None
            time.sleep(delay); delay *= 2
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt == retries:
                log.warning("GET %s failed after %d attempts: %s", url, retries, e)
                return None
            time.sleep(delay); delay *= 2
    return None
```

## 13. Smaller things

- `gowitness_screenshot` leaves `_urls.txt` inside `runs/.../screenshots/`.
  `tmp.unlink(missing_ok=True)` after the run.
- `feroxbuster(... "-o", "/dev/stdout")` is POSIX-only; use `--stdout` or a
  temp file if Windows support matters.
- `nuclei_takeovers()` is `nuclei_scan(hosts, tags="takeover")` with a
  different timeout — one function, one less place to drift.
- `core/scoring.py`: the "non-standard port" check tests `":" in hostname`,
  which is true for every `https://` URL passed in from `live_urls` — every
  host gets a free +10. Parse the netloc, or check `re.search(r":\d+$", host)`.
- `core/target.py`: `example.com:8443` is documented as accepted but the port
  is silently dropped by `urlsplit().hostname`. Also, IDN/punycode domains fail
  the ASCII hostname regex — `host.encode("idna").decode()` before matching.
- `phase 8` (feroxbuster) runs without a `reporter.phase_start` /
  `phase_done` pair, so the UI shows nothing while it's working. Wrap it.
- `unused import`: `score_host` in pipeline.py.
- `requirements.txt` lists `rich` under an "optional" comment but not as an
  extra, so `pip install -r` always pulls it. Fine, but the README claims
  optional — either move it to `requirements-ui.txt` or drop the claim.

---

## Optional: finer-grained live progress

`core/ui.py`'s reporter exposes `step(note)` on top of the existing Reporter
interface. Add a no-op to the base class so it stays optional:

```python
# core/pipeline.py
class Reporter:
    def phase_start(self, name): pass
    def phase_done(self, name, counts: dict, duration: float): pass
    def step(self, note): pass          # <- new, optional
    def warn(self, msg): pass
    def info(self, msg): pass
    def notify_change(self, line): pass
```

Then sprinkle it where a phase goes quiet for a long time:

```python
reporter.step(f"{len(seed_domains)} seed domains · subfinder + amass")
reporter.step(f"resolving {len(to_resolve)} hosts ({len(all_subs) - len(to_resolve)} cached)")
reporter.step(f"probing {len(all_subs)} hosts · {cfg['httpx']['mode']} profile")
reporter.step(f"{len(js_urls)} js files · {conc['js_workers']} workers")
reporter.step(f"{len(scan_targets)} targets · rl={cfg['nuclei']['rate_limit']}")
```

The spinner row then reads e.g.
`⠹ dns resolution   resolving 4,812 hosts (193 cached)  0:02:41`
instead of sitting blank.


---

## Verification

```
python3 -m py_compile recon.py db.py tools.py notify.py core/*.py
python3 -m unittest discover -s tests -v
```

Your existing suite patches `tools.py` by name — `core/cache.py` now uses
`functools.wraps`, so `tools.crtsh.__name__` survives decoration and those
patches keep resolving. Two test expectations will need updating on purpose:

- `nuclei_takeovers()` is now an alias over `nuclei_scan()`, so a test that
  asserts on the exact `nuclei` argv for takeovers will see `-rl`/`-c` added.
- the executor's timeout test should now assert that `run_parallel` *returns*
  within the budget, not just that the result dict has an entry — that was the
  behaviour the old test couldn't distinguish.
