"""
core/pipeline.py — the actual recon pipeline: independent phases run
concurrently where they don't depend on each other, with fast-mode scope
reduction (not just "more threads") keeping the default run quick.

Phase graph (see README for the diagram):
  seed expansion (crt.sh + subfinder + amass, concurrently)
    -> dedupe
    -> [deep only] brute force + permutations
    -> dnsx resolution (cached)
    -> httpx probing            \
         -> screenshots (async, optional, never blocks the rest)
         -> scoring / tiering
    -> URL discovery (gau/waybackurls always; katana bounded by tier)
    -> JS analysis (bounded parallel workers)
    -> [optional] content discovery (feroxbuster, bounded to top hosts)
    -> nuclei (staged tags, fast by default)
  -> diff against last run per asset table -> notify only on real deltas
"""

import copy
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import db
import notify
import tools
from core import cache as cache_mod
from core.executor import run_parallel, map_parallel
from core.scoring import tier_hosts, score_host
from core.target import normalize_targets, derive_org

log = logging.getLogger("recon.pipeline")

DEFAULTS = {
    "mode": "fast",
    "concurrency": {
        "discovery_workers": 15,  #increase from 5 
        "dns_workers": 50,        #increase from 20
        "js_workers": 20,         #increase from 10
        "content_workers": 5,
    },
    "discovery": {
        "passive": True,
        "expensive_pivots": False,   # ASN / org intel — off by default, on with --deep
        "brute_force": False,        # on with --deep or --bruteforce
        "permutations": False,
        "recursive_permutations": False,
    },
    "httpx": {"mode": "fast"},
    "url_discovery": {"katana_depth_fast": 1, "katana_depth_deep": 3,
                       "js_cap_fast": 150, "js_cap_deep": 1000},
    "content_discovery": {"enabled": False, "max_hosts": 10, "timeout": 300},
    "screenshots": {"enabled": False, "max_hosts": 20},
    "nuclei": {"enabled": True, "rate_limit": 50, "concurrency": 25, "timeout": 1800},
    "cache": {"enabled": True, "dns_ttl": 3600, "passive_ttl": 21600, "url_history_ttl": 86400},
    "wordlists": {"subdomains": None, "content": None},
    "resolvers": {"validated": None},
    "notifications": {"slack_webhook": "", "discord_webhook": "", "telegram_bot_token": "", "telegram_chat_id": ""},
}


def merge_defaults(user_cfg: dict) -> dict:
    merged = copy.deepcopy(DEFAULTS)

    def _merge(base, override):
        for k, v in (override or {}).items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                _merge(base[k], v)
            else:
                base[k] = v

    _merge(merged, user_cfg)
    return merged


class Reporter:
    """No-op base reporter; recon.py supplies a real one for terminal output."""
    def phase_start(self, name): pass
    def phase_done(self, name, counts: dict, duration: float): pass
    def warn(self, msg): pass
    def info(self, msg): pass
    def notify_change(self, line): pass


def run_dir_for(base_dir: Path, org: str) -> Path:
    ts = time.strftime("%Y%m%dT%H%M%S")
    d = base_dir / "runs" / org.replace(" ", "_") / ts
    d.mkdir(parents=True, exist_ok=True)
    return d


def _announce(cfg, org, layer, table, diff, reporter: Reporter):
    msg = notify.format_diff_message(org, layer, table, diff)
    if msg:
        notify.send(cfg["notifications"], msg)
        reporter.notify_change(f"{table}: +{len(diff['new'])} ~{len(diff['changed'])} -{len(diff['removed'])}")


def run_pipeline(target: str, org: str | None, cfg: dict, base_dir: Path, reporter: Reporter,
                  deep: bool = False, screenshots: bool = False, no_nuclei: bool = False,
                  bruteforce: bool = False, warnings: list | None = None) -> dict:
    """
    Runs the full pipeline for one target. Returns a summary dict used for
    the final report and for tests.
    """
    warnings = warnings if warnings is not None else []
    timings = {}
    t_pipeline_start = time.monotonic()

    org = org or derive_org(target)
    rd = run_dir_for(base_dir, org)

    if deep:
        cfg["discovery"]["expensive_pivots"] = True
        cfg["discovery"]["brute_force"] = True
        cfg["discovery"]["permutations"] = True
        cfg["discovery"]["recursive_permutations"] = True
        cfg["httpx"]["mode"] = "deep"
        cfg["content_discovery"]["enabled"] = True
    if bruteforce:
        cfg["discovery"]["brute_force"] = True
    if screenshots:
        cfg["screenshots"]["enabled"] = True
    if no_nuclei:
        cfg["nuclei"]["enabled"] = False

    cache_enabled = cfg["cache"]["enabled"]
    conc = cfg["concurrency"]

    # --------------------------------------------------- Phase 1: seed expansion
    reporter.phase_start("seed_expansion")
    t0 = time.monotonic()
    seed_run_id = db.start_run(org, "seed_expansion")

    seed_domains = {target}
    if cfg["discovery"]["expensive_pivots"]:
        expansion_tasks = {
            "asnmap": lambda: tools.asnmap(org),
            "amass_intel": lambda: tools.amass_intel_org(org),
        }
        exp_results = run_parallel(expansion_tasks, max_workers=2, per_task_timeout=180)
        if not exp_results["asnmap"].ok:
            warnings.append("asnmap failed or unavailable")
        if not exp_results["amass_intel"].ok:
            warnings.append("amass intel failed or unavailable")
        else:
            seed_domains.update(exp_results["amass_intel"].value or [])

    discovery_tasks = {"crtsh": lambda: tools.crtsh(target)}
    disc_results = run_parallel(discovery_tasks, max_workers=1, per_task_timeout=60)
    if disc_results["crtsh"].ok:
        seed_domains.update(disc_results["crtsh"].value or [])
    else:
        warnings.append("crt.sh lookup failed")

    seed_domains = normalize_targets(sorted(seed_domains))
    items = {d: {"source": "seed_expansion"} for d in seed_domains}
    db.upsert_assets(org, "root_domains", seed_run_id, items)
    diff = db.diff_since_last(org, "root_domains", seed_run_id)
    _announce(cfg, org, "seed_expansion", "root_domains", diff, reporter)
    db.finish_run(seed_run_id)

    timings["seed_expansion"] = time.monotonic() - t0
    reporter.phase_done("seed_expansion", {"domains": len(seed_domains)}, timings["seed_expansion"])

    # --------------------------------------------------- Phase 2: subdomain enum
    reporter.phase_start("subdomain_enum")
    t0 = time.monotonic()
    sub_run_id = db.start_run(org, "subdomain_enum")

    passive_tasks = {}
    for d in seed_domains:
        passive_tasks[f"subfinder:{d}"] = lambda d=d: tools.subfinder(d)
        passive_tasks[f"amass:{d}"] = lambda d=d: tools.amass_passive(d)
    passive_results = run_parallel(passive_tasks, max_workers=conc["discovery_workers"], per_task_timeout=150)

    all_subs = set(seed_domains)
    for name, res in passive_results.items():
        if res.ok:
            all_subs.update(res.value or [])
        else:
            warnings.append(f"{name} failed or unavailable")

    if cfg["discovery"]["brute_force"]:
        wl = cfg["wordlists"].get("subdomains")
        resolvers = cfg["resolvers"].get("validated")
        if wl and resolvers:
            brute_tasks = {f"puredns:{d}": lambda d=d: tools.puredns_bruteforce(d, wl, resolvers)
                            for d in seed_domains}
            brute_results = run_parallel(brute_tasks, max_workers=conc["discovery_workers"], per_task_timeout=1800)
            for name, res in brute_results.items():
                if res.ok:
                    all_subs.update(res.value or [])
                else:
                    warnings.append(f"{name} failed")
        else:
            warnings.append("brute force requested but wordlists/resolvers not configured — skipped")

    if cfg["discovery"]["permutations"]:
        resolvers = cfg["resolvers"].get("validated")
        if resolvers:
            perms = tools.alterx_permutations(sorted(all_subs))
            resolved = tools.puredns_resolve(perms, resolvers)
            all_subs.update(resolved)
            if cfg["discovery"]["recursive_permutations"] and resolved:
                more_perms = tools.alterx_permutations(resolved)
                all_subs.update(tools.puredns_resolve(more_perms, resolvers))
        else:
            warnings.append("permutations requested but no validated resolver list — skipped")

    all_subs = set(normalize_targets(sorted(all_subs)))
    tools.save_raw(rd, "subdomains.txt", "\n".join(sorted(all_subs)))

    items = {s: {"source": "subdomain_enum"} for s in all_subs}
    db.upsert_assets(org, "subdomains", sub_run_id, items)
    sub_diff = db.diff_since_last(org, "subdomains", sub_run_id)
    _announce(cfg, org, "subdomain_enum", "subdomains", sub_diff, reporter)
    new_sub_keys = {k for k, _ in sub_diff["new"]}
    db.finish_run(sub_run_id)

    timings["subdomain_enum"] = time.monotonic() - t0
    reporter.phase_done("subdomain_enum", {"subdomains": len(all_subs)}, timings["subdomain_enum"])

    # --------------------------------------------------- Phase 3: DNS resolution (cached)
    reporter.phase_start("dns")
    t0 = time.monotonic()

    dns_ttl = cfg["cache"]["dns_ttl"]
    to_resolve = []
    dns_records = []
    for host in sorted(all_subs):
        cached_rec = cache_mod.get(f"dns:{host}") if cache_enabled else None
        if cached_rec is not None:
            dns_records.append(cached_rec)
        else:
            to_resolve.append(host)

    if to_resolve:
        fresh = tools.dnsx(to_resolve, timeout=max(120, len(to_resolve) // max(1, conc["dns_workers"])))
        dns_records.extend(fresh)
        if cache_enabled:
            for r in fresh:
                host = r.get("host")
                if host:
                    cache_mod.set(f"dns:{host}", r, dns_ttl)

    tools.save_raw(rd, "dns.jsonl", "\n".join(str(r) for r in dns_records))

    dangling = [r["host"] for r in dns_records if r.get("cname") and not r.get("a")]
    takeover_hits = []
    if dangling:
        takeover_hits = tools.nuclei_takeovers(dangling, timeout=300)
        if takeover_hits:
            tools.save_raw(rd, "takeovers.jsonl", "\n".join(str(h) for h in takeover_hits))
            hosts_str = ", ".join(h.get("host", h.get("matched-at", "?")) for h in takeover_hits[:10])
            notify.send(cfg["notifications"], f"🚨 [{org}] {len(takeover_hits)} possible takeover(s): {hosts_str}")

    timings["dns"] = time.monotonic() - t0
    reporter.phase_done("dns", {"resolved": len(dns_records), "cached": len(all_subs) - len(to_resolve),
                                 "dangling": len(dangling)}, timings["dns"])

    # --------------------------------------------------- Phase 4: HTTP probing (+ async screenshots)
    reporter.phase_start("http")
    t0 = time.monotonic()
    probe_run_id = db.start_run(org, "probing")

    probes = tools.httpx_probe(sorted(all_subs), mode=cfg["httpx"]["mode"], timeout=900)
    tools.save_raw(rd, "httpx.jsonl", "\n".join(str(p) for p in probes))

    live_urls = [p["url"] for p in probes if p.get("url")]
    probe_by_host = {}
    for p in probes:
        host = p.get("input") or p.get("url")
        if host:
            probe_by_host[host] = p

    screenshot_future = None
    screenshot_pool = None
    if cfg["screenshots"]["enabled"] and live_urls:
        cap = cfg["screenshots"]["max_hosts"]
        tiers_for_shots = tier_hosts(live_urls, {u: probe_by_host.get(u, {}) for u in live_urls}, new_sub_keys)
        shot_urls = (tiers_for_shots["tier1"] + tiers_for_shots["tier2"])[:cap]
        screenshot_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="screenshots")
        screenshot_future = screenshot_pool.submit(tools.gowitness_screenshot, shot_urls, rd / "screenshots")
        reporter.info(f"screenshots running in background for {len(shot_urls)} hosts (non-blocking)")

    items = {}
    for p in probes:
        key = p.get("input") or p.get("url")
        if not key:
            continue
        items[key] = {
            "status_code": p.get("status_code"),
            "title": p.get("title"),
            "tech": p.get("tech", []),
            "server": p.get("webserver"),
            "content_length": p.get("content_length"),
            "cdn": p.get("cdn_name"),
            "cname": p.get("cname"),
            "hash": (p.get("hash") or {}).get("sha256") if isinstance(p.get("hash"), dict) else None,
        }
    db.upsert_assets(org, "http_probes", probe_run_id, items)
    http_diff = db.diff_since_last(org, "http_probes", probe_run_id)
    _announce(cfg, org, "probing", "http_probes", http_diff, reporter)
    new_live_hosts = {k for k, _ in http_diff["new"]}
    db.finish_run(probe_run_id)

    timings["http"] = time.monotonic() - t0
    reporter.phase_done("http", {"probed": len(probes), "live": len(live_urls)}, timings["http"])

    # --------------------------------------------------- Phase 5: prioritization
    tiers = tier_hosts(live_urls, {u: probe_by_host.get(u, {}) for u in live_urls}, new_live_hosts)

    # --------------------------------------------------- Phase 6: URL discovery
    reporter.phase_start("url_discovery")
    t0 = time.monotonic()

    url_ttl = cfg["cache"]["url_history_ttl"]

    def cached_gau(d):
        key = f"gau:{d}"
        hit = cache_mod.get(key) if cache_enabled else None
        if hit is not None:
            return hit
        val = tools.gau(d)
        if cache_enabled:
            cache_mod.set(key, val, url_ttl)
        return val

    def cached_wayback(d):
        key = f"wayback:{d}"
        hit = cache_mod.get(key) if cache_enabled else None
        if hit is not None:
            return hit
        val = tools.waybackurls(d)
        if cache_enabled:
            cache_mod.set(key, val, url_ttl)
        return val

    history_tasks = {}
    for d in seed_domains:
        history_tasks[f"gau:{d}"] = lambda d=d: cached_gau(d)
        history_tasks[f"wayback:{d}"] = lambda d=d: cached_wayback(d)
    history_results = run_parallel(history_tasks, max_workers=conc["discovery_workers"], per_task_timeout=300)

    historical_urls = set()
    for name, res in history_results.items():
        if res.ok:
            historical_urls.update(res.value or [])
        else:
            warnings.append(f"{name} failed")

    depth = cfg["url_discovery"]["katana_depth_deep" if deep else "katana_depth_fast"]
    crawl_targets = tiers["tier1"] + tiers["tier2"] if not deep else tiers["tier1"] + tiers["tier2"] + tiers["tier3"]
    crawled = set(tools.katana_crawl(crawl_targets, depth=depth, timeout=600)) if crawl_targets else set()

    all_urls = {tools.normalize_url(u) for u in (historical_urls | crawled)}
    tools.save_raw(rd, "urls.txt", "\n".join(sorted(all_urls)))

    timings["url_discovery"] = time.monotonic() - t0
    reporter.phase_done("url_discovery", {"historical": len(historical_urls), "crawled": len(crawled),
                                           "unique": len(all_urls)}, timings["url_discovery"])

    # --------------------------------------------------- Phase 7: JS analysis (bounded parallel)
    reporter.phase_start("javascript")
    t0 = time.monotonic()
    js_run_id = db.start_run(org, "content_discovery")

    js_cap = cfg["url_discovery"]["js_cap_deep" if deep else "js_cap_fast"]
    js_urls = sorted({u for u in all_urls if u.split("?")[0].endswith(".js")})[:js_cap]

    js_results = map_parallel(tools.analyze_js_url, js_urls,
                               max_workers=conc["js_workers"], per_item_timeout=45)

    endpoints = set()
    secrets_found = []
    for r in js_results:
        if not r.ok or not r.value:
            continue
        endpoints.update(r.value.get("endpoints", []))
        for s in r.value.get("secrets", []):
            secrets_found.append({**s, "url": r.value["url"]})

    if secrets_found:
        tools.save_raw(rd, "secrets.jsonl", "\n".join(str(s) for s in secrets_found))
        notify.send(cfg["notifications"],
                    f"🔑 [{org}] {len(secrets_found)} potential secret(s) in JS — see {rd / 'secrets.jsonl'}")

    items = {u: {"source": "content_discovery"} for u in endpoints}
    db.upsert_assets(org, "js_endpoints", js_run_id, items)
    js_diff = db.diff_since_last(org, "js_endpoints", js_run_id)
    _announce(cfg, org, "content_discovery", "js_endpoints", js_diff, reporter)

    # --------------------------------------------------- Phase 8: content discovery (optional, bounded)
    ferox_hits = set()
    if cfg["content_discovery"]["enabled"]:
        wl = cfg["wordlists"].get("content")
        max_hosts = cfg["content_discovery"]["max_hosts"]
        if wl:
            ferox_targets = tiers["tier1"][:max_hosts]
            ferox_tasks = {f"ferox:{u}": lambda u=u: tools.feroxbuster(u, wl, timeout=cfg["content_discovery"]["timeout"])
                            for u in ferox_targets}
            ferox_results = run_parallel(ferox_tasks, max_workers=conc["content_workers"],
                                          per_task_timeout=cfg["content_discovery"]["timeout"] + 30)
            for name, res in ferox_results.items():
                if res.ok:
                    ferox_hits.update(res.value or [])
                else:
                    warnings.append(f"{name} failed")
        else:
            warnings.append("content discovery enabled but no wordlist configured — skipped")

    tools.save_raw(rd, "js_endpoints.txt", "\n".join(sorted(endpoints | ferox_hits)))
    db.finish_run(js_run_id)

    timings["javascript"] = time.monotonic() - t0
    reporter.phase_done("javascript", {"js_files": len(js_urls), "endpoints": len(endpoints) + len(ferox_hits)},
                         timings["javascript"])

    # --------------------------------------------------- Phase 9: nuclei (staged)
    findings = []
    if cfg["nuclei"]["enabled"]:
        reporter.phase_start("nuclei")
        t0 = time.monotonic()
        nuclei_run_id = db.start_run(org, "vuln_correlation")

        tags = tools.DEEP_NUCLEI_TAGS if deep else tools.FAST_NUCLEI_TAGS
        scan_targets = dedupe_preserve(live_urls) if not deep else dedupe_preserve(live_urls + list(all_urls))
        findings = tools.nuclei_scan(scan_targets, tags=tags,
                                      rate_limit=cfg["nuclei"]["rate_limit"],
                                      concurrency=cfg["nuclei"]["concurrency"],
                                      timeout=cfg["nuclei"]["timeout"])
        tools.save_raw(rd, "nuclei.jsonl", "\n".join(str(f) for f in findings))

        items = {}
        for f in findings:
            key = f"{f.get('template-id')}::{f.get('matched-at', f.get('host'))}"
            items[key] = {"severity": f.get("info", {}).get("severity"),
                          "name": f.get("info", {}).get("name"), "host": f.get("host")}
        db.upsert_assets(org, "findings", nuclei_run_id, items)
        finding_diff = db.diff_since_last(org, "findings", nuclei_run_id)
        _announce(cfg, org, "vuln_correlation", "findings", finding_diff, reporter)

        critical = [f for f in findings if f.get("info", {}).get("severity") in ("high", "critical")]
        if critical:
            lines = "\n".join(f"  {f.get('info', {}).get('name')} @ {f.get('host')}" for f in critical[:15])
            notify.send(cfg["notifications"], f"🚨 [{org}] {len(critical)} HIGH/CRITICAL finding(s):\n{lines}")

        db.finish_run(nuclei_run_id)
        timings["nuclei"] = time.monotonic() - t0
        reporter.phase_done("nuclei", {"scanned": len(scan_targets), "findings": len(findings)}, timings["nuclei"])

    # --------------------------------------------------- join background screenshots before finishing
    if screenshot_future is not None:
        reporter.info("waiting on background screenshots to finish...")
        try:
            screenshot_future.result(timeout=600)
        except Exception as e:
            warnings.append(f"screenshots failed or timed out: {e}")
        screenshot_pool.shutdown(wait=False)

    total_duration = time.monotonic() - t_pipeline_start

    summary = {
        "org": org,
        "target": target,
        "mode": "deep" if deep else "fast",
        "run_dir": str(rd),
        "duration_seconds": total_duration,
        "timings": timings,
        "counts": {
            "domains": len(seed_domains),
            "subdomains": len(all_subs),
            "live_hosts": len(live_urls),
            "urls": len(all_urls),
            "js_files": len(js_urls),
            "endpoints": len(endpoints) + len(ferox_hits),
            "findings": len(findings),
        },
        "changes": {
            "new_subdomains": len(sub_diff["new"]),
            "new_live_hosts": len(http_diff["new"]),
            "new_endpoints": len(js_diff["new"]),
            "new_findings": len(findings),
        },
        "warnings": warnings,
    }
    tools.save_raw(rd, "summary.json", _to_json(summary))
    return summary


def dedupe_preserve(items):
    seen = set()
    out = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _to_json(obj):
    import json
    return json.dumps(obj, indent=2, default=str)
