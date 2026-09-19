"""
tools.py — thin subprocess/network wrappers around external recon binaries.

v2 changes from the original:
  - crt.sh gets retries with exponential backoff (it's a shared public
    service and 5xx/timeouts are common under load) and is cache-friendly
    via core.cache.cached.
  - httpx_probe() takes a `mode` ("fast"/"deep") — fast collects only the
    baseline fields worth paying for on every host; deep adds favicon
    hash / TLS grab / response hash, which are meaningfully more expensive
    per host.
  - nuclei_scan() replaces the old single nuclei_full(): takes an explicit
    tag set and rate/concurrency, used for both the fast default pass and
    the optional deep pass, instead of two near-duplicate functions.
  - scan_js_for_secrets() FIXES a real bug: the old trufflehog_scan_url()
    called `trufflehog filesystem <url>`, which scans a local path, not a
    remote URL — it would silently no-op against every JS URL. This
    version fetches the JS body once, then (a) runs a built-in regex
    secret scan, always available, and (b) if trufflehog is installed,
    writes the body to a temp file and runs `trufflehog filesystem` on
    *that*, which is the workflow trufflehog actually supports.
  - Every subprocess call still goes through which_or_warn() first, so a
    missing binary degrades gracefully instead of crashing the pipeline.
"""

import json
import re
import shutil
import subprocess
import logging
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path

from core.cache import cached

log = logging.getLogger("recon.tools")


def which_or_warn(binary: str) -> bool:
    if shutil.which(binary) is None:
        log.warning("'%s' not found on PATH — skipping this step. See README for install.", binary)
        return False
    return True


def run(cmd: list[str], timeout: int = 1800, input_data: str | None = None) -> str:
    log.debug("$ %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0 and proc.stderr:
            log.debug("stderr from %s: %s", cmd[0], proc.stderr[:2000])
        return proc.stdout
    except FileNotFoundError:
        log.warning("binary not found: %s", cmd[0])
        return ""
    except subprocess.TimeoutExpired:
        # subprocess.run already kills the process tree for us before re-raising
        log.warning("timed out (%ss): %s", timeout, " ".join(cmd[:3]) + " ...")
        return ""


MAX_BODY_BYTES = 8 * 1024 * 1024  # generous for a JS bundle; stops one huge
                                  # sourcemap from eating the worker pool's RAM


def _http_get_with_backoff(url: str, timeout: int = 20, retries: int = 3,
                           max_bytes: int = MAX_BODY_BYTES) -> bytes | None:
    delay = 1.0
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ghost-eye/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(max_bytes)
        except urllib.error.HTTPError as e:
            # a 404/403 will not start working on retry — don't burn three
            # attempts and two sleeps on it
            if 400 <= e.code < 500:
                return None
            if attempt == retries:
                log.warning("GET %s failed after %d attempts: HTTP %s", url, retries, e.code)
                return None
            time.sleep(delay)
            delay *= 2
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt == retries:
                log.warning("GET %s failed after %d attempts: %s", url, retries, e)
                return None
            time.sleep(delay)
            delay *= 2
    return None


def save_raw(run_dir: Path, name: str, content: str):
    # explicit encoding: write_text() defaults to the platform encoding, so a
    # non-ASCII nuclei title or JS endpoint killed the run on Windows/cp1252
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / name).write_text(content, encoding="utf-8")


def dedupe(items) -> list[str]:
    return sorted({i.strip() for i in items if i and i.strip()})


# ---------------------------------------------------------------- Layer 1 — seed expansion

def asnmap(org_or_domain: str) -> list[str]:
    if not which_or_warn("asnmap"):
        return []
    out = run(["asnmap", "-org", org_or_domain, "-silent"], timeout=60)
    return dedupe(out.splitlines())


def amass_intel_org(org_name: str) -> list[str]:
    if not which_or_warn("amass"):
        return []
    out = run(["amass", "intel", "-org", org_name], timeout=180)
    return dedupe(l for l in out.splitlines() if " " not in l.strip())


@cached("crtsh", ttl_seconds=21600)  # 6h — cert transparency data doesn't churn fast
def crtsh(domain: str) -> list[str]:
    """crt.sh via its JSON API (no binary needed), retried with backoff, cached."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    raw = _http_get_with_backoff(url, timeout=30, retries=3)
    if raw is None:
        return []
    try:
        data = json.loads(raw.decode())
    except json.JSONDecodeError as e:
        log.warning("crt.sh returned unparseable data for %s: %s", domain, e)
        return []
    names = set()
    for entry in data:
        for n in entry.get("name_value", "").split("\n"):
            n = n.strip().lstrip("*.")
            if n:
                names.add(n)
    return sorted(names)


# ---------------------------------------------------------------- Layer 2 — subdomain enum

def subfinder(domain: str) -> list[str]:
    if not which_or_warn("subfinder"):
        return []
    out = run(["subfinder", "-d", domain, "-silent", "-all"], timeout=300)
    return dedupe(out.splitlines())


def amass_passive(domain: str) -> list[str]:
    if not which_or_warn("amass"):
        return []
    out = run(["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=300)
    return dedupe(out.splitlines())


def puredns_bruteforce(domain: str, wordlist: str, resolvers: str, timeout: int = 1800) -> list[str]:
    if not which_or_warn("puredns"):
        return []
    out = run(["puredns", "bruteforce", wordlist, domain, "-r", resolvers, "--quiet"], timeout=timeout)
    return dedupe(out.splitlines())


def alterx_permutations(subs: list[str]) -> list[str]:
    if not which_or_warn("alterx"):
        return []
    out = run(["alterx", "-silent"], input_data="\n".join(subs), timeout=120)
    return dedupe(out.splitlines())


def puredns_resolve(domains: list[str], resolvers: str, timeout: int = 600) -> list[str]:
    if not domains:
        return []
    if not which_or_warn("puredns"):
        return domains
    out = run(["puredns", "resolve", "-r", resolvers, "--quiet"], input_data="\n".join(domains), timeout=timeout)
    return dedupe(out.splitlines())


# ---------------------------------------------------------------- Layer 3 — DNS + HTTP

def dnsx(subs: list[str], timeout: int = 300) -> list[dict]:
    if not subs:
        return []
    if not which_or_warn("dnsx"):
        return [{"host": s} for s in subs]
    out = run(["dnsx", "-json", "-silent", "-resp", "-cname", "-a"], input_data="\n".join(subs), timeout=timeout)
    results = []
    for line in out.splitlines():
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


HTTPX_FAST_FLAGS = ["-status-code", "-title", "-tech-detect", "-server", "-content-length", "-location"]
HTTPX_DEEP_FLAGS = HTTPX_FAST_FLAGS + ["-cdn", "-cname", "-hash", "sha256", "-favicon", "-tls-grab"]


def httpx_probe(subs: list[str], mode: str = "fast", timeout: int = 600) -> list[dict]:
    if not subs:
        return []
    if not which_or_warn("httpx"):
        return [{"input": s} for s in subs]
    flags = HTTPX_DEEP_FLAGS if mode == "deep" else HTTPX_FAST_FLAGS
    out = run(
        ["httpx", "-silent", "-json", "-follow-redirects", *flags],
        input_data="\n".join(subs), timeout=timeout,
    )
    results = []
    for line in out.splitlines():
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def nuclei_takeovers(subs: list[str], timeout: int = 600) -> list[dict]:
    """Thin alias over nuclei_scan so the two don't drift apart."""
    return nuclei_scan(subs, tags="takeover", timeout=timeout)


def gowitness_screenshot(urls: list[str], out_dir: Path, timeout: int = 600):
    if not urls or not which_or_warn("gowitness"):
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / "_urls.txt"
    tmp.write_text("\n".join(urls), encoding="utf-8")
    try:
        run(["gowitness", "scan", "file", "-f", str(tmp), "--screenshot-path", str(out_dir)], timeout=timeout)
    finally:
        tmp.unlink(missing_ok=True)  # don't leave scratch files in runs/


# ---------------------------------------------------------------- Layer 4 — URL / content discovery

def gau(domain: str, timeout: int = 300) -> list[str]:
    if not which_or_warn("gau"):
        return []
    out = run(["gau", "--subs", domain], timeout=timeout)
    return dedupe(out.splitlines())


def waybackurls(domain: str, timeout: int = 300) -> list[str]:
    if not which_or_warn("waybackurls"):
        return []
    out = run(["waybackurls", domain], timeout=timeout)
    return dedupe(out.splitlines())


def katana_crawl(urls: list[str], depth: int = 2, timeout: int = 600) -> list[str]:
    if not urls or not which_or_warn("katana"):
        return []
    out = run(["katana", "-silent", "-jc", "-kf", "all", "-depth", str(depth)],
              input_data="\n".join(urls), timeout=timeout)
    return dedupe(out.splitlines())


def normalize_url(u: str) -> str:
    """Strip volatile query params/fragments that would otherwise defeat dedup."""
    u = u.split("#")[0]
    return u.rstrip("/")


# --- JS analysis -----------------------------------------------------------

_SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,45}['\"]"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "generic_bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}"),
}

_ENDPOINT_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{2,}|https?://[a-zA-Z0-9_\-./%?=&]{5,})["']""")


def extract_endpoints_from_js(body: str) -> list[str]:
    """Regex-based endpoint extraction (no dependency on xnLinkFinder/LinkFinder being installed)."""
    found = set()
    for m in _ENDPOINT_RE.finditer(body):
        candidate = m.group(1)
        if candidate.startswith("/") and len(candidate) > 500:
            continue  # skip obvious base64 blobs matched by accident
        found.add(candidate)
    return sorted(found)


def scan_js_for_secrets(body: str) -> list[dict]:
    hits = []
    for name, pattern in _SECRET_PATTERNS.items():
        for m in pattern.finditer(body):
            hits.append({"type": name, "match_preview": m.group(0)[:60] + ("…" if len(m.group(0)) > 60 else "")})
    return hits


def analyze_js_url(js_url: str, use_trufflehog: bool = False, timeout: int = 30) -> dict:
    """
    Fetch a JS file once and run both endpoint extraction and secret scanning
    against the downloaded body. This replaces the old trufflehog-on-a-URL
    call, which doesn't reflect how trufflehog's `filesystem` subcommand
    actually works (it scans a local path, not a remote URL).
    """
    body_bytes = _http_get_with_backoff(js_url, timeout=timeout, retries=2)
    if body_bytes is None:
        return {"url": js_url, "endpoints": [], "secrets": [], "error": "fetch_failed"}

    body = body_bytes.decode("utf-8", errors="ignore")
    endpoints = extract_endpoints_from_js(body)
    secrets = scan_js_for_secrets(body)

    if use_trufflehog and which_or_warn("trufflehog"):
        with tempfile.TemporaryDirectory() as tmp:
            fname = Path(tmp) / "bundle.js"
            fname.write_text(body, encoding="utf-8")
            out = run(["trufflehog", "filesystem", "--json", tmp], timeout=60)
            for line in out.splitlines():
                try:
                    finding = json.loads(line)
                    secrets.append({"type": "trufflehog:" + finding.get("DetectorName", "unknown"),
                                     "match_preview": "(see trufflehog output)"})
                except json.JSONDecodeError:
                    continue

    return {"url": js_url, "endpoints": endpoints, "secrets": secrets}


def arjun_params(url: str, timeout: int = 300) -> list[str]:
    if not which_or_warn("arjun"):
        return []
    out = run(["arjun", "-u", url, "-oT", "-"], timeout=timeout)
    return dedupe(out.splitlines())


def feroxbuster(url: str, wordlist: str, timeout: int = 300) -> list[str]:
    if not which_or_warn("feroxbuster"):
        return []
    out = run(["feroxbuster", "-u", url, "-w", wordlist, "--silent", "-o", "/dev/stdout"], timeout=timeout)
    return dedupe(out.splitlines())


# ---------------------------------------------------------------- Layer 5 — nuclei / secrets

FAST_NUCLEI_TAGS = "exposures,misconfig,default-login,takeover"
DEEP_NUCLEI_TAGS = FAST_NUCLEI_TAGS + ",cve,vuln"


def nuclei_scan(hosts: list[str], tags: str, rate_limit: int = 50, concurrency: int = 25,
                 timeout: int = 1800) -> list[dict]:
    if not hosts:
        return []
    if not which_or_warn("nuclei"):
        return []
    out = run(
        ["nuclei", "-silent", "-jsonl", "-tags", tags,
         "-rl", str(rate_limit), "-c", str(concurrency)],
        input_data="\n".join(dedupe(hosts)),
        timeout=timeout,
    )
    results = []
    for line in out.splitlines():
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def gitleaks_scan(path: str, timeout: int = 300) -> list[dict]:
    if not which_or_warn("gitleaks"):
        return []
    out = run(["gitleaks", "detect", "--source", path, "--report-format", "json",
               "--report-path", "/dev/stdout", "--no-git"], timeout=timeout)
    try:
        return json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        return []


def s3scanner(bucket_names_file: str, timeout: int = 300) -> list[dict]:
    if not which_or_warn("s3scanner"):
        return []
    out = run(["s3scanner", "scan", "-f", bucket_names_file, "--json"], timeout=timeout)
    results = []
    for line in out.splitlines():
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


# ---------------------------------------------------------------- Resolver hygiene

def validate_resolvers(input_file: str, output_file: str, timeout: int = 300):
    if not which_or_warn("dnsvalidator"):
        return
    run(["dnsvalidator", "-tL", input_file, "-threads", "50", "-o", output_file], timeout=timeout)
