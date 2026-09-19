"""
core/scoring.py — decide scan ORDER, not vulnerability status.

Nothing here should ever be surfaced to the user as "vulnerable" — a high
score means "reconnaissance target worth spending time-budget on first",
nothing more. Used to pick which hosts get crawled deeper / content-
discovered / nuclei-scanned first when time or request budget is limited.
"""

import re

INTERESTING_LABEL_PATTERNS = [
    r"^api[-.]", r"[-.]api$", r"^api$",
    r"^admin", r"[-.]admin",
    r"^dev[-.]", r"[-.]dev$", r"^dev$",
    r"^staging", r"[-.]staging",
    r"^test[-.]", r"[-.]test$",
    r"^internal", r"[-.]internal",
    r"^vpn", r"[-.]vpn",
    r"^portal", r"[-.]portal",
    r"^auth", r"[-.]auth",
    r"^login", r"[-.]login",
    r"^dashboard", r"[-.]dashboard",
    r"^upload", r"[-.]upload",
    r"^graphql", r"[-.]graphql",
    r"^sso", r"[-.]sso",
    r"^git", r"[-.]git",
    r"^jenkins", r"^grafana", r"^kibana", r"^jira",
]
_INTERESTING_RE = re.compile("|".join(INTERESTING_LABEL_PATTERNS), re.IGNORECASE)

UNUSUAL_STATUS_CODES = {401, 403, 500, 502, 503}
INTERESTING_TECH_KEYWORDS = {
    "jenkins", "gitlab", "jira", "confluence", "grafana", "kibana",
    "wordpress", "drupal", "phpmyadmin", "tomcat", "swagger", "graphql",
}


def score_host(hostname: str, probe_attrs: dict | None = None, is_new: bool = False) -> int:
    """
    Higher = higher priority for deeper follow-up (crawl / content-discovery /
    nuclei ordering). Purely a scan-ordering heuristic.
    """
    score = 0
    attrs = probe_attrs or {}

    if _INTERESTING_RE.search(hostname):
        score += 30

    status = attrs.get("status_code")
    if status in UNUSUAL_STATUS_CODES:
        score += 15

    tech = attrs.get("tech") or []
    tech_lower = {str(t).lower() for t in tech}
    if tech_lower & INTERESTING_TECH_KEYWORDS:
        score += 15

    # non-standard port embedded in the URL/host
    if ":" in hostname and not hostname.endswith(":443") and not hostname.endswith(":80"):
        score += 10

    if is_new:
        score += 10  # newly discovered since last run — worth a fresh look

    return score


def tier_hosts(hosts: list[str], probe_by_host: dict, new_hosts: set | None = None,
                tier1_size: int = 15, tier2_size: int = 60) -> dict:
    """
    Splits hosts into tier1 (highest priority), tier2, tier3 based on score,
    for staged URL discovery / content discovery / nuclei ordering.
    """
    new_hosts = new_hosts or set()
    scored = sorted(
        hosts,
        key=lambda h: score_host(h, probe_by_host.get(h), h in new_hosts),
        reverse=True,
    )
    return {
        "tier1": scored[:tier1_size],
        "tier2": scored[tier1_size:tier1_size + tier2_size],
        "tier3": scored[tier1_size + tier2_size:],
    }
