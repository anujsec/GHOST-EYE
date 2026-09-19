"""
core/target.py — turn whatever the user typed into a clean root domain.

Accepts:
    example.com
    https://example.com
    http://example.com/
    HTTPS://WWW.Example.com/some/path?x=1
    example.com:8443

and normalizes all of them down to a bare, lowercase hostname suitable for
feeding into subfinder/amass/crt.sh/etc.
"""

import re
from urllib.parse import urlsplit

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class InvalidTargetError(ValueError):
    pass


def normalize_target(raw: str) -> str:
    """
    Normalize a single user-supplied target string into a bare hostname.
    Raises InvalidTargetError if it doesn't look like a usable domain.
    """
    if not raw or not raw.strip():
        raise InvalidTargetError("empty target")

    s = raw.strip()

    # If there's no scheme, urlsplit treats the whole thing as a path unless
    # we give it something that looks like a netloc. Add a scheme so
    # urlsplit parses host/port correctly either way.
    if "://" not in s:
        s = "//" + s  # netloc-relative form, urlsplit still extracts host
    parsed = urlsplit(s)

    host = parsed.hostname or ""
    host = host.strip().lower()
    host = host.rstrip(".")  # trailing dot (FQDN notation)

    if not host:
        raise InvalidTargetError(f"could not extract a hostname from: {raw!r}")

    # allow bare 'localhost' and IPs through for local/test usage even
    # though the strict hostname regex below wouldn't match them
    if host == "localhost" or _looks_like_ip(host):
        return host

    if not _HOSTNAME_RE.match(host):
        raise InvalidTargetError(f"'{host}' doesn't look like a valid domain")

    return host


def normalize_targets(raw_list) -> list[str]:
    """Normalize + dedupe a list (or comma-separated string) of targets."""
    if isinstance(raw_list, str):
        raw_list = raw_list.split(",")
    seen = []
    for item in raw_list:
        item = item.strip()
        if not item:
            continue
        norm = normalize_target(item)
        if norm not in seen:
            seen.append(norm)
    return seen


def _looks_like_ip(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return ":" in host  # crude IPv6 check, good enough to not misfire the regex


def derive_org(domain: str) -> str:
    """
    Best-effort human-readable org label from a bare domain, with no
    external dependency (no tldextract) — good enough for run-folder
    naming and notification labels, not meant to be authoritative.
    """
    labels = domain.split(".")
    if len(labels) < 2:
        return domain.capitalize()
    # naive: assume the registrable label is second-to-last, except for
    # common two-part public suffixes (co.uk, com.au, etc.)
    two_part_suffixes = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "org.uk", "gov.uk"}
    last_two = ".".join(labels[-2:])
    if last_two in two_part_suffixes and len(labels) >= 3:
        base = labels[-3]
    else:
        base = labels[-2]
    return base.capitalize()
