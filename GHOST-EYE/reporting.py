"""
Enhanced reporting for Ghost-Eye.
Generates prioritized attack surface summaries with source attribution.
"""

import json
from pathlib import Path
from typing import Any


def categorize_endpoints(urls: list[str], endpoints_from_js: list[str]) -> dict:
    """
    Categorize discovered endpoints by type.
    Returns dict with categories like admin, api, auth, upload, etc.
    """
    import re
    
    categories = {
        "admin": [],
        "auth": [],
        "api": [],
        "upload": [],
        "webhooks": [],
        "graphql": [],
        "metrics": [],
        "health": [],
        "docs": [],
        "misc": []
    }
    
    all_endpoints = urls + endpoints_from_js
    
    patterns = {
        "admin": [r"/admin", r"/manager", r"/control", r"/dashboard"],
        "auth": [r"/auth", r"/login", r"/signin", r"/oauth", r"/saml"],
        "api": [r"/api", r"/v\d+/", r"/rest"],
        "upload": [r"/upload", r"/file", r"/media", r"/image", r"/submit"],
        "webhooks": [r"/webhook", r"/hook", r"/notify"],
        "graphql": [r"/graphql", r"/gql"],
        "metrics": [r"/metrics", r"/stats", r"/analytics"],
        "health": [r"/health", r"/status", r"/ping", r"/alive"],
        "docs": [r"/doc", r"/swagger", r"/openapi", r"/api-docs", r"/schema"],
    }
    
    for endpoint in all_endpoints:
        categorized = False
        for category, regexes in patterns.items():
            for regex in regexes:
                if re.search(regex, endpoint, re.IGNORECASE):
                    if endpoint not in categories[category]:
                        categories[category].append(endpoint)
                    categorized = True
                    break
            if categorized:
                break
        if not categorized:
            categories["misc"].append(endpoint)
    
    # Remove empty categories
    return {k: v for k, v in categories.items() if v}


def prioritize_findings(findings: dict, config: dict) -> list[dict]:
    """
    Prioritize nuclei findings by severity and likelihood of exploitation.
    Returns sorted list of findings with priority scores.
    """
    severity_scores = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10,
    }
    
    scored_findings = []
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        score = severity_scores.get(severity, 0)
        
        # Boost score for specific template types
        template = finding.get("template", "").lower()
        if "cve" in template:
            score += 20
        elif "auth" in template or "authentication" in template:
            score += 15
        elif "rce" in template or "command" in template:
            score += 15
        elif "sqli" in template or "injection" in template:
            score += 10
        
        scored_findings.append({
            **finding,
            "priority_score": score
        })
    
    return sorted(scored_findings, key=lambda x: x["priority_score"], reverse=True)


def generate_attack_surface_summary(data: dict) -> dict:
    """
    Generate a comprehensive attack surface summary.
    """
    summary = {
        "target": data.get("target"),
        "mode": data.get("mode"),
        "timestamp": data.get("timestamp"),
        
        "discovery_summary": {
            "subdomains": {
                "total": len(data.get("subdomains", [])),
                "resolved": len(data.get("dns_records", [])),
            },
            "http_services": {
                "live_hosts": len(set(r.get("host") for r in data.get("httpx_probes", []))),
                "status_codes": _count_status_codes(data.get("httpx_probes", [])),
                "technologies": _extract_technologies(data.get("httpx_probes", [])),
            },
            "urls": {
                "live": len(data.get("live_urls", [])),
                "historical": len(data.get("historical_urls", [])),
                "unique_paths": len(set(_extract_paths(data.get("live_urls", [])))),
                "unique_params": len(_extract_parameters(data.get("live_urls", []))),
            },
            "javascript": {
                "files": len(data.get("js_files", [])),
                "endpoints": len(data.get("js_endpoints", [])),
                "source_maps": len(data.get("source_maps", [])),
            },
            "content_discovery": {
                "directories": len(data.get("content_discovery_results", [])),
            },
            "network": {
                "open_ports": len(data.get("open_ports", [])),
                "services": len(set(p.get("service", "") for p in data.get("open_ports", []))),
            }
        },
        
        "vulnerabilities": {
            "critical": len([f for f in data.get("nuclei_findings", []) if f.get("severity") == "critical"]),
            "high": len([f for f in data.get("nuclei_findings", []) if f.get("severity") == "high"]),
            "medium": len([f for f in data.get("nuclei_findings", []) if f.get("severity") == "medium"]),
            "low": len([f for f in data.get("nuclei_findings", []) if f.get("severity") == "low"]),
            "info": len([f for f in data.get("nuclei_findings", []) if f.get("severity") == "info"]),
        },
        
        "interesting_findings": _extract_interesting_items(data),
    }
    
    return summary


def _count_status_codes(probes: list[dict]) -> dict:
    """Count HTTP status codes from httpx probes."""
    counts = {}
    for probe in probes:
        status = probe.get("status_code")
        if status:
            counts[str(status)] = counts.get(str(status), 0) + 1
    return counts


def _extract_technologies(probes: list[dict]) -> list[str]:
    """Extract unique technologies from httpx probes."""
    techs = set()
    for probe in probes:
        if probe.get("technology"):
            techs.update(probe.get("technology", []))
    return sorted(list(techs))


def _extract_paths(urls: list[str]) -> list[str]:
    """Extract unique paths from URLs."""
    from urllib.parse import urlparse
    paths = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
            paths.add(path)
        except Exception:
            pass
    return list(paths)


def _extract_parameters(urls: list[str]) -> set[str]:
    """Extract unique parameter names from URLs."""
    from urllib.parse import urlparse, parse_qs
    params = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.query:
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                params.update(query_params.keys())
        except Exception:
            pass
    return params


def _extract_interesting_items(data: dict) -> dict:
    """Extract interesting items for attack surface."""
    interesting = {
        "authentication_endpoints": [],
        "api_endpoints": [],
        "admin_paths": [],
        "upload_endpoints": [],
        "graphql": [],
        "exposed_documentation": [],
        "unusual_status_codes": [],
        "interesting_technologies": [],
    }
    
    # Find auth endpoints
    for url in data.get("live_urls", []):
        if any(x in url.lower() for x in ["/auth", "/login", "/signin", "/oauth"]):
            interesting["authentication_endpoints"].append(url)
    
    # Find API endpoints
    api_endpoints = data.get("api_endpoints", {})
    for host, endpoints in api_endpoints.items():
        for ep in endpoints:
            interesting["api_endpoints"].append(f"{host}{ep}")
    
    # Find admin paths
    for url in data.get("live_urls", []):
        if any(x in url.lower() for x in ["/admin", "/manager", "/control", "/dashboard"]):
            interesting["admin_paths"].append(url)
    
    # Find GraphQL
    for url in data.get("live_urls", []):
        if "/graphql" in url.lower():
            interesting["graphql"].append(url)
    
    # Find upload endpoints
    for url in data.get("live_urls", []):
        if any(x in url.lower() for x in ["/upload", "/file", "/media", "/image"]):
            interesting["upload_endpoints"].append(url)
    
    # Remove duplicates and empty lists
    interesting = {k: list(set(v)) for k, v in interesting.items() if v}
    
    return interesting


def write_prioritized_report(run_dir: Path, summary: dict) -> Path:
    """
    Write a prioritized, human-readable attack surface report.
    """
    report_path = run_dir / "attack_surface_report.md"
    
    lines = [
        f"# Attack Surface Report: {summary['target']}",
        f"\n**Mode:** {summary['mode']}",
        f"\n**Timestamp:** {summary['timestamp']}",
        "\n## Discovery Summary\n",
    ]
    
    # Subdomains
    ds = summary.get("discovery_summary", {})
    lines.append(f"### Subdomains")
    lines.append(f"- Total discovered: {ds.get('subdomains', {}).get('total', 0)}")
    lines.append(f"- Resolved: {ds.get('subdomains', {}).get('resolved', 0)}\n")
    
    # HTTP Services
    lines.append(f"### HTTP Services")
    lines.append(f"- Live hosts: {ds.get('http_services', {}).get('live_hosts', 0)}")
    status_codes = ds.get('http_services', {}).get('status_codes', {})
    if status_codes:
        lines.append(f"- Status codes: {', '.join(f'{k}:{v}' for k, v in sorted(status_codes.items()))}")
    lines.append("")
    
    # URLs
    lines.append(f"### URL Discovery")
    lines.append(f"- Live URLs: {ds.get('urls', {}).get('live', 0)}")
    lines.append(f"- Historical URLs: {ds.get('urls', {}).get('historical', 0)}")
    lines.append(f"- Unique paths: {ds.get('urls', {}).get('unique_paths', 0)}")
    lines.append(f"- Unique parameters: {ds.get('urls', {}).get('unique_params', 0)}\n")
    
    # JavaScript
    lines.append(f"### JavaScript Analysis")
    lines.append(f"- Files discovered: {ds.get('javascript', {}).get('files', 0)}")
    lines.append(f"- Endpoints extracted: {ds.get('javascript', {}).get('endpoints', 0)}")
    lines.append(f"- Source maps found: {ds.get('javascript', {}).get('source_maps', 0)}\n")
    
    # Vulnerabilities
    lines.append(f"## Vulnerabilities\n")
    vulns = summary.get("vulnerabilities", {})
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = vulns.get(severity, 0)
        if count > 0:
            lines.append(f"- **{severity.upper()}**: {count}")
    lines.append("")
    
    # Interesting findings
    lines.append(f"## Interesting Attack Surface Items\n")
    interesting = summary.get("interesting_findings", {})
    for category, items in interesting.items():
        if items:
            lines.append(f"### {category.replace('_', ' ').title()}")
            for item in items[:10]:  # Limit to 10 per category
                lines.append(f"- {item}")
            lines.append("")
    
    report_path.write_text("\n".join(lines))
    return report_path
