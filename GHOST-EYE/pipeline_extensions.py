"""
Pipeline extensions for Ghost-Eye.
Additional discovery phases for deeper reconnaissance.
"""

import logging
import time
from pathlib import Path
from core.executor import run_parallel, map_parallel

import tools

log = logging.getLogger("recon.pipeline_extensions")


def run_port_discovery(targets: list[str], cfg: dict, conc: dict, reporter, timeout: int = 600) -> dict:
    """
    Port and service discovery using naabu.
    Returns dict with open ports and services.
    """
    if not cfg.get("port_discovery", {}).get("enabled"):
        return {}
    
    if not targets:
        return {}
    
    reporter.phase_start("port_discovery")
    t0 = time.monotonic()
    
    open_ports = []
    services = {}
    
    # Run naabu scan
    max_hosts = cfg["port_discovery"].get("max_hosts", 50)
    targets_to_scan = targets[:max_hosts]
    
    if targets_to_scan:
        ports = tools.naabu_scan(targets_to_scan, timeout=timeout)
        open_ports.extend(ports)
        
        # Optionally run nmap service detection on high-value targets
        if cfg["port_discovery"].get("service_detection"):
            nmap_results = tools.nmap_service_detect(targets_to_scan[:10], timeout=timeout)
            open_ports.extend(nmap_results)
    
    result = {
        "open_ports": open_ports,
        "services": services,
    }
    
    duration = time.monotonic() - t0
    reporter.phase_done("port_discovery", 
                       {"open_ports": len(open_ports)}, 
                       duration)
    
    return result


def run_content_discovery_enhanced(targets: list[str], cfg: dict, conc: dict, 
                                   reporter, wordlist: str = None, timeout: int = 600) -> set:
    """
    Enhanced content discovery using ffuf or feroxbuster.
    """
    if not cfg.get("content_discovery", {}).get("enabled"):
        return set()
    
    if not targets or not wordlist:
        return set()
    
    reporter.phase_start("content_discovery_enhanced")
    t0 = time.monotonic()
    
    max_hosts = cfg["content_discovery"].get("max_hosts", 10)
    tool_choice = cfg["content_discovery"].get("tool", "ffuf")
    targets_to_scan = targets[:max_hosts]
    
    all_results = set()
    
    if targets_to_scan:
        tasks = {}
        for target in targets_to_scan:
            if tool_choice == "ffuf":
                tasks[f"ffuf:{target}"] = lambda t=target: tools.ffuf(t, wordlist, timeout=timeout)
            else:
                tasks[f"ferox:{target}"] = lambda t=target: tools.feroxbuster(t, wordlist, timeout=timeout)
        
        results = run_parallel(tasks, max_workers=conc.get("content_workers", 5),
                              per_task_timeout=timeout + 30)
        
        for name, res in results.items():
            if res.ok:
                all_results.update(res.value or [])
    
    duration = time.monotonic() - t0
    reporter.phase_done("content_discovery_enhanced",
                       {"paths_found": len(all_results)},
                       duration)
    
    return all_results


def run_source_map_discovery(js_files: list[str], reporter) -> list[str]:
    """
    Discover and extract source maps from JavaScript files.
    """
    if not js_files:
        return []
    
    reporter.phase_start("source_map_discovery")
    t0 = time.monotonic()
    
    source_maps = tools.extract_source_maps(js_files)
    
    duration = time.monotonic() - t0
    reporter.phase_done("source_map_discovery",
                       {"source_maps_found": len(source_maps)},
                       duration)
    
    return source_maps


def extract_api_endpoints(urls: list[str]) -> dict:
    """
    Identify and group API endpoints from URLs.
    """
    return tools.extract_api_endpoints(urls)


def normalize_and_dedupe_urls(urls: list[str], cfg: dict, timeout: int = 300) -> list[str]:
    """
    Normalize and deduplicate URLs using uro if available.
    """
    if not urls:
        return []
    
    use_uro = cfg.get("url_normalization", {}).get("use_uro", True)
    if use_uro and tools.which_or_warn("uro"):
        return tools.normalize_urls_batch(urls, timeout=timeout)
    else:
        # Basic normalization
        normalized = set()
        for u in urls:
            normalized.add(tools.normalize_url(u))
        return sorted(list(normalized))
