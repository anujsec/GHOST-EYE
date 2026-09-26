"""
Tool availability checker for Ghost-Eye.
Auto-detects installed recon tools and reports availability.
"""

import shutil
import subprocess
from typing import Dict, List


REQUIRED_TOOLS = [
    "subfinder",
    "httpx",
    "nuclei",
]

OPTIONAL_TOOLS = [
    "amass",
    "assetfinder",
    "dnsx",
    "katana",
    "gau",
    "waybackurls",
    "wamore",
    "ffuf",
    "feroxbuster",
    "naabu",
    "nmap",
    "gowitness",
    "alterx",
    "puredns",
    "arjun",
    "jsluice",
    "jq",
    "trufflehog",
    "uro",
]


def which(binary: str) -> bool:
    """Check if a binary is in PATH."""
    return shutil.which(binary) is not None


def check_tool_version(binary: str) -> str:
    """Try to get tool version."""
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.split("\n")[0][:60]  # First line, max 60 chars
    except Exception:
        pass
    
    # Try -version for some tools
    try:
        result = subprocess.run(
            [binary, "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.split("\n")[0][:60]
    except Exception:
        pass
    
    return "installed"


def check_all_tools() -> Dict[str, Dict]:
    """Check all tools and return availability status."""
    tools = {}
    
    for tool in REQUIRED_TOOLS + OPTIONAL_TOOLS:
        available = which(tool)
        if available:
            version = check_tool_version(tool)
            tools[tool] = {
                "available": True,
                "required": tool in REQUIRED_TOOLS,
                "version": version
            }
        else:
            tools[tool] = {
                "available": False,
                "required": tool in REQUIRED_TOOLS,
                "version": None
            }
    
    return tools


def print_tool_status():
    """Print a formatted tool availability report."""
    tools = check_all_tools()
    
    print("\n" + "="*60)
    print("GHOST-EYE Tool Status")
    print("="*60 + "\n")
    
    # Required tools
    print("REQUIRED TOOLS:")
    print("-" * 60)
    for tool in REQUIRED_TOOLS:
        info = tools[tool]
        status = "✓" if info["available"] else "✗"
        version = info["version"] or "not installed"
        print(f"  {status} {tool:<20} {version}")
    
    print("\n" + "="*60)
    print("\nOPTIONAL TOOLS (Features gracefully degrade without these):")
    print("-" * 60)
    
    available_count = 0
    for tool in OPTIONAL_TOOLS:
        info = tools[tool]
        status = "✓" if info["available"] else "✗"
        if info["available"]:
            available_count += 1
            version = info["version"] or "installed"
            print(f"  {status} {tool:<20} {version}")
    
    # Show unavailable optional tools compactly
    unavailable = [t for t in OPTIONAL_TOOLS if not tools[t]["available"]]
    if unavailable:
        print(f"\n  ✗ Missing: {', '.join(unavailable)}")
    
    print(f"\nOptional tools: {available_count}/{len(OPTIONAL_TOOLS)} available")
    print("\n" + "="*60 + "\n")
    
    return tools


def get_missing_required() -> List[str]:
    """Return list of missing required tools."""
    tools = check_all_tools()
    return [t for t in REQUIRED_TOOLS if not tools[t]["available"]]


def get_available_optional() -> List[str]:
    """Return list of available optional tools."""
    tools = check_all_tools()
    return [t for t in OPTIONAL_TOOLS if tools[t]["available"]]
