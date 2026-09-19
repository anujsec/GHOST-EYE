#!/usr/bin/env python3
"""
recon.py — entrypoint for GHOST-EYE, a fast, parallel, delta-first recon
framework.

    python recon.py                          interactive target + mode prompt
    python recon.py example.com              fast mode
    python recon.py --target example.com     same, explicit flag
    python recon.py example.com --deep       deep mode
    python recon.py example.com --screenshots
    python recon.py example.com --no-nuclei
    python recon.py example.com --bruteforce

Only ever point this at scope you are explicitly authorized to test.

Author: @anujsec
"""

import argparse
import logging
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from core.target import normalize_target, derive_org, InvalidTargetError
from core.pipeline import run_pipeline, merge_defaults
from core import ui

try:
    from rich.console import Console
    from rich.logging import RichHandler
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

VERSION = "2.0"
console = Console(highlight=False) if HAVE_RICH else None

if HAVE_RICH:
    logging.basicConfig(level=logging.WARNING, format="%(message)s", datefmt="[%X]",
                        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)])
else:
    logging.basicConfig(level=logging.WARNING,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("recon")


def load_config(path: str | Path) -> dict:
    """
    v1 bug: `-c/--config` was parsed and then thrown away — main() called
    merge_defaults({}) unconditionally, so config.yaml was never read and
    webhooks / wordlists / resolvers / concurrency overrides silently did
    nothing. This actually loads it.
    """
    p = Path(path)
    if not p.is_absolute():
        p = BASE_DIR / p
    if not p.exists():
        return {}
    try:
        import yaml
    except ImportError:
        log.warning("PyYAML not installed — ignoring %s and using defaults", p.name)
        return {}
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            log.warning("%s is not a YAML mapping — ignoring it", p.name)
            return {}
        return data
    except Exception as e:
        log.warning("could not parse %s (%s) — using defaults", p.name, e)
        return {}


def build_arg_parser():
    ap = argparse.ArgumentParser(
        prog="recon.py",
        description="GHOST-EYE — silent, parallel, delta-first recon framework (@anujsec)",
    )
    ap.add_argument("target_positional", nargs="?", help="target domain, e.g. example.com")
    ap.add_argument("-t", "--target", dest="target_flag", help="target domain")
    ap.add_argument("-o", "--org", help="override the auto-derived org label")
    ap.add_argument("--deep", action="store_true", help="expensive pivots, brute force, wider nuclei tags")
    ap.add_argument("--screenshots", action="store_true", help="capture screenshots of live hosts")
    ap.add_argument("--no-nuclei", action="store_true", help="skip nuclei scanning")
    ap.add_argument("--bruteforce", action="store_true", help="DNS brute force without full --deep")
    ap.add_argument("-c", "--config", default="config.yaml", help="path to config YAML")
    ap.add_argument("-y", "--yes", action="store_true", help="non-interactive: never prompt, fail fast")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    ap.add_argument("--no-banner", action="store_true", help="suppress the banner")
    ap.add_argument("--version", action="version", version=f"GHOST-EYE {VERSION}")
    return ap


def prompt_mode() -> bool:
    """README advertised an interactive mode prompt; v1 never implemented one."""
    try:
        answer = input("Scan profile — [f]ast (default) or [d]eep? ").strip().lower()
    except EOFError:
        return False
    return answer.startswith("d")


def main():
    args = build_arg_parser().parse_args()

    if args.verbose:
        logging.getLogger("recon").setLevel(logging.DEBUG)

    if not args.no_banner:
        ui.banner(version=VERSION, console=console)

    target_raw = args.target_flag or args.target_positional
    deep = args.deep

    if not target_raw:
        if args.yes:
            log.error("no target provided and --yes was passed (nothing can answer a prompt)")
            sys.exit(2)
        try:
            target_raw = input("Enter target domain (e.g. example.com): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(130)
        if not deep:
            deep = prompt_mode()

    try:
        target = normalize_target(target_raw)
    except InvalidTargetError as e:
        log.error("invalid target: %s", e)
        sys.exit(2)

    org = args.org or derive_org(target)
    mode_str = "deep" if deep else "fast"

    flags = [f for f, on in (("screenshots", args.screenshots),
                             ("bruteforce", args.bruteforce),
                             ("no-nuclei", args.no_nuclei)) if on]
    ui.run_header(console, target=target, org=org, mode=mode_str, flags=flags)

    cfg = merge_defaults(load_config(args.config))

    warnings: list[str] = []
    started = time.monotonic()
    reporter = ui.GhostEyeReporter(target=target, mode=mode_str, console=console)

    try:
        with reporter:
            summary = run_pipeline(
                target=target,
                org=org,
                cfg=cfg,
                base_dir=BASE_DIR,
                reporter=reporter,
                deep=deep,
                screenshots=args.screenshots,
                no_nuclei=args.no_nuclei,
                bruteforce=args.bruteforce,
                warnings=warnings,
            )
    except KeyboardInterrupt:
        elapsed = time.monotonic() - started
        msg = f"interrupted after {elapsed:.1f}s — partial results are in runs/{org}/"
        if HAVE_RICH:
            console.print(f"\n[bold {ui.C.BAD}]aborted[/] [{ui.C.MUTED}]{msg}[/]\n")
        else:
            print(f"\naborted — {msg}\n")
        sys.exit(130)
    except Exception as e:
        log.exception("pipeline failed: %s", e)
        sys.exit(1)

    # warnings the pipeline accumulated (missing binaries, degraded steps) are
    # surfaced in the final panel instead of scrolling off the top of the term
    summary.setdefault("warnings", warnings)
    ui.summary_report(console, summary, reporter)

    # non-zero-ish exit signal for CI: 0 clean, 0 with warnings is still fine,
    # only a hard failure above exits non-zero.
    sys.exit(0)


if __name__ == "__main__":
    main()
