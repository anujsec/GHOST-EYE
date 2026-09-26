"""
core/ui.py — all terminal presentation for GHOST-EYE lives here.

recon.py used to hold the banner, the reporter, and the summary table inline.
Pulling them out means:
  - pipeline.py still only ever talks to the Reporter interface (no rich import)
  - the no-rich fallback is a real fallback, not an afterthought
  - a live spinner + elapsed clock runs *during* a phase instead of the UI
    going silent for the 5 minutes subfinder is chewing on something.

Nothing here knows anything about recon; it only renders what it's handed.
"""

import sys
import threading
import time

try:
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False


# --------------------------------------------------------------------- theme

class C:
    """One place to retune the palette instead of hunting hex codes inline."""
    EYE = "#7dd3fc"
    EYE_DIM = "#38bdf8"
    ACCENT = "#a78bfa"
    OK = "#4ade80"
    WARN = "#fbbf24"
    BAD = "#f87171"
    DELTA = "#f0abfc"
    MUTED = "#64748b"


# vertical gradient down the wordmark — cold cyan at the top, violet at the base
_GRADIENT = ["#67e8f9", "#38bdf8", "#60a5fa", "#818cf8", "#a78bfa"]

_WORDMARK = r"""
 ██████  ██   ██  ██████  ███████ ████████    ███████ ██    ██ ███████
██       ██   ██ ██    ██ ██         ██       ██       ██  ██  ██
██  ███  ███████ ██    ██ ███████    ██ █████ █████     ████   █████
██   ██  ██   ██ ██    ██      ██    ██       ██         ██    ██
 ██████  ██   ██  ██████  ███████    ██       ███████    ██    ███████
""".strip("\n").split("\n")

_WORDMARK_ASCII = r"""
  ____ _   _  ___  ____ _____     _______   _______
 / ___| | | |/ _ \/ ___|_   _|   | ____\ \ / / ____|
| |  _| |_| | | | \___ \ | |     |  _|  \ V /|  _|
| |_| |  _  | |_| |___) || |     | |___  | | | |___
 \____|_| |_|\___/|____/ |_|     |_____| |_| |_____|
""".strip("\n").split("\n")

_EYE = "(⊙)"
_EYE_ASCII = "(o)"


def _unicode_ok() -> bool:
    """Windows consoles on cp1252 will hard-crash on the block characters."""
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in enc


def banner(version: str = "2.0", author: str = "anujsec", console=None):
    """Prints the GHOST-EYE wordmark. Degrades to plain ASCII without rich."""
    uni = _unicode_ok()
    art = _WORDMARK if uni else _WORDMARK_ASCII
    eye = _EYE if uni else _EYE_ASCII

    if not (HAVE_RICH and console):
        print()
        for line in art:
            print(line)
        print(f"  {eye} GHOST-EYE v{version} — silent, parallel, delta-first recon")
        print(f"      author @{author}  |  only scan what you're authorized to scan")
        print()
        return

    body = Text()
    for i, line in enumerate(art):
        body.append(line + "\n", style=f"bold {_GRADIENT[i % len(_GRADIENT)]}")

    tagline = Text()
    tagline.append(f"\n{eye} ", style=f"bold {C.EYE}")
    tagline.append("silent", style=f"bold {C.EYE}")
    tagline.append(" · ", style=C.MUTED)
    tagline.append("parallel", style=f"bold {C.ACCENT}")
    tagline.append(" · ", style=C.MUTED)
    tagline.append("delta-first", style=f"bold {C.DELTA}")
    tagline.append("  recon framework", style=C.MUTED)

    footer = Text()
    footer.append("\n  author ", style=C.MUTED)
    footer.append(f"@{author}", style=f"bold {C.OK}")
    footer.append("   engine ", style=C.MUTED)
    footer.append("bounded threadpool + TTL cache", style=C.EYE_DIM)

    console.print(
        Panel(
            Align.center(Group(body, Align.center(tagline), Align.center(footer))),
            title=f"[bold {C.EYE}]GHOST-EYE[/] [{C.MUTED}]v{version}[/]",
            subtitle=f"[{C.MUTED}]authorized scope only[/]",
            border_style=C.EYE_DIM,
            padding=(1, 4),
        )
    )


def run_header(console, target: str, org: str, mode: str, flags: list[str]):
    """The one-line 'here's what I'm about to do' strip under the banner."""
    extras = ("  " + " ".join(f"+{f}" for f in flags)) if flags else ""
    if not (HAVE_RICH and console):
        print(f"\n  target {target}  |  org {org}  |  mode {mode}{extras}\n")
        return
    t = Text()
    t.append("  target ", style=C.MUTED)
    t.append(target, style=f"bold {C.OK}")
    t.append("   org ", style=C.MUTED)
    t.append(org, style=f"bold {C.EYE}")
    t.append("   mode ", style=C.MUTED)
    t.append(mode.upper(), style=f"bold {C.WARN if mode.lower() == 'deep' else C.ACCENT}")
    for f in flags:
        t.append(f"  +{f}", style=C.DELTA)
    console.print(t)
    console.print()


# ------------------------------------------------------------------ reporter

class GhostEyeReporter:
    """
    Implements the pipeline's Reporter interface (phase_start / phase_done /
    info / warn / notify_change) with a live spinner + elapsed clock.

    The pipeline calls phase_start, then disappears into subprocesses for
    possibly minutes. A live task row means the terminal is never silent, and
    the elapsed timer makes 'is this hung or just slow' answerable at a glance.

    Also collects warnings and deltas so the final panel can replay them —
    previously they scrolled off the top and were effectively lost.
    """

    PHASE_LABELS = {
        "seed_expansion": "seed expansion",
        "subdomain_enum": "subdomain enumeration",
        "dns": "dns resolution",
        "http": "http probing",
        "url_discovery": "url discovery",
        "javascript": "javascript analysis",
        "content_discovery": "content discovery",
        "nuclei": "nuclei scanning",
    }

    def __init__(self, target: str, mode: str, console=None):
        self.target = target
        self.mode = mode
        self.console = console
        self.start_time = time.monotonic()
        self.warnings: list[str] = []
        self.deltas: list[str] = []
        self.completed: list[tuple[str, dict, float]] = []
        self._progress = None
        self._task = None
        self._current = None
        self._lock = threading.Lock()
        self._uni = _unicode_ok()

    # -- lifecycle -------------------------------------------------------

    def __enter__(self):
        if HAVE_RICH and self.console:
            self._progress = Progress(
                SpinnerColumn(spinner_name="dots" if self._uni else "line", style=C.EYE),
                TextColumn("[bold]{task.description}"),
                TextColumn("[" + C.MUTED + "]{task.fields[note]}"),
                TimeElapsedColumn(),
                console=self.console,
                transient=True,       # the live row is replaced by the done line
            )
            self._progress.start()
        return self

    def __exit__(self, *exc):
        self._stop_task()
        if self._progress:
            self._progress.stop()
            self._progress = None
        return False

    def _stop_task(self):
        with self._lock:
            if self._progress is not None and self._task is not None:
                self._progress.remove_task(self._task)
            self._task = None

    def _print(self, renderable):
        """Safe printing while a Live/Progress is active."""
        if self._progress is not None:
            self._progress.console.print(renderable)
        elif self.console is not None:
            self.console.print(renderable)
        else:
            print(renderable)

    # -- Reporter interface ---------------------------------------------

    def phase_start(self, name: str):
        label = self.PHASE_LABELS.get(name, name)
        self._current = name
        if self._progress is not None:
            self._stop_task()
            with self._lock:
                self._task = self._progress.add_task(label, note="running", total=None)
        else:
            print(f"[>] {label} ...")

    def step(self, note: str):
        """Optional finer-grained progress. Safe to call even without rich."""
        if self._progress is not None and self._task is not None:
            self._progress.update(self._task, note=note)

    def phase_done(self, name: str, counts: dict, duration: float):
        label = self.PHASE_LABELS.get(name, name)
        counts = {k: v for k, v in (counts or {}).items() if v}
        self.completed.append((label, counts, duration))
        self._stop_task()
        self._current = None

        tick = "✔" if self._uni else "+"
        if not (HAVE_RICH and self.console):
            extra = "  ".join(f"{k}={v}" for k, v in counts.items())
            print(f"[{tick}] {label}  ({duration:.1f}s)  {extra}")
            return

        line = Text()
        line.append(f"  {tick} ", style=f"bold {C.OK}")
        line.append(f"{label:<22}", style="bold white")
        line.append(f"{duration:>7.1f}s  ", style=C.MUTED)
        for k, v in counts.items():
            line.append(f"{k} ", style=C.MUTED)
            line.append(f"{v}  ", style=f"bold {C.EYE}")
        self._print(line)

    def info(self, msg: str):
        if HAVE_RICH and self.console:
            self._print(Text.assemble(("    i ", C.EYE_DIM), (str(msg), C.MUTED)))
        else:
            print(f"    i {msg}")

    def warn(self, msg: str):
        self.warnings.append(str(msg))
        if HAVE_RICH and self.console:
            self._print(Text.assemble(("    ! ", f"bold {C.WARN}"), (str(msg), C.WARN)))
        else:
            print(f"    ! {msg}")

    def notify_change(self, line: str):
        self.deltas.append(str(line))
        glyph = "Δ" if self._uni else "*"
        if HAVE_RICH and self.console:
            self._print(Text.assemble((f"    {glyph} ", f"bold {C.DELTA}"),
                                      (str(line), f"bold {C.DELTA}")))
        else:
            print(f"    {glyph} {line}")


# ------------------------------------------------------------------ summary

def _bar(fraction: float, width: int = 18) -> str:
    filled = max(0, min(width, round(fraction * width)))
    return "█" * filled + "░" * (width - filled) if _unicode_ok() else "#" * filled + "." * (width - filled)


def summary_report(console, summary: dict, reporter: GhostEyeReporter | None = None):
    """Final results table + where-the-time-went breakdown + warnings replay."""
    counts = summary.get("counts", {}) or {}
    changes = summary.get("changes", {}) or {}
    timings = summary.get("timings", {}) or {}
    warnings = summary.get("warnings", []) or []
    duration = summary.get("duration_seconds", 0.0)

    rows = [
        ("root domains", counts.get("domains", 0), None),
        ("subdomains", counts.get("subdomains", 0), changes.get("new_subdomains", 0)),
        ("live http hosts", counts.get("live_hosts", 0), changes.get("new_live_hosts", 0)),
        ("urls / endpoints", counts.get("urls", 0), changes.get("new_endpoints", 0)),
        ("js files analyzed", counts.get("js_files", 0), None),
        ("findings", counts.get("findings", 0), changes.get("new_findings", 0)),
    ]

    if not (HAVE_RICH and console):
        print("\n--- GHOST-EYE summary ---")
        for label, total, new in rows:
            delta = "" if new is None else f"  (+{new} new)"
            print(f"  {label:<20} {total}{delta}")
        print(f"\n  run dir: {summary.get('run_dir')}")
        if warnings:
            print(f"  {len(warnings)} warning(s):")
            for w in warnings[:15]:
                print(f"    ! {w}")
        print(f"  completed in {duration:.1f}s\n")
        return

    table = Table(show_header=True, header_style=f"bold {C.ACCENT}", box=None, pad_edge=False)
    table.add_column("asset", style="white", no_wrap=True)
    table.add_column("total", justify="right", style=f"bold {C.EYE}")
    table.add_column("new since last run", justify="right", style=f"bold {C.DELTA}")

    for label, total, new in rows:
        if new is None:
            table.add_row(label, str(total), f"[{C.MUTED}]—[/]")
        elif new:
            table.add_row(label, str(total), f"+{new}")
        else:
            table.add_row(label, str(total), f"[{C.MUTED}]+0[/]")

    blocks = [table]

    if timings:
        slowest = max(timings.values()) or 1.0
        t_table = Table(show_header=False, box=None, pad_edge=False)
        t_table.add_column(style=C.MUTED, no_wrap=True)
        t_table.add_column(style=C.EYE_DIM, no_wrap=True)
        t_table.add_column(justify="right", style=C.MUTED)
        for phase, secs in sorted(timings.items(), key=lambda kv: -kv[1]):
            t_table.add_row(phase, _bar(secs / slowest), f"{secs:.1f}s")
        blocks += [Text("\n  where the time went", style=f"bold {C.ACCENT}"), t_table]

    if warnings:
        w = Text("\n  degraded steps\n", style=f"bold {C.WARN}")
        for item in warnings[:12]:
            w.append(f"    ! {item}\n", style=C.WARN)
        if len(warnings) > 12:
            w.append(f"    ...and {len(warnings) - 12} more\n", style=C.MUTED)
        blocks.append(w)

    footer = Text()
    footer.append("\n  output  ", style=C.MUTED)
    footer.append(str(summary.get("run_dir", "")), style=C.EYE_DIM)
    footer.append("\n  elapsed ", style=C.MUTED)
    footer.append(f"{duration:.1f}s", style=f"bold {C.OK}")
    blocks.append(footer)

    console.print()
    console.print(Panel(
        Group(*blocks),
        title=f"[bold {C.EYE}]results[/] [{C.MUTED}]{summary.get('target')} · {str(summary.get('mode', '')).upper()}[/]",
        border_style=C.EYE_DIM,
        padding=(1, 3),
    ))
