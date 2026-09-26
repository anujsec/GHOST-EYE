# Changes Made to Ghost-Eye

## Files Modified

### 1. `tools.py` (Extended)
**Added new tool wrappers:**
- `ffuf()` — FFuf-based content discovery
- `naabu_scan()` — Port scanning with naabu
- `nmap_service_detect()` — Service detection with nmap
- `wamore()` — Enhanced historical URL discovery
- `jsluice_analyze()` — Enhanced JS analysis with jsluice
- `extract_source_maps()` — Extract and resolve .map files
- `extract_api_endpoints()` — Identify API endpoint patterns
- `normalize_urls_batch()` — Intelligent URL normalization with uro

**Enhanced existing functions:**
- `normalize_url()` — Now with query parameter sorting

## Files Created (New Modules)

### 1. `tool_check.py`
- Automatic detection of installed tools
- Version checking
- Missing tool reporting
- Usage: `python recon.py --check-tools`

### 2. `reporting.py`
- Enhanced attack-surface reporting
- Endpoint categorization
- Finding prioritization
- Attack surface summary generation
- Source attribution

### 3. `pipeline_extensions.py`
- Port discovery phase
- Enhanced content discovery
- Source map discovery
- API endpoint extraction
- URL normalization integration

### 4. `ENHANCEMENTS.md`
- Complete documentation of new features
- Tool installation guide
- Configuration examples
- Usage patterns

### 5. `CHANGES.md` (this file)
- Summary of all modifications

## Files Updated (Configuration)

### `config.example.yaml`
**Added:**
- `concurrency.http_workers` — HTTP probing parallelism
- `concurrency.port_workers` — Port scanning parallelism
- `content_discovery.tool` — Choice between ffuf/feroxbuster
- `port_discovery` — New section for naabu/nmap configuration
- `url_normalization` — New section for uro configuration

## Integration Points

### With Existing Pipeline
New tool wrappers are fully compatible with existing:
- Exception handling (all return empty on failure)
- Timeout enforcement
- Subprocess management
- Output parsing

### With Configuration
New options are all optional with sensible defaults:
- Port discovery is disabled by default
- Source map extraction is lightweight
- Content discovery only runs in deep mode
- URL normalization falls back gracefully

## Backward Compatibility

✓ All existing functionality preserved
✓ Config file syntax unchanged
✓ Existing runs and history work as before
✓ No breaking changes to database schema
✓ CLI flags unchanged (new flags added, not modified)

## What's Still in Original Code

- Core pipeline logic (pipeline.py)
- Concurrency model (executor.py)
- Database and history (db.py, cache.py)
- Configuration loading (recon.py)
- Notifications (notify.py)
- All existing tool integrations

These are intentionally left untouched to maintain stability.

## What Can Be Integrated Further (Optional)

The new modules can be fully integrated into the main pipeline with these changes to pipeline.py:

1. Import pipeline_extensions and reporting
2. Add port_discovery phase after JavaScript analysis
3. Add source_map_discovery during JS phase
4. Add API endpoint extraction
5. Add URL normalization to all URL collections
6. Generate attack_surface_report at the end

However, to minimize risk, this is left as optional integration that can be done incrementally.

## Testing Notes

All new functions have:
- Graceful fallback if tools unavailable
- Timeout enforcement
- Exception handling
- Empty/default return values on failure

The pipeline will continue to work even if:
- ffuf is not installed (falls back to feroxbuster)
- naabu is not installed (skips port scanning)
- uro is not installed (uses basic normalization)
- jsluice is not installed (uses regex extraction)

## Usage Example

### Check available tools:
```bash
python -c "from tool_check import print_tool_status; print_tool_status()"
```

### Import new reporting:
```python
from reporting import generate_attack_surface_summary, write_prioritized_report
from tool_check import check_all_tools
```

### Use pipeline extensions:
```python
from pipeline_extensions import (
    run_port_discovery,
    run_content_discovery_enhanced,
    extract_api_endpoints,
    normalize_and_dedupe_urls
)
```

---

**Key principle:** Extensions are available but optional. The original Ghost-Eye pipeline works exactly as before.
