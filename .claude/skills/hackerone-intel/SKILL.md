# /hackerone-intel - HackerOne Intelligence Refresh

Refreshes the threat intelligence database from 14.5K+ disclosed HackerOne reports. Generates per-category attack intel, technique patterns, and optionally scrapes full writeups.

## Trigger
When user says: "refresh intel", "update hackerone intel", "hackerone intel", "refresh techniques", "update threat intel", "intel refresh"

## Requirements
- Python 3.8+
- Internet access (downloads CSV from GitHub)
- Playwright (optional, only for writeup scraping): `pip install playwright && playwright install chromium`

## Pipeline

### Mode: Full Refresh (default)

Runs all 3 generators sequentially.

```bash
# Step 1: Stats + top reports per category (44 hackerone-intel.md files)
python3 tools/hackerone-intel-generator.py

# Step 2: Technique extraction from titles (44 hackerone-techniques.md files)
python3 tools/hackerone-technique-extractor.py

# Step 3 (optional): Scrape top writeups via Playwright
python3 tools/hackerone-writeup-scraper.py --limit 100
```

### Mode: Quick (stats only)

```bash
python3 tools/hackerone-intel-generator.py
```

### Mode: Custom CSV

If user has a local CSV (e.g., from a private dataset):

```bash
python3 tools/hackerone-intel-generator.py --csv /path/to/data.csv
python3 tools/hackerone-technique-extractor.py --csv /path/to/data.csv
```

## What Gets Generated

| File | Location | Count | Purpose |
|------|----------|-------|---------|
| `hackerone-intel.md` | Each attack skill folder | 44 | Stats, top programs, bounty ranges, top reports |
| `hackerone-techniques.md` | Each attack skill folder | 44 | Injection points, techniques, bypasses, escalation chains |
| `hackerone-intel-index.json` | `.claude/skills/pentest/` | 1 | Program index for on-demand lookups (427 programs) |
| `top-writeups.json` | `.claude/skills/pentest/hackerone-writeups/` | 1 | Full writeups from top reports (Playwright required) |

## How It Integrates

### Executor (automatic)
The executor loads `hackerone-intel.md` at L1 (alongside quickstart) and `hackerone-techniques.md` at L3 (escalation). No manual intervention needed — files are in the skill folders.

### Orchestrator (Phase 1.5)
The orchestrator dispatches `HackerOne Intel Fetcher` agent which reads `hackerone-intel-index.json` for program-specific lookups during planning.

### Bounty Forecast
Program bounty data feeds into `/bounty-forecast` for earnings estimation.

## Execution Flow

```
User: /hackerone-intel
  │
  ├─ Ask: "Full refresh, quick, or custom CSV?"
  │
  ├─ [Full] Run all 3 scripts sequentially
  │   ├─ hackerone-intel-generator.py     → 44 intel files + program index
  │   ├─ hackerone-technique-extractor.py → 44 technique files
  │   └─ hackerone-writeup-scraper.py     → top writeups (if Playwright available)
  │
  ├─ [Quick] Run generator only
  │   └─ hackerone-intel-generator.py     → 44 intel files + program index
  │
  └─ Report: files generated, coverage %, categories updated
```

## Validation

After refresh, verify:
```bash
# Count generated files
find .claude/skills/pentest/attacks -name "hackerone-intel.md" | wc -l      # expect 44
find .claude/skills/pentest/attacks -name "hackerone-techniques.md" | wc -l  # expect 44

# Check program index
python3 -c "import json; d=json.load(open('.claude/skills/pentest/hackerone-intel-index.json')); print(f'{len(d)} programs indexed')"
```

## Source

- **Data**: [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) — updated monthly
- **14,552+ reports**, 427 programs, 194 vulnerability types
- **16,006 technique signals** extracted across 6 dimensions
