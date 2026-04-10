# Output Standards - Single Source of Truth

All temporary files, evidence, reports, and logs MUST go in `outputs/{engagement}/`.

## Directory Structure

```
outputs/{engagement-name}/
├── data/
│   ├── reconnaissance/    # domains.json, web-apps.json, apis.json
│   └── findings/          # finding-{NNN}.json (structured)
├── processed/
│   ├── reconnaissance/    # Raw tool outputs (nmap, ffuf, nuclei)
│   ├── findings/          # Detailed finding folders
│   │   └── finding-{NNN}/
│   │       ├── description.md
│   │       ├── poc.py
│   │       ├── poc_output.txt
│   │       ├── workflow.md
│   │       └── evidence/  # Screenshots, HTTP logs
│   ├── helpers/           # Testing utilities
│   └── test-frameworks/   # Auth frameworks, scripts
├── reports/
│   ├── appendix/          # Evidence per finding
│   │   └── finding-{id}/  # Screenshots, curl output
│   └── intermediate/      # Draft reports
└── logs/                  # NDJSON execution logs
```

## Engagement Naming

| Platform | Pattern | Example |
|----------|---------|---------|
| HackerOne | `hackerone-{company}` | `hackerone-boozt` |
| Intigriti | `intigriti-{company}` | `intigriti-quadcode` |
| Bugcrowd | `bugcrowd-{company}` | `bugcrowd-okta` |
| DefectDojo | `defectdojo-{id}` | `defectdojo-573` |

## Path Functions

Use `tools/validation_gates.py`:
```python
from tools.validation_gates import get_output_path
path = get_output_path("hackerone-company", "evidence", "screenshot.png", finding_id="finding-001")
```

## Forbidden

- Files in project root (except permanent configs)
- `OUTPUT_DIR/`, `output/`, `tmp/` directories
- Evidence outside `outputs/{engagement}/`
