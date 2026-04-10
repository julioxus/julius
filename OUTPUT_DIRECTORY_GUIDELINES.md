# 📁 Output Directory Guidelines - MANDATORY STANDARD

## 🎯 **CRITICAL RULE: All temporary files MUST go in `outputs/` directory**

### **✅ CORRECT Structure (ONLY use this):**

```
outputs/{engagement-name}/
├── components/                # TSX components + manifest.json
├── data/                      # JSON data files
│   ├── reconnaissance/        # domains.json, web-apps.json, apis.json, etc.
│   └── findings/             # finding-{NNN}.json (structured data)
├── reports/                   # Markdown reports, DOCX, PDF deliverables
│   ├── intermediate-reports/  # Draft reports
│   └── appendix/             # Evidence per finding (finding-{id}/)
├── logs/                      # Execution logs (NDJSON format)
└── processed/                # Optional working artifacts
    ├── reconnaissance/       # Raw tool outputs
    ├── findings/            # Detailed finding folders with PoCs
    ├── helpers/             # Testing utilities
    └── test-frameworks/     # Testing scripts
```

### **❌ FORBIDDEN Directories (NEVER use these):**

- ❌ `OUTPUT_DIR/` 
- ❌ `output/`
- ❌ `tmp/`
- ❌ Files in project root
- ❌ Random directories

---

## 📝 **Engagement Naming Convention:**

- **HackerOne programs**: `hackerone-{company}` (e.g., `hackerone-spankki`, `hackerone-boozt`)
- **Intigriti programs**: `intigriti-{company}` (e.g., `intigriti-exoscale`)
- **Custom programs**: `{platform}-{company}` (e.g., `defectdojo-573`)

---

## 🛠️ **How to Setup New Engagement:**

```bash
# Use the provided script:
./setup_engagement_structure.sh hackerone-company

# This creates the complete standard structure
```

---

## 📋 **File Organization Rules:**

### **JSON Data → `data/`**
- `data/reconnaissance/` → domains.json, web-apps.json, apis.json, network.json, cloud.json
- `data/findings/` → finding-{NNN}.json (structured data)
- `data/pentest-report.json` → Machine-readable export

### **Reports & Evidence → `reports/`**
- `reports/` → Final deliverables (DOCX, PDF, markdown)
- `reports/intermediate-reports/` → Draft reports
- `reports/appendix/{finding-id}/` → Evidence per finding (screenshots, logs)

### **Execution Logs → `logs/`**
- `logs/pentester-orchestrator.log` → NDJSON orchestrator logs
- `logs/{executor-name}.log` → Per-executor activity logs
- `logs/activity/` → Alternative location for activity logs

### **Working Files → `processed/`**
- `processed/reconnaissance/raw/` → Raw tool outputs (nmap, ffuf, ZAP)
- `processed/findings/finding-{NNN}/` → Detailed finding folders
  - `description.md`
  - `poc.py`
  - `poc_output.txt` 
  - `workflow.md`
  - `evidence/` (screenshots, HTTP logs)
- `processed/helpers/` → Testing utilities
- `processed/test-frameworks/` → Authentication frameworks

### **Components → `components/` (if needed)**
- `components/manifest.json` → Component metadata
- `components/*.tsx` → React TSX components

---

## 🚨 **MANDATORY FOR ALL SKILLS:**

### **Before writing any temporary file:**
```python
# ✅ CORRECT
engagement_dir = f"outputs/{platform}-{company}"
output_file = f"{engagement_dir}/processed/findings/finding-{id}/poc.py"

# ❌ WRONG
output_file = "tmp_poc.py"  # Root clutter
output_file = "OUTPUT_DIR/poc.py"  # Wrong directory
```

### **Evidence capture:**
```python
# ✅ CORRECT
evidence_dir = f"outputs/{engagement}/reports/appendix/finding-{id}"
screenshot = f"{evidence_dir}/screenshot-exploit.png"

# ❌ WRONG  
screenshot = "evidence/screenshot.png"  # Wrong location
```

### **Logs:**
```python
# ✅ CORRECT
log_file = f"outputs/{engagement}/logs/{agent_name}.log"

# ❌ WRONG
log_file = "agent_output.log"  # Root clutter
```

---

## 🧹 **Cleanup Rules:**

1. **Never leave files in project root** (except permanent configs)
2. **All temp files → appropriate `outputs/{engagement}/` subdirectory**
3. **Use `.gitkeep` to preserve empty directories**
4. **Remove obsolete engagement directories when closed**

---

## ✅ **Validation Checklist:**

Before any PR or commit:

- [ ] No files in project root except: README.md, CLAUDE.md, AGENTS.md, package.json, .env, .gitignore, setup scripts
- [ ] All engagement files in `outputs/{engagement}/` 
- [ ] Proper subdirectory usage (data/, reports/, logs/, processed/)
- [ ] No `OUTPUT_DIR/`, `output/`, `tmp/` directories
- [ ] Evidence files in `reports/appendix/{finding-id}/`
- [ ] PoCs in `processed/findings/{finding-id}/`

---

## 📖 **Reference:**

Full specification: `.claude/skills/pentest/coordination/reference/OUTPUT_STRUCTURE.md`

**This standard is MANDATORY and must be followed by all skills, agents, and manual workflows.**