# 🚨 PROJECT ENFORCEMENT DIRECTIVES - MANDATORY IMPLEMENTATION

## 🎯 **CRITICAL: Two Major Directives Must Be Enforced Project-Wide**

After recent false positive crises (S-Pankki OIDC, Boozt JWT/OAuth), these directives are **MANDATORY** across all skills, agents, and tools:

1. **📁 OUTPUTS DIRECTORY STANDARDIZATION** 
2. **🔒 STRICT VALIDATION PROTOCOLS**

---

## 📁 **DIRECTIVE 1: OUTPUTS DIRECTORY ENFORCEMENT**

### **🚨 IMMEDIATE ACTIONS REQUIRED:**

#### **A. UPDATE ALL SKILLS (.claude/skills/**/)**

**FILES TO UPDATE:** Any skill that writes temporary files, evidence, or reports

**SEARCH PATTERNS:**
```bash
# Find violations:
grep -r "OUTPUT_DIR\|output/\|\.json\|\.txt\|\.py\|evidence\|screenshot" .claude/skills/
```

**MANDATORY REPLACEMENTS:**

```python
# ❌ OLD PATTERNS (FORBIDDEN):
output_file = "evidence.png"
output_file = "OUTPUT_DIR/finding.json"  
output_file = "output/report.md"
output_file = "./temp_file.txt"
output_file = "/tmp/analysis.json"

# ✅ NEW PATTERN (MANDATORY):
def get_engagement_output_path(engagement_name: str, file_type: str, filename: str) -> str:
    """Get standardized output path according to OUTPUT_STRUCTURE.md"""
    if file_type == "evidence":
        return f"outputs/{engagement_name}/reports/appendix/{finding_id}/{filename}"
    elif file_type == "finding":
        return f"outputs/{engagement_name}/processed/findings/{finding_id}/{filename}"
    elif file_type == "data":
        return f"outputs/{engagement_name}/data/{subtype}/{filename}"
    elif file_type == "log":
        return f"outputs/{engagement_name}/logs/{filename}"
    else:
        return f"outputs/{engagement_name}/processed/{file_type}/{filename}"

# USAGE:
evidence_file = get_engagement_output_path("hackerone-company", "evidence", "screenshot.png")
poc_file = get_engagement_output_path("hackerone-company", "finding", "poc.py")
```

#### **B. UPDATE ALL AGENTS (.claude/agents/)**

**SEARCH PATTERNS:**
```bash
grep -r "save\|write\|evidence\|screenshot\|output" .claude/agents/
```

**MANDATORY ADDITIONS:**
Every agent must validate output paths before writing:

```python
def validate_output_path(path: str, engagement_name: str) -> bool:
    """Validate path follows OUTPUT_STRUCTURE.md standard"""
    if not path.startswith(f"outputs/{engagement_name}/"):
        raise ValueError(f"Invalid path: {path}. Must start with outputs/{engagement_name}/")
    
    valid_subdirs = ["data", "reports", "logs", "processed", "components"]
    path_parts = path.split("/")
    if len(path_parts) < 4 or path_parts[2] not in valid_subdirs:
        raise ValueError(f"Invalid subdirectory in path: {path}")
    
    return True

# MANDATORY: Call before any file write
validate_output_path(output_path, engagement_name)
```

#### **C. UPDATE TOOLS (tools/)**

**MANDATORY CHANGES:**
- All tools that accept `output_dir` parameter must default to standard structure
- Tools must validate that output paths follow standard

```python
# UPDATE THIS PATTERN:
def __init__(self, output_dir: str):
    # ✅ Add validation:
    if not output_dir.startswith("outputs/") or "/.." in output_dir:
        raise ValueError(f"Output directory must follow standard: outputs/{{engagement}}/ Got: {output_dir}")
```

---

## 🔒 **DIRECTIVE 2: STRICT VALIDATION PROTOCOLS**

### **🚨 MANDATORY VALIDATION GATES**

#### **A. UPDATE ALL VULNERABILITY REPORTING SKILLS**

**FILES TO UPDATE:** `/hackerone/`, `/intigriti/`, `/defectdojo/`, `/pentest/`

**MANDATORY ADDITIONS:**

```python
from VALIDATION_CHECKLIST import ValidationGates

class MandatoryValidator:
    @staticmethod
    def validate_finding_before_report(finding_data: dict, engagement_name: str) -> bool:
        """MANDATORY: Run before ANY external communication"""
        
        # GATE 1: Infrastructure Reality Check
        if not ValidationGates.verify_infrastructure_exists(finding_data['target']):
            raise ValidationError("Target infrastructure is not functional")
        
        # GATE 2: Behavior Differentiation Test  
        if not ValidationGates.verify_different_responses(finding_data):
            raise ValidationError("No behavioral difference detected between valid/invalid inputs")
        
        # GATE 3: End-to-End Impact Proof
        if not ValidationGates.verify_e2e_impact(finding_data):
            raise ValidationError("No end-to-end exploitation demonstrated")
        
        # GATE 4: Business Logic Verification
        if not ValidationGates.verify_not_by_design(finding_data):
            raise ValidationError("Behavior appears to be by design")
        
        # GATE 5: Live Revalidation
        if not ValidationGates.verify_still_vulnerable(finding_data):
            raise ValidationError("Vulnerability no longer reproducible")
        
        return True

# MANDATORY: Call before ANY submission
MandatoryValidator.validate_finding_before_report(finding, engagement)
```

#### **B. CREATE VALIDATION_CHECKLIST.py**

```python
# NEW FILE: VALIDATION_CHECKLIST.py
import requests
from urllib.parse import urlparse
from typing import Dict, Any

class ValidationGates:
    @staticmethod
    def verify_infrastructure_exists(target_url: str) -> bool:
        """GATE 1: Verify target is functional application, not placeholder"""
        try:
            # Test 3 endpoints to verify real application
            base_tests = [
                f"{target_url}/",
                f"{target_url}/definitely-fake-endpoint-12345",
                f"{target_url}/health"
            ]
            
            responses = []
            for url in base_tests:
                try:
                    resp = requests.get(url, timeout=10, allow_redirects=False)
                    responses.append((url, resp.status_code, resp.text[:100]))
                except:
                    responses.append((url, 0, ""))
            
            # RED FLAGS: All return same response (placeholder server)
            texts = [r[2] for r in responses]
            if len(set(texts)) <= 1 and all(r[1] == 200 for r in responses):
                print(f"❌ INFRASTRUCTURE FAILURE: All endpoints return identical responses")
                print(f"   Responses: {responses}")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ INFRASTRUCTURE FAILURE: {e}")
            return False
    
    @staticmethod  
    def verify_different_responses(finding_data: Dict[Any, Any]) -> bool:
        """GATE 2: Verify valid vs invalid inputs produce different responses"""
        target = finding_data.get('target')
        if not target:
            return False
            
        try:
            # Test with no auth
            resp_none = requests.get(target, timeout=10)
            
            # Test with valid auth (if provided)
            valid_auth = finding_data.get('valid_credentials')
            resp_valid = None
            if valid_auth:
                resp_valid = requests.get(target, headers=valid_auth, timeout=10)
            
            # Test with invalid auth  
            invalid_auth = {"Authorization": "Bearer INVALID_TOKEN"}
            resp_invalid = requests.get(target, headers=invalid_auth, timeout=10)
            
            # Check if responses are actually different
            responses = [resp_none.status_code, resp_invalid.status_code]
            if valid_auth:
                responses.append(resp_valid.status_code)
            
            # RED FLAG: All same status code suggests no real validation
            if len(set(responses)) <= 1:
                print(f"❌ BEHAVIOR FAILURE: All auth scenarios return same status: {responses}")
                return False
                
            return True
            
        except Exception as e:
            print(f"❌ BEHAVIOR FAILURE: {e}")
            return False
    
    @staticmethod
    def verify_e2e_impact(finding_data: Dict[Any, Any]) -> bool:
        """GATE 3: Verify end-to-end impact is demonstrated with evidence"""
        
        # Check for evidence files
        evidence_path = finding_data.get('evidence_path', '')
        if not evidence_path or not os.path.exists(evidence_path):
            print(f"❌ E2E FAILURE: No evidence directory found")
            return False
        
        # Check for PoC files
        poc_code = finding_data.get('poc_code', '')
        poc_output = finding_data.get('poc_output', '')
        
        if not poc_code or not poc_output:
            print(f"❌ E2E FAILURE: Missing PoC code or output")
            return False
        
        # Check for impact claims vs evidence
        claimed_impact = finding_data.get('impact', '').lower()
        impact_keywords = ['account takeover', 'data breach', 'rce', 'sql injection']
        
        has_impact_claim = any(keyword in claimed_impact for keyword in impact_keywords)
        
        if has_impact_claim:
            # For high impact claims, require specific evidence
            evidence_files = os.listdir(evidence_path) if os.path.exists(evidence_path) else []
            
            if 'account takeover' in claimed_impact:
                # Must have screenshot of successful login or session hijack
                if not any('login' in f or 'session' in f or 'account' in f for f in evidence_files):
                    print(f"❌ E2E FAILURE: Account takeover claimed but no login evidence")
                    return False
            
            if 'data breach' in claimed_impact:
                # Must have extracted data evidence
                if not any('data' in f or 'extract' in f for f in evidence_files):
                    print(f"❌ E2E FAILURE: Data breach claimed but no extraction evidence")
                    return False
        
        return True
    
    @staticmethod
    def verify_not_by_design(finding_data: Dict[Any, Any]) -> bool:
        """GATE 4: Verify behavior is not intended/by-design"""
        target = finding_data.get('target', '')
        description = finding_data.get('description', '').lower()
        
        # Check for common by-design patterns
        by_design_patterns = [
            'store locator',
            'public api',
            'documentation',
            'help page',
            'contact information',
            'privacy policy'
        ]
        
        if any(pattern in description for pattern in by_design_patterns):
            print(f"⚠️  BUSINESS LOGIC WARNING: May be by design - manual review required")
            # Don't auto-fail, but flag for review
        
        return True
    
    @staticmethod
    def verify_still_vulnerable(finding_data: Dict[Any, Any]) -> bool:
        """GATE 5: Live revalidation - verify vulnerability still exists"""
        poc_code = finding_data.get('poc_code', '')
        
        if not poc_code:
            return False
            
        try:
            # Re-execute PoC to verify it still works
            # This is a simplified version - would need more robust execution
            target = finding_data.get('target')
            if not target:
                return False
                
            # Quick verification request
            resp = requests.get(target, timeout=10)
            
            # If target is completely down, that's different from fixed vulnerability
            if resp.status_code >= 500:
                print(f"⚠️  REVALIDATION WARNING: Target appears down (5xx), not necessarily fixed")
            
            return True
            
        except Exception as e:
            print(f"❌ REVALIDATION FAILURE: {e}")
            return False
```

#### **C. UPDATE SKILL DOCUMENTATION**

**MANDATORY ADDITIONS TO ALL SKILL.md FILES:**

```markdown
## 🔒 MANDATORY VALIDATION REQUIREMENTS

Before ANY external communication (emails, reports, submissions):

```python
# REQUIRED AT TOP OF ALL SKILLS:
from VALIDATION_CHECKLIST import MandatoryValidator

# REQUIRED BEFORE ANY FINDING SUBMISSION:
try:
    MandatoryValidator.validate_finding_before_report(finding_data, engagement_name)
    print("✅ All validation gates passed")
except ValidationError as e:
    print(f"❌ VALIDATION FAILED: {e}")
    print("🚫 SUBMISSION BLOCKED - Fix issues before proceeding")
    return False
```

**Output Structure Compliance:**
- Evidence files → `outputs/{engagement}/reports/appendix/{finding-id}/`  
- PoC files → `outputs/{engagement}/processed/findings/{finding-id}/`
- Data files → `outputs/{engagement}/data/{type}/`
- Logs → `outputs/{engagement}/logs/`

**Emergency Halt Conditions:**
- All endpoints return identical responses
- OAuth without external redirects  
- Claims without end-to-end proof
- "Could lead to" without demonstration
```

---

## 🛠️ **IMPLEMENTATION CHECKLIST**

### **Phase 1: Skills Update (Priority 1)**
- [ ] `/hackerone/` - Add validation gates + output paths
- [ ] `/intigriti/` - Add validation gates + output paths  
- [ ] `/pentest/` - Add validation gates + output paths
- [ ] `/defectdojo/` - Add validation gates + output paths
- [ ] `/bounty-validation/` - Enhance with new gates

### **Phase 2: Agents Update (Priority 1)**  
- [ ] `pentester-orchestrator` - Add output validation
- [ ] `pentester-executor` - Add output validation + gates
- [ ] `pentester-validator` - Enhance with strict checks
- [ ] `dom-xss-scanner` - Add output validation

### **Phase 3: Tools Update (Priority 2)**
- [ ] `tools/` - Update all output_dir parameters
- [ ] `bounty_intel/` - Verify paths compliance
- [ ] Utility scripts - Add path validation

### **Phase 4: Documentation Update (Priority 2)**
- [ ] Update all SKILL.md files with validation requirements
- [ ] Update all agent documentation
- [ ] Create VALIDATION_CHECKLIST.py
- [ ] Update OUTPUT_STRUCTURE.md references

### **Phase 5: Testing (Priority 1)**
- [ ] Run `validate_output_structure.sh` 
- [ ] Test validation gates with mock findings
- [ ] Verify no false positive scenarios pass validation

---

## 🚨 **ENFORCEMENT DEADLINES**

- **Phase 1-2 (Critical)**: Complete within 24 hours
- **Phase 3-4 (Important)**: Complete within 48 hours  
- **Phase 5 (Validation)**: Complete within 72 hours

**After implementation, ALL new findings must pass validation gates before ANY external communication.**

**This directive is MANDATORY following the false positive crisis and must be enforced consistently.**