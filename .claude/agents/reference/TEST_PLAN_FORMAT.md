# Test Plan Format

Template for creating test plans during Phase 3 (Planning & Approval).

## Structure

```markdown
# Penetration Test Plan

## Target
- URL: https://example.com
- Engagement: example-com-2026-01
- Scope: All endpoints under /api/*, /admin/*
- Restrictions: [any OOS items, rate limits, no destructive testing]

## Reconnaissance Findings
- Login form (2 parameters: username, password)
- API endpoints: /api/users, /api/orders
- File upload: /upload/profile-picture
- Admin panel detected: /admin
- Technologies: Node.js, PostgreSQL, React

## Proposed Executors

### High Priority (Always Deploy)
- **SQL Injection Executor** → Login form, API endpoints
  - Skill: attacks/injection/sql-injection/, quickstart
- **XSS Executor** → All input fields, search functionality
  - Skill: attacks/client-side/xss/, quickstart
- **SSRF Executor** → API endpoints, webhook functionality
  - Skill: attacks/server-side/ssrf/, quickstart
- **Auth Bypass Executor** → Login form, admin panel
  - Skill: attacks/authentication/auth-bypass/, quickstart

### Attack Surface Specific
- **CSRF Executor** → State-changing forms
  - Skill: attacks/client-side/csrf/, quickstart
- **File Upload Executor** → Profile picture upload
  - Skill: attacks/server-side/file-upload/, quickstart
- **JWT Executor** → API authentication tokens
  - Skill: attacks/authentication/jwt/, quickstart
[... additional executors based on recon findings]

## Testing Approach
1. Deploy all approved executors in parallel (single Agent dispatch)
2. Each executor follows 4-phase workflow: Recon → Experiment → Test → Verify
3. Monitor progress with TaskOutput(block=False)
4. Recursive spawning: If new attack surface discovered, deploy additional executors
5. After all executors complete: deploy validators per-finding in parallel
6. Aggregate validated findings, deduplicate, escalate chains

## Estimated Resources
- Executors: N agents running in parallel (max 15 concurrent)
- Output: Activity logs + finding folders + aggregated report
```

## Critical Rules

- Always create plan after reconnaissance
- Always present plan to user for approval before deploying executors
- Map each executor to specific skill folders and escalation levels
- Include only executors justified by recon findings (no speculative testing)
- After plan approval, proceed immediately to executor deployment
