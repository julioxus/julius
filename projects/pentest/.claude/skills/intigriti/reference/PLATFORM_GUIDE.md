# Intigriti Platform Guide

## Platform Overview

Intigriti is a European bug bounty platform (headquartered in Belgium) with managed triage. All submissions are triaged by Intigriti's in-house security team before reaching the program owner.

## Triage Model

### Managed Triage (Key Difference from HackerOne)

1. **Researcher submits** → Intigriti triage team reviews
2. **Triage team validates** → Reproduces PoC, assigns severity
3. **Program owner notified** → Reviews triaged finding
4. **Resolution** → Fix verified, bounty awarded

**Advantages**: Professional triage reduces noise, consistent severity ratings
**Implications**: Reports must be high-quality (triage team will reject incomplete reports)

## Report Statuses

| Status | Description |
|--------|-------------|
| New | Submitted, awaiting triage |
| Triaged | Validated by Intigriti team |
| Accepted | Confirmed by program owner |
| Closed (Resolved) | Fixed and verified |
| Closed (Duplicate) | Previously reported |
| Closed (Informational) | Valid but no security impact |
| Closed (Out of Scope) | Not in program scope |

## Severity Levels

Intigriti uses CVSS v3.1 and v4.0:

| Severity | CVSS v3.1 | Typical Bounty (Tier 1) |
|----------|-----------|------------------------|
| Critical | 9.0-10.0 | EUR 5,000-50,000+ |
| High | 7.0-8.9 | EUR 2,000-10,000 |
| Medium | 4.0-6.9 | EUR 500-3,000 |
| Low | 0.1-3.9 | EUR 100-1,000 |

## Bounty Tiers

Programs assign domains to tiers (1-5):

| Tier | Priority | Bounty Multiplier |
|------|----------|-------------------|
| Tier 1 | Highest | 1.0x (full bounty) |
| Tier 2 | High | ~0.75x |
| Tier 3 | Medium | ~0.5x |
| Tier 4 | Low | ~0.25x |
| Tier 5 | Lowest | ~0.1x or hall of fame only |

**Strategy**: Focus testing on Tier 1 assets for maximum bounty return.

## Vulnerability Type Taxonomy

Intigriti requires selecting a vulnerability type from their taxonomy:

### Web Application

- Cross-Site Scripting (XSS) — Reflected, Stored, DOM
- SQL Injection
- Server-Side Request Forgery (SSRF)
- Remote Code Execution (RCE)
- XML External Entity (XXE)
- Insecure Direct Object Reference (IDOR)
- Cross-Site Request Forgery (CSRF)
- Authentication Bypass
- Authorization/Access Control
- Information Disclosure
- Open Redirect
- Server-Side Template Injection (SSTI)
- Business Logic Flaw
- Race Condition

### Infrastructure

- Subdomain Takeover
- DNS Misconfiguration
- SSL/TLS Misconfiguration

### Mobile

- Insecure Data Storage
- Insecure Communication
- Authentication Bypass

## Report Format Requirements

### Title

- Descriptive vulnerability type + affected component
- Do NOT include URLs in the title
- Good: "Stored XSS in User Profile Bio Field"
- Bad: "XSS on https://example.com/profile"

### Domain Field

- Must be an in-scope domain from the program
- Select from the program's domain list

### Description

- Markdown formatted
- Clear explanation of the vulnerability
- Technical details and root cause analysis

### Steps to Reproduce

- Numbered steps
- Include exact URLs, parameters, payloads
- Reproducible by someone with no prior context

### Impact

- Realistic attack scenario
- Business impact (data exposure, account takeover, etc.)
- Affected users/data scope

## Common Rejection Reasons

| Reason | Prevention |
|--------|-----------|
| Out of Scope | Verify domain is in program scope with correct tier |
| Cannot Reproduce | Include working PoC, test before submitting |
| Duplicate | Search for disclosed reports, submit quickly |
| Informational | Demonstrate real security impact |
| Insufficient Impact | Show realistic attack scenario, not theoretical |
| Low Quality | Follow report format, include all required fields |
| WAF Bypass Only | WAF bypass alone is typically rated Low |

## API Authentication

- OAuth 2.0 Bearer token
- Obtain from Intigriti account settings
- Header: `Authorization: Bearer <token>`
- Base URL: `https://api.intigriti.com/core/researcher/`
