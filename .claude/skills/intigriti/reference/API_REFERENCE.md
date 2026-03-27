# Intigriti Scope Input Reference

## Overview

**Intigriti does NOT provide a public researcher API.** All scope and program data must be obtained from the program page via PDF export, browser scraping, or manual input.

## Scope Input Methods

### Method 1: PDF Export (Recommended)

1. User exports/screenshots the Intigriti program page as PDF
2. Read PDF to extract:
   - **Assets table**: name, type (Device/iOS/Android/Web), tier (1-5)
   - **Bounty table**: per-tier payout ranges by severity
   - **Rules**: out-of-scope items, special instructions
   - **Program metadata**: response SLAs, safe harbour status

### Method 2: Browser Scraping

1. User provides Intigriti program URL
2. Use Playwright MCP or browser automation to load the page
3. Extract the same data points as PDF method
4. Parse HTML tables for structured data

### Method 3: Manual Input

1. Ask user for assets via AskUserQuestion
2. Ask for program rules and exclusions
3. Build scope from responses

## Parsed Scope Format

After extraction, scope should be structured as:

```json
[
  {
    "name": "Functions dealing with vehicle access and immobilizer",
    "type": "device",
    "tier": 1,
    "description": "Vehicle security functions"
  },
  {
    "name": "1519034860",
    "type": "ios",
    "tier": 2,
    "description": "iOS app (App Store ID)"
  },
  {
    "name": "de.bmw.connected.mobile20.row",
    "type": "android",
    "tier": 2,
    "description": "Android app (Play Store package)"
  }
]
```

## Mobile Asset Identification

When parsing scope, identify mobile assets by:

| Scope Type | Platform | Identifier Format |
|------------|----------|-------------------|
| iOS | Apple | App Store numeric ID (e.g., `1519034860`) |
| Android | Google | Package name (e.g., `com.example.app`) |
| Mobile | Either | Bundle ID or store URL |

## Bounty Table Format

```json
{
  "currency": "EUR",
  "tiers": {
    "1": {"low": 500, "medium": 2000, "high": 5000, "critical": 10000, "exceptional": 15000},
    "2": {"low": 100, "medium": 500, "high": 1000, "critical": 2000, "exceptional": 5000}
  }
}
```

## Program Rules Extraction

Key fields to extract from program page:
- **Policies**: community code, T&C, disclosure rules
- **General rules**: testing constraints, product ownership requirements
- **Out of scope**: excluded vulnerability types
- **Response SLAs**: first response, triage, bounty, resolution times
- **FAQ**: credentials, special instructions
- **Safe harbour**: researcher protection status

## Vulnerability Type Taxonomy

Intigriti uses a dropdown taxonomy for vulnerability classification. Common types:

### Web Application
- Cross-Site Scripting (XSS) - Stored, Reflected, DOM
- SQL Injection
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object Reference (IDOR)
- Authentication Bypass
- Authorization Issues
- Remote Code Execution (RCE)
- Information Disclosure
- Cross-Site Request Forgery (CSRF)

### Mobile
- Insecure Data Storage
- Insecure Communication
- Insufficient Cryptography
- Client-Side Injection
- Reverse Engineering
- Code Tampering

### Infrastructure
- Subdomain Takeover
- Open Redirect (if chained)
- DNS Misconfiguration

## Submission Format

Reports are submitted manually via the Intigriti web interface. Required fields:

1. **Title**: Vulnerability description (NO URL in title)
2. **Severity**: CVSS v3.1 or v4.0 vector + score
3. **Domain**: Select affected in-scope asset
4. **Vulnerability Type**: Select from taxonomy dropdown
5. **Description**: Markdown, detailed explanation
6. **Steps to Reproduce**: Numbered, clear steps
7. **Impact**: Realistic attack scenario
8. **Attachments**: PoC files, screenshots, videos
