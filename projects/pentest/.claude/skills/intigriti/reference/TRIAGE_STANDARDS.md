# Intigriti Triage Standards

Based on Intigriti Triage Standards v1.3 (January 2026).

## Assessment Methods

### PoC-Based Assessment

Primary method: Triage team reproduces the PoC to validate the vulnerability.

**Requirements**:
- Working PoC that can be reproduced by a third party
- Clear steps to reproduce (no assumed knowledge)
- Evidence of impact (not just theoretical)

### Vulnerability Type Assessment

Secondary method: Severity based on vulnerability type when PoC is clear.

## CVSS Scoring

### CVSS v3.1 (Primary)

Standard CVSS v3.1 vector format:
```
CVSS:3.1/AV:[N|A|L|P]/AC:[L|H]/PR:[N|L|H]/UI:[N|R]/S:[U|C]/C:[N|L|H]/I:[N|L|H]/A:[N|L|H]
```

### CVSS v4.0 (Accepted)

Newer format also accepted:
```
CVSS:4.0/AV:[N|A|L|P]/AC:[L|H]/AT:[N|P]/PR:[N|L|H]/UI:[N|P|A]/VC:[N|L|H]/VI:[N|L|H]/VA:[N|L|H]/SC:[N|L|H]/SI:[N|L|H]/SA:[N|L|H]
```

## Valid Submission Criteria

### Must Have

- Affects in-scope domain
- Working PoC demonstrating the vulnerability
- Clear security impact
- Follows program rules
- Not a duplicate of existing submission

### Invalid Submissions

- Theoretical vulnerabilities without PoC
- Self-XSS (user can only attack themselves)
- Missing security headers without demonstrated impact
- Rate limiting absence (unless demonstrable abuse)
- Version disclosure without exploit
- SPF/DMARC misconfiguration (unless chained)

## Vulnerability-Specific Ratings

| Vulnerability | Typical Rating | Notes |
|---------------|---------------|-------|
| RCE (unauthenticated) | Critical | Full server compromise |
| SQL Injection (data access) | Critical/High | Depends on data sensitivity |
| SSRF (internal access) | High/Critical | Depends on what's reachable |
| Stored XSS | Medium/High | Depends on context (admin panel = High) |
| Reflected XSS | Medium | Requires user interaction |
| CSRF | Medium | Depends on action (state-changing) |
| IDOR | Medium/High | Depends on data accessed |
| Open Redirect | Low | Unless chained with OAuth |
| WAF Bypass | Low | Bypass alone has minimal impact |
| Clickjacking | Low | Unless on sensitive action |
| Information Disclosure | Low/Medium | Depends on data sensitivity |
| Subdomain Takeover | Medium/High | Depends on subdomain usage |

## Duplicate Handling

### Rules

- First valid submission wins
- Duplicates are closed with reference to original
- Partial duplicates: If new submission adds significant impact, may be accepted
- Different attack vectors for same underlying issue = same vulnerability

### Prevention

- Search for disclosed findings on the program
- Check Intigriti's disclosed reports
- Submit quickly after discovery
- Provide maximum detail (harder to claim as duplicate of vague report)

## Bounty Payment

### Process

1. Vulnerability validated by triage
2. Program owner confirms
3. Fix deployed and verified
4. Bounty awarded in EUR
5. Payment via bank transfer or PayPal

### Factors Affecting Bounty

- Domain tier (Tier 1 = highest)
- Vulnerability severity (CVSS score)
- Quality of report (bonus for exceptional reports)
- Impact demonstration (real-world scenario)

## Triage Timeline

| Stage | Expected Time |
|-------|---------------|
| Initial triage | 1-5 business days |
| Program owner review | 5-15 business days |
| Resolution | Varies by program |
| Bounty payment | 30 days after resolution |

## Appeals

If submission is rejected:
1. Review rejection reason carefully
2. Provide additional evidence if available
3. Respond in the submission thread
4. Triage team will re-evaluate with new information
