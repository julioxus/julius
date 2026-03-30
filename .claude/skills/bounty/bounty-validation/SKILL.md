---
name: bounty-validation
description: Shared validation pipeline - PoC validation requirements, automated finding validation (anti-hallucination), pre-submission gate (OOS check, business logic verification, developer reproducibility review), AI usage compliance, and quality checklist. Referenced by /intigriti, /hackerone, and /defectdojo.
---

# Bug Bounty Validation Pipeline

Shared validation, compliance, and quality logic for security testing platforms. Invoked by `/intigriti` and `/hackerone` after testing completes. Also available to `/defectdojo` for finding quality assurance before upload.

## PoC Validation (CRITICAL)

**Every finding MUST have**:
1. `poc.py` - Executable exploit script
2. `poc_output.txt` - Timestamped execution proof
3. `workflow.md` - Manual steps (if applicable)
4. `evidence/` directory with real captured evidence (see Visual Evidence Standard below)

## Visual Evidence Standard (MANDATORY)

All evidence MUST be captured from real interactions — never simulated, reconstructed, or mocked.

**Browser-renderable vulnerabilities** (XSS, CSRF, open redirect, clickjacking, DOM manipulation, auth bypass with UI):
- **PRIMARY**: Browser screenshot via Playwright MCP (`playwright_screenshot`) showing the exploit firing (alert popup, redirect, DOM change, unauthorized access)
- **SUPPLEMENTARY**: Raw HTTP request/response logs as text files
- A finding with only terminal output for a browser-renderable vuln = **REJECTED at validation gate**

**Server-side vulnerabilities** (SSRF, race conditions, blind injection, command injection, deserialization):
- **PRIMARY**: Real `curl` command output (copy-pasteable command + actual response), Burp Collaborator interaction proof, or direct tool output
- **SUPPLEMENTARY**: Playwright screenshot of the Collaborator/webhook showing the OOB callback
- All commands must be real, executed, and show actual timestamps

**What counts as valid evidence**:
- Playwright screenshots (browser rendering of exploit result)
- `curl -v` output (real request + response with headers)
- Burp Suite HTTP history exports (via MCP)
- Burp Collaborator interaction logs
- Tool output (nmap, nuclei, sqlmap, ffuf) — raw, not summarized
- Logcat/Frida output from real device/emulator (with timestamps)

**What is NEVER valid evidence**:
- Simulated terminal output (text formatted to look like a terminal)
- Reconstructed HTTP responses (written from memory, not captured)
- Generic screenshots from documentation or tutorials
- Placeholder images or diagrams
- AI-generated mock responses
- Screenshots of code editors showing "what would happen"

**Evidence file naming convention**:
```
evidence/
├── screenshot-exploit-firing.png     # Playwright browser capture
├── curl-request-response.txt         # Real curl -v output
├── burp-http-exchange.txt            # Burp MCP export
├── collaborator-interaction.png      # OOB callback proof
├── raw-source.txt                    # Raw tool output
└── video-poc.mp4                     # Screen recording (if applicable)
```

**Experimentation**: Test edge cases, verify impact, document failures.

## Automated Finding Validation (Phase 4.5 — BEFORE Pre-Submission Gate)

Deploy **`pentester-validator`** agent per finding (all in parallel) to run 5 anti-hallucination checks:

1. **CVSS consistency** — Severity label must exactly match CVSS score range (no tolerance)
2. **Evidence exists** — `poc.py`, `poc_output.txt`, `description.md`, and `evidence/` directory must all exist
3. **PoC validation** — Valid Python syntax, references target URL, output matches `poc_output.txt`
4. **Claims vs raw evidence** — Every technical claim (HTTP codes, ports, versions, CVEs, ciphers) must appear in raw scan output. One uncorroborated claim = REJECTED
5. **Log corroboration** — All 4 workflow phases (recon, experiment, test, verify) must be present with distinct timestamps. Bulk timestamps indicate fabricated verification = REJECTED

**Only VALIDATED findings proceed to the Pre-Submission Gate.** Rejected findings are logged to `false-positives/` with detailed failure reasons.

## Pre-Submission Gate (MANDATORY before reporting)

**Before submitting ANY finding, validate it passes ALL these checks:**

1. **OOS check**: Re-read the program's out-of-scope list. Is this vuln type explicitly excluded? Is the asset in scope? Check BOTH the general OOS and any platform-specific OOS (mobile/desktop).
2. **Informative likelihood gate (CRITICAL — prevents wasted submissions)**:
   The most common rejection type is "Informative" — findings that are technically true but have no exploitable impact. Before proceeding, check the finding against these patterns:
   - **Config disclosure without exploit chain**: Exposed version numbers, server paths, stack traces, internal IPs, pod names, debug info — unless chained into a working exploit, these are informative. Ask: "What can an attacker DO with this information alone?"
   - **Missing security header / best practice violation**: Missing rate limiting, weak CSP, absent HSTS, verbose errors — these are hardening recommendations, not vulnerabilities, unless you can demonstrate concrete exploitation (e.g., XSS that fires because CSP is absent).
   - **Theoretical impact only**: The report says "could lead to account takeover" or "an attacker might steal tokens" but the PoC only shows the first step. If the chain is incomplete, the triager will close as informative. **Every hop in the chain must be demonstrated.**
   - **"Defense in depth" findings**: The finding improves security posture but the current state isn't exploitable (e.g., open redirect without token theft, CORS misconfiguration without data exfiltration PoC).
   - **Input validation without downstream impact**: Server accepts invalid values but the values don't affect processing, compliance, or output. Prove the bad input propagates to cause harm.

   **Decision**: If the finding matches any pattern above and lacks a demonstrated exploit chain, STOP. Either:
   (a) Go back to `/pentest` Phase 5.5 to complete the exploit chain, or
   (b) Downgrade to a building block for future chaining — do NOT submit.

   **The test**: "If I were a triager spending 5 minutes on this, would I close it as informative?" If yes, it probably is.

   **Browser security model kill-test (MANDATORY for all web findings)**:
   Before accepting any browser-based exploit chain, verify that **every hop** survives modern browser defenses. A finding that "works" in curl but breaks in a real browser is NOT exploitable. Check:
   - **SameSite cookies**: If the attack requires cross-origin cookie sending, check the `SameSite` attribute. No attribute = defaults to `Lax` in all modern browsers (Chrome 80+, Firefox 96+, Edge 80+). `SameSite=Lax` blocks cookies on cross-origin `fetch()`, `XMLHttpRequest`, and `<img>` requests. Only top-level navigations (link clicks, form GET) send Lax cookies. If the exploit needs `credentials: 'include'` to work and cookies are Lax/missing → **EXPLOIT CHAIN BROKEN**.
   - **CORS + redirects**: If the vulnerable response is a 3xx redirect, JavaScript CANNOT read it. `fetch(url, {redirect:'manual'})` returns an opaque redirect (type: 'opaqueredirect') — headers and body are unreadable. `redirect:'follow'` follows to the new origin where a DIFFERENT CORS policy applies. `redirect:'error'` throws TypeError. A CORS misconfiguration on a 302 response has **zero practical impact** unless the attacker can trigger a non-redirect response.
   - **Opaque responses**: `no-cors` fetch mode returns opaque responses — status is always 0, body is empty, headers are inaccessible. Don't claim data exfiltration from opaque responses.
   - **COOP/COEP**: `Cross-Origin-Opener-Policy: same-origin` severs `window.opener`, blocking postMessage-based exfiltration via `window.open()`. Check if COOP is set before claiming postMessage attacks work.
   - **CSP frame-ancestors / X-Frame-Options**: If the attack requires framing the target, check these headers. Framing is blocked if `frame-ancestors` doesn't include the attacker's origin.
   - **HttpOnly cookies**: `document.cookie` cannot read HttpOnly cookies. If the claim is "steal session cookies via XSS/CORS" but cookies are HttpOnly, the cookie theft claim is false. (The attacker can still make authenticated requests and read responses if CORS allows, but cannot exfiltrate the cookie value itself.)
   - **Proxy-layer vs application-layer headers**: If security-relevant headers (CORS, CSP, HSTS) come from a proxy/WAF/CDN layer (check `x-goog-iap-generated-response`, `server: cloudflare`, `via` headers), verify whether those headers also appear on **authenticated application responses**, not just proxy error/redirect pages. A CORS header on a 302 login redirect does NOT mean the 200 authenticated response has the same CORS policy.

   **If ANY browser defense breaks the exploit chain and no bypass is demonstrated, the finding is defense-in-depth (informational) — do NOT submit as Medium/High.**
3. **Business logic verification (CRITICAL — prevents "by design" rejections)**:
   Before reporting any data exposure, information leak, or access control finding, verify it's NOT intended behavior:
   - **Understand the core service**: What does this company actually do? Search the company's website, About page, and marketing materials. If they are a people-search engine, exposing personal data IS the product. If they are a public registry, open access IS the feature.
   - **Check public documentation**: Read ToS, Privacy Policy, FAQ, API docs, and help pages. Do they describe or justify the behavior you found? Look for phrases like "publicly available information", "data provided by users", "open access".
   - **Compare with competitors**: Do similar services in the same industry expose the same data or behave the same way? If all competitors do it, it's likely an industry norm, not a vulnerability.
   - **Test the "would a customer complain?" heuristic**: If a regular user of this service saw this behavior, would they be surprised? Or is it exactly what they signed up for?
   - **Check for explicit access controls**: Is there a login wall, paywall, or robots.txt restriction that the data bypasses? If the data is freely browsable without authentication, it's likely public by design.
   - **Document your conclusion**: In the finding, explicitly state why this behavior is NOT by design. If you cannot articulate a clear reason, DO NOT report it.
   - **When in doubt, ASK the user** before reporting — a "by design" rejection wastes everyone's time and damages researcher reputation.
4. **Submission requirements check**: Does the report include everything the program requires? Read the program's submission requirements — each program has its own (e.g., role used, raw HTTP requests, affected plans, reproduction steps).
5. **Impact honesty check (CRITICAL — prevents inflated/rejected reports)**:
   - **Confirmed vs theoretical**: Does the report claim impact that was actually demonstrated? If the report says "account takeover" but only showed an IDOR read, the severity is inflated. The CVSS must reflect CONFIRMED impact, with theoretical maximum documented separately in the report body.
   - **Environment defenses factored in**: Was CVSS adjusted for real defenses? Check:
     - WAF present → is Attack Complexity set to AC:H? Were bypass attempts documented?
     - CSP blocks script execution → is XSS impact downgraded if no bypass was found?
     - Rate limiting in place → is brute-force/DoS impact realistic?
     - Auth required → is Privileges Required correct (PR:L/PR:H, not PR:N)?
     - Network segmentation → is Scope S:U unless cross-boundary was proven?
     - **SameSite=Lax cookies → does the cross-origin attack actually send cookies?** If not, the exploit chain is broken regardless of CORS/CSRF misconfigurations. This is the #1 missed defense in CORS findings.
     - **Response is a redirect (3xx) → can JS actually read the response?** Opaque redirects are unreadable. CORS on a 302 has no impact unless the same CORS appears on 200 responses.
     - **Headers from proxy vs backend → do CORS/security headers persist on authenticated responses?** Check `x-goog-iap-generated-response`, CDN-injected headers, etc.
   - **"Prove it or downgrade it" verification**: For each high-impact claim, check that evidence exists:
     - ATO claim → evidence shows actual login as victim or session hijack
     - RCE claim → evidence shows command output on target
     - Data exfil claim → evidence shows retrieved data (redacted)
     - If evidence is missing for a claim: **REJECT and send back to /pentest Phase 5.5** to either prove the claim or rewrite the finding with confirmed-only impact
   - **Mitigations documented**: Does the report acknowledge defenses that affect real-world exploitability? Reports that ignore obvious mitigations (e.g., claiming Critical SSRF when cloud metadata is blocked by IMDSv2) get rejected by triagers.
6. **Developer reproducibility review**: For EACH finding, verify:
   - All URLs in Steps to Reproduce are FULL (https://...), never relative
   - Auth method explained (how to get tokens/cookies)
   - Every command is copy-pasteable and will work as written
   - Request body/params match what was ACTUALLY tested, not guessed from code
   - Expected responses documented (status codes, body snippets)
   - All prerequisites listed as numbered steps (2nd account, specific role, etc.)
   - Category/enum values match what the server actually accepts
   - No contradictions between different sections of the report
   - Impact claims are supported by evidence (no "could steal tokens" without proof)
   - CVSS vector, score, and severity all computed and aligned
   - Evidence directory has real captured output (screenshots, HTTP logs, PoC scripts)
   - **Visual evidence enforced** (see Visual Evidence Standard): browser-renderable vulns MUST have Playwright screenshots; server-side vulns MUST have real curl/tool output. Simulated terminal output = REJECTED.
7. **Present findings to user for review**: Show a summary of each finding with severity, evidence quality, OOS risk assessment, and business logic verification result. Let the user decide which to submit.

## AI Usage Compliance (MANDATORY)

Both HackerOne and Intigriti permit AI tools but require responsible use. **Every report MUST comply:**

1. **AI Disclosure**: Add a section at the end of every report:
   ```
   ## AI Disclosure
   AI tools (Claude Code) were used to assist with [specific tasks: static analysis, script generation,
   report structuring, etc.]. The vulnerability was identified by the researcher through [method].
   All [evidence type] was [how it was obtained]. [What was NOT tested and why].
   ```

2. **No fabricated content**: NEVER include invented endpoints, placeholder URLs, generic exploit templates, or references to features/behaviors that were not actually observed in the target.

3. **All claims verified**: Every code snippet, logcat line, HTTP response, and technical detail MUST come from actual testing or analysis. If a code snippet is from decompiled source, say so. If logcat is from an emulator, say so with timestamp.

4. **Methodology transparency**: Clearly distinguish between:
   - Runtime-verified (executed on device/emulator with real output)
   - Static analysis (found in decompiled/source code but not triggered at runtime)
   - Inferred (reasonable conclusion based on code patterns but not directly confirmed)

5. **Honest CVSS & impact**: Score only confirmed impact. State mitigations and caveats upfront. Never present theoretical worst-case as confirmed impact. **ALWAYS compute CVSS scores using a calculator (Python/bash script), NEVER guess or estimate — the formulas are non-linear and guessing produces wrong scores.**

6. **No unverified escalation**: Don't claim "full account takeover" if only information leakage was demonstrated. Don't claim "remote code execution" from a code pattern without runtime proof.

**Reports that violate these rules will be closed without response and may lead to platform removal.**

## Quality Checklist

Before submission:
- [ ] Working PoC with poc_output.txt + visual evidence
- [ ] Accurate CVSS score with vector string (computed with calculator, not guessed)
- [ ] **CWE identifier included** (e.g., CWE-601 — must appear in report Type/summary field)
- [ ] Correct vulnerability type/classification
- [ ] Step-by-step reproduction + impact + remediation
- [ ] Sensitive data sanitized
- [ ] Mobile apps downloaded and analyzed (if in scope)
- [ ] **Informative likelihood gate passed**: finding has demonstrated E2E exploit chain, not just config disclosure or theoretical impact
- [ ] **Business logic verified: behavior is NOT by design** (checked company service, docs, competitors)
- [ ] **AI Disclosure section included**
- [ ] **All technical claims verified against real evidence**
- [ ] **No fabricated endpoints, placeholders, or generic templates**
- [ ] **Methodology (runtime vs static vs inferred) clearly stated**

