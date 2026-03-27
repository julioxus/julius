# CWE Mapping Reference

Vulnerability type → CWE ID mapping for DefectDojo finding creation.

## Injection

| Vulnerability | CWE | Name |
|---------------|-----|------|
| SQL Injection | 89 | SQL Injection |
| SQL Injection (Blind) | 89 | SQL Injection |
| NoSQL Injection | 943 | Improper Neutralization of Special Elements in Data Query Logic |
| Command Injection | 78 | OS Command Injection |
| SSTI | 1336 | Improper Neutralization of Special Elements Used in a Template Engine |
| XXE | 611 | Improper Restriction of XML External Entity Reference |
| LDAP Injection | 90 | LDAP Injection |
| XPath Injection | 643 | XPath Injection |
| Header Injection | 113 | Improper Neutralization of CRLF Sequences in HTTP Headers |
| CRLF Injection | 93 | Improper Neutralization of CRLF Sequences |
| Code Injection | 94 | Improper Control of Generation of Code |

## Client-Side

| Vulnerability | CWE | Name |
|---------------|-----|------|
| XSS (Reflected) | 79 | Cross-site Scripting |
| XSS (Stored) | 79 | Cross-site Scripting |
| XSS (DOM-based) | 79 | Cross-site Scripting |
| CSRF | 352 | Cross-Site Request Forgery |
| Clickjacking | 1021 | Improper Restriction of Rendered UI Layers |
| CORS Misconfiguration | 942 | Overly Permissive Cross-domain Whitelist |
| Prototype Pollution | 1321 | Improperly Controlled Modification of Object Prototype Attributes |
| Open Redirect | 601 | URL Redirection to Untrusted Site |

## Server-Side

| Vulnerability | CWE | Name |
|---------------|-----|------|
| SSRF | 918 | Server-Side Request Forgery |
| HTTP Request Smuggling | 444 | Inconsistent Interpretation of HTTP Requests |
| Path Traversal | 22 | Improper Limitation of a Pathname to a Restricted Directory |
| File Upload | 434 | Unrestricted Upload of File with Dangerous Type |
| Insecure Deserialization | 502 | Deserialization of Untrusted Data |
| Host Header Injection | 644 | Improper Neutralization of HTTP Headers for Scripting Syntax |
| IDOR | 639 | Authorization Bypass Through User-Controlled Key |
| Directory Listing | 548 | Exposure of Information Through Directory Listing |

## Authentication & Authorization

| Vulnerability | CWE | Name |
|---------------|-----|------|
| Authentication Bypass | 287 | Improper Authentication |
| Broken Access Control | 284 | Improper Access Control |
| JWT Issues | 347 | Improper Verification of Cryptographic Signature |
| OAuth Misconfiguration | 346 | Origin Validation Error |
| 2FA Bypass | 308 | Use of Single-factor Authentication |
| Password Issues | 521 | Weak Password Requirements |
| Session Fixation | 384 | Session Fixation |
| Privilege Escalation | 269 | Improper Privilege Management |
| Missing Authorization | 862 | Missing Authorization |

## API & Business Logic

| Vulnerability | CWE | Name |
|---------------|-----|------|
| GraphQL Introspection | 200 | Exposure of Sensitive Information |
| REST API Issues | 285 | Improper Authorization |
| WebSocket Issues | 1385 | Missing Origin Validation in WebSockets |
| Race Condition | 362 | Race Condition |
| Business Logic | 840 | Business Logic Errors |
| Mass Assignment | 915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| Rate Limiting | 770 | Allocation of Resources Without Limits |
| Information Disclosure | 200 | Exposure of Sensitive Information |

## Cryptography

| Vulnerability | CWE | Name |
|---------------|-----|------|
| Weak Encryption | 326 | Inadequate Encryption Strength |
| Hardcoded Credentials | 798 | Use of Hard-coded Credentials |
| Sensitive Data Exposure | 311 | Missing Encryption of Sensitive Data |
| Weak Hashing | 328 | Use of Weak Hash |

## Infrastructure

| Vulnerability | CWE | Name |
|---------------|-----|------|
| Subdomain Takeover | 669 | Incorrect Resource Transfer Between Spheres |
| DNS Misconfiguration | 350 | Reliance on Reverse DNS Resolution |
| Cloud Misconfiguration | 1032 | OWASP Top Ten 2017 Category A6 |
| Container Escape | 250 | Execution with Unnecessary Privileges |

## Usage

```python
CWE_MAP = {
    "sql_injection": 89,
    "xss": 79,
    "csrf": 352,
    "ssrf": 918,
    "idor": 639,
    "command_injection": 78,
    "path_traversal": 22,
    "file_upload": 434,
    "auth_bypass": 287,
    "broken_access_control": 284,
    # ... extend as needed
}
```
