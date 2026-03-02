# OWASP Mobile Top 10 (2024)

## Vulnerability Categories

### M1: Improper Credential Usage

**Description**: Hardcoded credentials, insecure credential storage, weak authentication
**MobSF Detection**: Hardcoded API keys, embedded passwords, insecure SharedPreferences
**Frida Testing**: Hook credential storage APIs, intercept auth tokens at runtime
**Severity**: High-Critical
**Common Findings**:
- Hardcoded API keys in source/resources
- Credentials in SharedPreferences (Android) or UserDefaults (iOS)
- Plaintext passwords in app storage

### M2: Inadequate Supply Chain Security

**Description**: Third-party SDK vulnerabilities, malicious libraries, unverified dependencies
**MobSF Detection**: Library vulnerability scan, SDK version analysis
**Severity**: Medium-Critical
**Common Findings**:
- Outdated libraries with known CVEs
- Overprivileged SDKs (analytics, ads)

### M3: Insecure Authentication/Authorization

**Description**: Weak auth mechanisms, missing server-side validation, client-side auth bypass
**Frida Testing**: Bypass biometric auth, modify auth response, hook isAuthenticated()
**Severity**: High-Critical
**Common Findings**:
- Client-side authentication bypass
- Missing server-side session validation
- Weak biometric implementation

### M4: Insufficient Input/Output Validation

**Description**: SQL injection, XSS in WebViews, path traversal, intent injection
**MobSF Detection**: Exported components, WebView JavaScript enabled, intent filters
**Frida Testing**: Hook input validation functions, inject payloads via IPC
**Severity**: Medium-High
**Common Findings**:
- SQL injection in content providers
- XSS in WebView loadUrl()
- Intent redirection/hijacking

### M5: Insecure Communication

**Description**: Cleartext traffic, weak TLS, missing certificate pinning
**MobSF Detection**: Network security config, cleartext traffic allowed, pinning config
**Frida Testing**: SSL pinning bypass, intercept network calls
**Severity**: Medium-High
**Common Findings**:
- Missing or weak certificate pinning
- Cleartext HTTP traffic allowed
- Custom TrustManager accepting all certificates

### M6: Inadequate Privacy Controls

**Description**: PII leakage, excessive data collection, insecure data sharing
**MobSF Detection**: Permissions analysis, data sharing intents, tracking SDKs
**Severity**: Medium-High
**Common Findings**:
- Excessive permissions (location, contacts, camera)
- PII in application logs
- Data shared with third-party SDKs without consent

### M7: Insufficient Binary Protections

**Description**: Missing obfuscation, no anti-tampering, debuggable builds
**MobSF Detection**: Binary analysis (PIE, stack canary, ARC, obfuscation)
**Severity**: Low-Medium
**Common Findings**:
- Debuggable flag enabled in manifest
- No code obfuscation (ProGuard/R8)
- Missing root/jailbreak detection

### M8: Security Misconfiguration

**Description**: Default configs, debug mode, excessive permissions, insecure defaults
**MobSF Detection**: Manifest analysis, exported components, backup allowed
**Severity**: Medium-High
**Common Findings**:
- `android:allowBackup="true"`
- Exported activities/services without permission checks
- Debug logging in production

### M9: Insecure Data Storage

**Description**: Unencrypted local storage, sensitive data in logs, clipboard exposure
**MobSF Detection**: SQLite databases, file storage analysis, log analysis
**Frida Testing**: Hook file I/O, SQLite queries, clipboard access
**Severity**: Medium-High
**Common Findings**:
- Sensitive data in SQLite without encryption
- Tokens/passwords in application logs
- Cache files containing sensitive data

### M10: Insufficient Cryptography

**Description**: Weak algorithms, hardcoded keys, improper key management
**MobSF Detection**: Crypto API usage, hardcoded keys, weak algorithms (MD5, SHA1, DES)
**Frida Testing**: Hook crypto functions, extract keys at runtime
**Severity**: High
**Common Findings**:
- MD5/SHA1 for password hashing
- Hardcoded encryption keys
- ECB mode for symmetric encryption

## Severity Mapping

| OWASP Category | Typical CVSS | Bounty Impact |
|----------------|-------------|---------------|
| M1 (Credentials) | 7.0-9.0 | High-Critical |
| M3 (Auth/Authz) | 7.0-9.8 | High-Critical |
| M5 (Communication) | 5.0-7.5 | Medium-High |
| M9 (Data Storage) | 4.0-7.0 | Medium-High |
| M10 (Crypto) | 5.0-8.0 | Medium-High |
| M7 (Binary) | 2.0-4.0 | Low-Medium |
