# Container Image Scanning

## Tools

### Trivy

```bash
# Scan image for vulnerabilities
trivy image <image:tag>

# Scan with severity filter
trivy image --severity CRITICAL,HIGH <image:tag>

# Scan for secrets
trivy image --scanners secret <image:tag>

# Scan for misconfigurations
trivy image --scanners misconfig <image:tag>

# JSON output for processing
trivy image -f json -o results.json <image:tag>

# Scan filesystem (for CI/CD)
trivy fs --scanners vuln,secret /path/to/project
```

### Grype

```bash
# Scan image
grype <image:tag>

# Severity filter
grype <image:tag> --only-fixed --fail-on high

# JSON output
grype <image:tag> -o json > results.json
```

### Snyk

```bash
# Scan container image
snyk container test <image:tag>

# Monitor for new vulnerabilities
snyk container monitor <image:tag>
```

## Base Image Selection

### Security-Ranked Base Images

| Image | Size | CVE Surface | Use Case |
|-------|------|-------------|----------|
| `distroless` | ~2MB | Minimal | Production (no shell) |
| `alpine` | ~5MB | Low | General purpose |
| `ubuntu:22.04` | ~77MB | Medium | Full OS needed |
| `debian:bookworm-slim` | ~80MB | Medium | Debian ecosystem |
| `ubuntu:latest` | ~77MB | High (unpinned) | Never use in production |

### Recommendations

- **Production**: Use distroless or alpine as base
- **Pin versions**: `FROM alpine:3.19` not `FROM alpine:latest`
- **Multi-stage builds**: Build in full image, run in minimal image
- **Regular updates**: Rebuild images when base updates are available

## CVE Severity Mapping

| Scanner Level | CVSS Range | Action |
|---------------|------------|--------|
| Critical | 9.0-10.0 | Block deployment, patch immediately |
| High | 7.0-8.9 | Patch within 7 days |
| Medium | 4.0-6.9 | Patch within 30 days |
| Low | 0.1-3.9 | Patch at next cycle |
| Negligible | 0.0 | Informational only |

## Scan Integration Points

### Pre-Build (CI/CD)

```bash
# Scan Dockerfile
hadolint Dockerfile

# Scan dependencies
trivy fs --scanners vuln .
```

### Post-Build (CI/CD)

```bash
# Scan built image before push
trivy image --exit-code 1 --severity CRITICAL <image:tag>
```

### Registry Scanning

```bash
# Scan images in registry
trivy image <registry>/<image>:<tag>
```

### Runtime Scanning

```bash
# Scan running container filesystem
docker export <container-id> | trivy image --input -
```

## Output Format

```
outputs/<engagement>/inventory/
├── image-scan-<image>.json    # Full scan results
├── cve-summary.md             # CVE counts by severity
└── base-image-analysis.md     # Base image recommendations
```
