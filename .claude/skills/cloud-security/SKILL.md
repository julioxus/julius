---
name: cloud-security
description: Cloud security assessment for AWS, Azure, and GCP environments. Orchestrates IAM review, storage enumeration, serverless analysis, network audit, metadata exploitation, and privilege escalation testing. Maps findings to CIS Benchmarks.
---

# Cloud Security Assessment

Orchestrates cloud-specific security testing across AWS, Azure, and GCP. References attack skills at `attacks/cloud-containers/`.

## Quick Start

```
1. Identify target cloud provider(s): AWS, Azure, GCP
2. Determine access level: external (black-box) or internal (credentials provided)
3. Select testing modules based on scope
4. Execute tests and map findings to CIS Benchmarks
5. Generate cloud security report
```

## Prerequisites

- **AWS**: `aws` CLI configured, or target URLs for external testing
- **Azure**: `az` CLI configured, or target URLs for external testing
- **GCP**: `gcloud` CLI configured, or target URLs for external testing
- Optional: ScoutSuite, Prowler, Pacu (for automated scanning)

## Workflows

### IAM & Identity Review

```
- [ ] Enumerate IAM users, roles, groups, policies
- [ ] Identify overprivileged roles (admin access, wildcard permissions)
- [ ] Check for unused credentials and access keys
- [ ] Test cross-account trust relationships
- [ ] Check MFA enforcement
- [ ] Test privilege escalation paths (see reference/{AWS,AZURE,GCP}_TESTING.md)
```

### Storage Security

```
- [ ] Enumerate storage buckets/blobs/objects
- [ ] Test public access (anonymous read/write/list)
- [ ] Check encryption at rest configuration
- [ ] Test pre-signed URL generation and expiry
- [ ] Check versioning and lifecycle policies
- [ ] Test for sensitive data exposure (credentials, PII, backups)
```

### Serverless & Compute

```
- [ ] Enumerate Lambda/Functions/Cloud Functions
- [ ] Check function permissions and execution roles
- [ ] Test event source injection (API Gateway, S3 triggers, queue messages)
- [ ] Review environment variables for secrets
- [ ] Check function timeout and memory limits (resource abuse)
- [ ] Test for SSRF via function code (metadata service access)
```

### Network Security

```
- [ ] Review security groups / NSGs / firewall rules
- [ ] Check for overly permissive ingress (0.0.0.0/0)
- [ ] Test VPC/VNet peering configurations
- [ ] Check for exposed management ports (22, 3389, 443)
- [ ] Test load balancer and CDN configurations
- [ ] Check DNS configurations for subdomain takeover
```

### Metadata Service Exploitation

```
- [ ] Test SSRF to metadata endpoints:
      AWS: http://169.254.169.254/latest/meta-data/
      Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
      GCP: http://metadata.google.internal/computeMetadata/v1/
- [ ] Check IMDSv2 enforcement (AWS)
- [ ] Extract IAM credentials from metadata
- [ ] Test for credential relay attacks
```

### Privilege Escalation

```
- [ ] Map current permissions (whoami equivalent)
- [ ] Identify escalation paths (IAM policy attachment, role assumption)
- [ ] Test cross-service privilege escalation
- [ ] Check for service account key generation permissions
- [ ] Test resource-based policy abuse
```

## Provider-Specific References

| Provider | Reference | Key Tools |
|----------|-----------|-----------|
| AWS | `reference/AWS_TESTING.md` | aws CLI, Pacu, Prowler, ScoutSuite |
| Azure | `reference/AZURE_TESTING.md` | az CLI, MicroBurst, ROADtools |
| GCP | `reference/GCP_TESTING.md` | gcloud CLI, ScoutSuite |

## Attack Skill References

- `attacks/cloud-containers/aws/` - AWS-specific attack patterns
- `attacks/cloud-containers/azure/` - Azure-specific attack patterns
- `attacks/cloud-containers/gcp/` - GCP-specific attack patterns

## Output Structure

```
outputs/<engagement>/
├── findings/
│   ├── finding-NNN/
│   │   ├── report.md           # Finding with CIS Benchmark mapping
│   │   ├── poc.py              # Exploitation PoC
│   │   ├── poc_output.txt      # Execution proof
│   │   └── evidence/
│   │       ├── iam-policy.json # Relevant IAM policy
│   │       └── screenshots/
├── inventory/
│   ├── iam-inventory.json      # Users, roles, policies
│   ├── storage-inventory.json  # Buckets, permissions
│   └── network-inventory.json  # Security groups, rules
└── reports/
    └── cloud-security-report.md
```

## CIS Benchmark Mapping

See `reference/CIS_BENCHMARKS.md` for compliance mapping per provider.

## Integration

**With Pentester Orchestrator**: Cloud as attack surface
- Metadata SSRF findings from web testing → feed to cloud escalation
- API credentials discovered → test cloud API access

**With Container Security**: Cloud-hosted containers
- EKS/AKS/GKE clusters → delegate to `/container-security`

## Critical Rules

- **Respect scope boundaries** - only test authorized cloud accounts/subscriptions
- **Never modify production IAM** - read-only testing unless explicitly authorized
- **Document credential access** - log all credential discovery and usage
- **Avoid destructive actions** - no resource deletion, policy changes, or data modification
- **Time-box metadata exploitation** - credential rotation may be in effect
