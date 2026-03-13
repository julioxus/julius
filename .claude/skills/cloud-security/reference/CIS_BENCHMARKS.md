# CIS Benchmark Mapping

## AWS CIS Benchmark (v2.0)

### Identity and Access Management

| Check | Description | Severity |
|-------|-------------|----------|
| 1.1 | Maintain current contact details | Low |
| 1.4 | Ensure no root account access key exists | Critical |
| 1.5 | Ensure MFA is enabled for root account | Critical |
| 1.8 | Ensure IAM password policy requires minimum length ≥ 14 | Medium |
| 1.10 | Ensure MFA is enabled for all IAM users with console access | High |
| 1.12 | Ensure credentials unused for 45+ days are disabled | Medium |
| 1.16 | Ensure IAM policies are attached only to groups or roles | Medium |
| 1.17 | Ensure no inline policies exist | Low |

### Storage

| Check | Description | Severity |
|-------|-------------|----------|
| 2.1.1 | Ensure S3 bucket policy denies HTTP requests | Medium |
| 2.1.2 | Ensure MFA delete is enabled on S3 buckets | Medium |
| 2.1.4 | Ensure all S3 buckets use public access block | High |
| 2.2.1 | Ensure EBS volume encryption is enabled | Medium |

### Logging

| Check | Description | Severity |
|-------|-------------|----------|
| 3.1 | Ensure CloudTrail is enabled in all regions | High |
| 3.4 | Ensure CloudTrail log validation is enabled | Medium |
| 3.7 | Ensure S3 bucket access logging is enabled | Medium |

### Networking

| Check | Description | Severity |
|-------|-------------|----------|
| 5.1 | Ensure no security groups allow ingress 0.0.0.0/0 to port 22 | High |
| 5.2 | Ensure no security groups allow ingress 0.0.0.0/0 to port 3389 | High |
| 5.3 | Ensure default security group restricts all traffic | Medium |

## Azure CIS Benchmark (v2.1)

### Identity

| Check | Description | Severity |
|-------|-------------|----------|
| 1.1 | Ensure Security Defaults or Conditional Access is enabled | Critical |
| 1.2 | Ensure MFA is enabled for all users | Critical |
| 1.3 | Ensure no guest users with privileged roles | High |
| 1.8 | Ensure custom subscription owner roles are not created | Medium |

### Storage

| Check | Description | Severity |
|-------|-------------|----------|
| 3.1 | Ensure secure transfer required is enabled | Medium |
| 3.7 | Ensure public access level is disabled for storage accounts | High |
| 3.9 | Ensure storage account encryption is with CMK | Medium |

### Networking

| Check | Description | Severity |
|-------|-------------|----------|
| 6.1 | Ensure RDP access from internet is restricted | High |
| 6.2 | Ensure SSH access from internet is restricted | High |
| 6.5 | Ensure Network Watcher is enabled | Medium |

## GCP CIS Benchmark (v2.0)

### Identity

| Check | Description | Severity |
|-------|-------------|----------|
| 1.1 | Ensure corporate login credentials are used | High |
| 1.3 | Ensure no service account has admin privileges | Critical |
| 1.4 | Ensure service account keys are managed | High |
| 1.6 | Ensure KMS encryption keys are rotated within 90 days | Medium |

### Storage

| Check | Description | Severity |
|-------|-------------|----------|
| 5.1 | Ensure Cloud Storage buckets are not publicly accessible | High |
| 5.2 | Ensure Cloud Storage buckets have uniform access enabled | Medium |

### Networking

| Check | Description | Severity |
|-------|-------------|----------|
| 3.6 | Ensure SSH access from internet is restricted | High |
| 3.7 | Ensure RDP access from internet is restricted | High |
| 3.9 | Ensure VPC Flow Logs are enabled | Medium |

## Finding Severity Mapping

| CIS Severity | CVSS Range | Report Priority |
|-------------|------------|-----------------|
| Critical | 9.0-10.0 | Immediate remediation required |
| High | 7.0-8.9 | Remediate within 7 days |
| Medium | 4.0-6.9 | Remediate within 30 days |
| Low | 0.1-3.9 | Remediate at next maintenance cycle |
