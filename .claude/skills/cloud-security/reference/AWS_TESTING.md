# AWS Security Testing

## IAM Analysis

### Enumeration

```bash
# Current identity
aws sts get-caller-identity

# List users, roles, policies
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local
aws iam list-attached-user-policies --user-name <user>

# Get policy details
aws iam get-policy-version --policy-arn <arn> --version-id <v>
```

### Privilege Escalation Paths

| Technique | Required Permission | Impact |
|-----------|-------------------|--------|
| Attach admin policy | `iam:AttachUserPolicy` | Full account access |
| Create access key | `iam:CreateAccessKey` | Impersonate any user |
| Update login profile | `iam:UpdateLoginProfile` | Console access as user |
| Pass role to Lambda | `iam:PassRole` + `lambda:CreateFunction` | Execute as privileged role |
| AssumeRole chain | `sts:AssumeRole` | Cross-account escalation |
| Create policy version | `iam:CreatePolicyVersion` | Modify policy inline |

**Tools**: `pacu` (AWS exploitation framework)
```bash
pacu --new-session test
# Modules: iam__enum_permissions, iam__privesc_scan, iam__backdoor_users_keys
```

## S3 Storage

### Enumeration

```bash
# List buckets
aws s3 ls

# Check bucket ACL
aws s3api get-bucket-acl --bucket <name>

# Check bucket policy
aws s3api get-bucket-policy --bucket <name>

# Check public access block
aws s3api get-public-access-block --bucket <name>

# List objects (anonymous)
aws s3 ls s3://<bucket-name> --no-sign-request
```

### Common Misconfigurations

- Public read/write ACL
- Bucket policy allowing `s3:*` to `*`
- Missing public access block
- Static website hosting with sensitive files
- Logging disabled

## EC2 & Metadata

### SSRF to Metadata (IMDSv1)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data
```

### IMDSv2 (Token Required)

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: $TOKEN"
```

### Bypass Techniques

- URL encoding: `http://169.254.169.254/latest/meta-data/` → `http://[::ffff:a9fe:a9fe]/`
- DNS rebinding to 169.254.169.254
- Redirect via open redirect → metadata endpoint

## Lambda & Serverless

```bash
# List functions
aws lambda list-functions

# Get function configuration (env vars, role)
aws lambda get-function-configuration --function-name <name>

# Check execution role permissions
aws iam list-attached-role-policies --role-name <lambda-role>

# Invoke function (if permitted)
aws lambda invoke --function-name <name> output.json
```

**Key checks**: Environment variable secrets, overprivileged execution roles, public function URLs

## Automated Scanning

### Prowler

```bash
prowler aws --severity critical high
prowler aws --compliance cis_2.0_aws
```

### ScoutSuite

```bash
scout aws --report-dir ./scout-results
```

## ECS/EKS

- ECS task definitions may contain secrets in environment variables
- EKS: Delegate to `/container-security` skill for Kubernetes-specific testing
- Check task role permissions for escalation paths

## CloudTrail & Detection

**Check if logging is enabled**:
```bash
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name <trail>
```

**Detection considerations**:
- Most API calls are logged to CloudTrail
- GuardDuty may alert on unusual API patterns
- Avoid rapid enumeration — space out requests
