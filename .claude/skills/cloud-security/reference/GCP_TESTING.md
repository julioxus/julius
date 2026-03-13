# GCP Security Testing

## IAM & Identity

### Enumeration

```bash
# Current identity
gcloud auth list
gcloud config get-value project

# List IAM policy for project
gcloud projects get-iam-policy <project-id>

# List service accounts
gcloud iam service-accounts list

# List service account keys
gcloud iam service-accounts keys list --iam-account <sa-email>

# Get effective permissions
gcloud projects get-iam-policy <project-id> --flatten="bindings[].members" \
  --filter="bindings.members:<user-email>"
```

### Privilege Escalation Paths

| Technique | Required Permission | Impact |
|-----------|-------------------|--------|
| SA key creation | iam.serviceAccountKeys.create | Impersonate service account |
| SA token generation | iam.serviceAccounts.getAccessToken | Temporary SA impersonation |
| Set IAM policy | resourcemanager.projects.setIamPolicy | Grant any role |
| Deploy Cloud Function | cloudfunctions.functions.create + iam.serviceAccounts.actAs | Code exec as SA |
| Compute instance SA | compute.instances.create + iam.serviceAccounts.actAs | Metadata token theft |
| Custom role creation | iam.roles.create | Create role with any permission |

**Tools**: ScoutSuite

```bash
scout gcp --report-dir ./scout-results --user-account
```

## Cloud Storage (GCS)

### Enumeration

```bash
# List buckets
gsutil ls

# Check bucket IAM
gsutil iam get gs://<bucket>

# Check bucket ACL
gsutil acl get gs://<bucket>

# Test anonymous access
curl "https://storage.googleapis.com/<bucket>"
gsutil ls gs://<bucket> 2>/dev/null  # without credentials
```

### Common Misconfigurations

- `allUsers` or `allAuthenticatedUsers` with read/write
- Uniform bucket-level access disabled (legacy ACLs)
- Missing object versioning
- Public dataset exposure
- Bucket name enumeration via DNS

## Metadata Service

### IMDS Endpoint

```
http://metadata.google.internal/computeMetadata/v1/
Header required: Metadata-Flavor: Google
```

### Token Extraction

```bash
# Get access token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Get project metadata
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/"

# Get instance metadata
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true"
```

### SSRF Exploitation

- Requires `Metadata-Flavor: Google` header
- Bypass: Find SSRF allowing custom headers, or redirect-based bypass
- Check for `X-Google-Metadata-Request` header in older versions

## Cloud Functions

```bash
# List functions
gcloud functions list

# Describe function (env vars, service account)
gcloud functions describe <name> --region <region>

# Get function source
gcloud functions logs read <name> --region <region>
```

**Key checks**: Environment variables with secrets, overprivileged service account, public HTTP triggers

## Network Security

```bash
# List firewall rules
gcloud compute firewall-rules list

# Check for overly permissive rules
gcloud compute firewall-rules list --filter="sourceRanges=('0.0.0.0/0') AND direction=INGRESS"

# List VPC networks
gcloud compute networks list
gcloud compute networks subnets list
```

## GKE (Google Kubernetes Engine)

- GKE clusters → Delegate to `/container-security` for K8s testing
- Check GKE node service account permissions
- Review Workload Identity configuration
- Test metadata concealment settings

## App Engine & Cloud Run

```bash
# App Engine
gcloud app describe
gcloud app versions list
gcloud app instances list

# Cloud Run
gcloud run services list
gcloud run services describe <name> --region <region>
```

**Key checks**: Public access, IAM invoker permissions, environment secrets

## Automated Scanning

### ScoutSuite

```bash
scout gcp --user-account --report-dir ./scout-results
```

### Forseti Security

```bash
forseti inventory create
forseti scanner run
```

## Detection Considerations

- Cloud Audit Logs record all admin and data access
- Security Command Center generates findings
- VPC Flow Logs capture network traffic
- Avoid rapid API enumeration — use targeted queries
