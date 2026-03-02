# Azure Security Testing

## Azure AD & Identity

### Enumeration

```bash
# Current identity
az account show
az ad signed-in-user show

# List users and groups
az ad user list --query "[].{name:displayName, upn:userPrincipalName}"
az ad group list --query "[].{name:displayName, id:id}"

# List service principals
az ad sp list --all --query "[].{name:displayName, appId:appId}"

# List role assignments
az role assignment list --all
az role assignment list --assignee <user-id>
```

### Privilege Escalation Paths

| Technique | Required Role/Permission | Impact |
|-----------|------------------------|--------|
| Global Admin escalation | User Access Administrator | Full subscription access |
| Service Principal abuse | Application.ReadWrite.All | Create creds for any app |
| Custom role manipulation | Microsoft.Authorization/roleDefinitions/write | Escalate permissions |
| Managed Identity abuse | Contributor on VM/Function | Token theft |
| Runbook execution | Automation Contributor | Code execution as automation account |
| Key Vault access | Key Vault Contributor | Extract secrets and certificates |

**Tools**: ROADtools, MicroBurst

```bash
# ROADtools - Azure AD enumeration
roadrecon auth -u user@tenant.com -p password
roadrecon gather
roadrecon gui

# MicroBurst - Azure security assessment
Import-Module MicroBurst
Invoke-EnumerateAzureBlobs -Base company
Invoke-EnumerateAzureSubDomains -Base company
```

## Blob Storage

### Enumeration

```bash
# List storage accounts
az storage account list --query "[].{name:name, sku:sku.name}"

# List containers
az storage container list --account-name <name> --query "[].{name:name, access:properties.publicAccess}"

# Check anonymous access
az storage blob list --container-name <container> --account-name <name> --auth-mode key
curl "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"
```

### Common Misconfigurations

- Container public access (blob or container level)
- Storage account key in application config
- Missing soft delete and versioning
- Shared Access Signatures (SAS) with excessive scope/expiry
- CORS misconfiguration allowing credential theft

## Metadata Service

### IMDS Endpoint

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header required: Metadata: true
```

### Token Extraction

```bash
# Get managed identity token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Use token
az account get-access-token
```

### SSRF Exploitation

- Requires `Metadata: true` header (blocks simple SSRF)
- Bypass: Find SSRF that allows custom headers
- Redirect-based bypass may work if header forwarded

## Function Apps

```bash
# List function apps
az functionapp list --query "[].{name:name, state:state}"

# Get function configuration
az functionapp config appsettings list --name <name> --resource-group <rg>

# Check authentication
az functionapp auth show --name <name> --resource-group <rg>
```

**Key checks**: App settings containing secrets, managed identity permissions, function key exposure

## Network Security

```bash
# List NSGs and rules
az network nsg list
az network nsg rule list --nsg-name <name> --resource-group <rg>

# Check for open management ports
az network nsg rule list --nsg-name <name> --query "[?direction=='Inbound' && access=='Allow']"
```

## AKS (Azure Kubernetes)

- AKS clusters → Delegate to `/container-security` for K8s testing
- Check AKS-managed identity permissions
- Review Azure CNI network policies
- Check Azure Key Vault integration for secrets

## Automated Scanning

### ScoutSuite

```bash
scout azure --report-dir ./scout-results
```

### Azure Security Center / Defender

```bash
az security assessment list --query "[?status.code=='Unhealthy']"
```

## Detection Considerations

- Azure Activity Log records management plane operations
- Azure Sentinel may correlate suspicious activity
- Microsoft Defender for Cloud generates security alerts
- Avoid rapid enumeration of Azure AD
