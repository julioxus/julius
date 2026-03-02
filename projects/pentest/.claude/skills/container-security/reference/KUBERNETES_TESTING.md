# Kubernetes Security Testing

## RBAC Analysis

### Enumeration

```bash
# Current context and permissions
kubectl auth whoami
kubectl auth can-i --list

# List cluster roles and bindings
kubectl get clusterroles -o name
kubectl get clusterrolebindings -o name

# Check specific role permissions
kubectl describe clusterrole <name>
kubectl describe clusterrolebinding <name>

# Find overprivileged roles (wildcard permissions)
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]?.verbs[]? == "*")'
```

### Service Account Analysis

```bash
# List service accounts
kubectl get serviceaccounts --all-namespaces

# Check SA token mounting
kubectl get pods -o json | jq '.items[] | select(.spec.automountServiceAccountToken != false) | .metadata.name'

# Get SA token from pod
kubectl exec <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Test SA permissions
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
```

### Escalation Paths

| Technique | Required Permission | Impact |
|-----------|-------------------|--------|
| Create privileged pod | pods/create + SA with node access | Node compromise |
| SA token theft | pods/exec or logs | Impersonate service account |
| Bind cluster-admin | clusterrolebindings/create | Full cluster access |
| Create service account key | serviceaccounts/token/create | Persistent access |
| Impersonate user | users/impersonate | Act as any user |

## Pod Security

### Security Context Checks

```bash
# Find privileged pods
kubectl get pods -o json --all-namespaces | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'

# Find pods running as root
kubectl get pods -o json --all-namespaces | \
  jq '.items[] | select(.spec.containers[].securityContext.runAsNonRoot!=true) | .metadata.name'

# Check host namespace sharing
kubectl get pods -o json | jq '.items[] | select(.spec.hostNetwork==true) | .metadata.name'
kubectl get pods -o json | jq '.items[] | select(.spec.hostPID==true) | .metadata.name'
```

### Dangerous Volume Mounts

```bash
# Find hostPath mounts
kubectl get pods -o json --all-namespaces | \
  jq '.items[] | select(.spec.volumes[]?.hostPath != null) | {name: .metadata.name, paths: [.spec.volumes[].hostPath.path]}'

# Critical paths: /, /etc, /var/run/docker.sock, /proc
```

### Pod Security Standards

```bash
# Check namespace labels for PSA enforcement
kubectl get namespaces -o json | \
  jq '.items[] | {name: .metadata.name, labels: .metadata.labels | with_entries(select(.key | startswith("pod-security")))}'
```

## Network Policies

```bash
# Check for NetworkPolicies
kubectl get networkpolicies --all-namespaces

# Namespaces without any NetworkPolicy (no isolation)
# Compare: namespaces list vs namespaces with policies

# Test connectivity between pods
kubectl exec <pod-a> -- curl -s <pod-b-svc>:<port>
```

### Default Deny Template

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

## Secrets

```bash
# List secrets
kubectl get secrets --all-namespaces

# Check encryption at rest
kubectl -n kube-system get cm kube-apiserver -o yaml | grep encryption

# Secrets in environment variables (visible in pod spec)
kubectl get pods -o json | jq '.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef)'
```

## API Server

```bash
# Check API server flags
kubectl -n kube-system get pod kube-apiserver-* -o yaml | grep -E "\-\-(anonymous-auth|authorization-mode|enable-admission)"

# Test anonymous access
curl -k https://<api-server>:6443/api

# Check exposed API server
curl -k https://<api-server>:6443/version
```

## etcd Security

```bash
# Check etcd exposure (port 2379)
curl http://<etcd-host>:2379/version

# Extract secrets from etcd (if accessible)
etcdctl get /registry/secrets --prefix --keys-only
```

## Automated Scanning

### kube-bench (CIS Kubernetes Benchmark)

```bash
kube-bench run --targets master,node
kube-bench run --targets master --check 1.2.16  # specific check
```

### kube-hunter

```bash
kube-hunter --remote <cluster-ip>
kube-hunter --pod  # Run from within cluster
```

### kubeaudit

```bash
kubeaudit all
kubeaudit privileged
kubeaudit rootfs
kubeaudit capabilities
```

## Container Escape from Kubernetes

1. **Privileged pod** → nsenter to host
2. **hostPath mount (/)** → read/write host filesystem
3. **Docker socket mount** → create new privileged container
4. **hostPID** → ptrace host processes
5. **Service account with node proxy** → kubelet API → RCE on node

## Detection Considerations

- Kubernetes audit logs record API server requests
- Falco can detect runtime anomalies (exec in containers, unexpected network)
- OPA/Gatekeeper policies may block privileged workloads
- Avoid creating/deleting resources — prefer read-only enumeration
