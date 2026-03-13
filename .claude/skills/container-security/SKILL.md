---
name: container-security
description: Container security assessment for Docker and Kubernetes environments. Orchestrates image scanning, Dockerfile analysis, K8s RBAC audit, pod security assessment, network policy review, secrets management audit, and container escape testing.
---

# Container Security Assessment

Orchestrates container-specific security testing for Docker and Kubernetes. References attack skills at `attacks/cloud-containers/`.

## Quick Start

```
1. Identify target: Docker host, Kubernetes cluster, or container images
2. Determine access level: external, cluster-internal, or image-only
3. Select testing modules based on scope
4. Execute tests and generate container security report
```

## Prerequisites

- **Docker**: `docker` CLI, access to target host or images
- **Kubernetes**: `kubectl` configured with target cluster access
- Optional: trivy, grype, kube-bench, kube-hunter, kubeaudit

## Workflows

### Image Security Scanning

```
- [ ] Scan container images for CVEs (trivy/grype)
- [ ] Check base image freshness and known vulnerabilities
- [ ] Analyze image layers for secrets, credentials, keys
- [ ] Verify image signing and provenance
- [ ] Check image size and unnecessary packages
```

See `reference/IMAGE_SCANNING.md` for tool integration.

### Dockerfile Analysis

```
- [ ] Check for privileged user (USER root or no USER directive)
- [ ] Verify no secrets in build args or ENV
- [ ] Check for unnecessary COPY of sensitive files
- [ ] Verify minimal base image (distroless, alpine)
- [ ] Check for pinned dependency versions
- [ ] Verify HEALTHCHECK directive exists
- [ ] Check for excessive capabilities (no --cap-add=ALL)
```

### Kubernetes RBAC Audit

```
- [ ] Enumerate ClusterRoles and ClusterRoleBindings
- [ ] Identify overprivileged service accounts
- [ ] Check for wildcard permissions (* verbs or resources)
- [ ] Test service account token mounting (automountServiceAccountToken)
- [ ] Check for default namespace usage
- [ ] Test RBAC escalation paths
```

### Pod Security Assessment

```
- [ ] Check for privileged containers (securityContext.privileged)
- [ ] Test hostPath volume mounts (/, /etc, /var/run/docker.sock)
- [ ] Check host network/PID/IPC namespace sharing
- [ ] Verify security contexts (runAsNonRoot, readOnlyRootFilesystem)
- [ ] Check capabilities (drop ALL, add only required)
- [ ] Test pod security admission/standards enforcement
```

### Network Policy Review

```
- [ ] Check if NetworkPolicies exist
- [ ] Test default deny (ingress + egress)
- [ ] Verify namespace isolation
- [ ] Test service mesh mTLS (if applicable)
- [ ] Check for pods bypassing network policies
```

### Secrets Management Audit

```
- [ ] Check for secrets in environment variables
- [ ] Verify Kubernetes Secrets encryption at rest
- [ ] Test for secrets in container filesystem
- [ ] Check external secrets manager integration (Vault, AWS SM)
- [ ] Test secret rotation policies
```

### Container Escape Testing

```
- [ ] Test Docker socket mount exploitation (/var/run/docker.sock)
- [ ] Test privileged container escape (nsenter, chroot)
- [ ] Check cgroup escape vectors
- [ ] Test kernel exploit applicability
- [ ] Verify seccomp/AppArmor profiles are enforced
```

## Attack Skill References

- `attacks/cloud-containers/docker/` - Docker-specific attack patterns
- `attacks/cloud-containers/kubernetes/` - Kubernetes-specific attack patterns

## Provider-Specific References

| Platform | Reference | Key Tools |
|----------|-----------|-----------|
| Docker | `reference/DOCKER_TESTING.md` | docker, trivy, grype |
| Kubernetes | `reference/KUBERNETES_TESTING.md` | kubectl, kube-bench, kube-hunter |

## Output Structure

```
outputs/<engagement>/
├── findings/
│   ├── finding-NNN/
│   │   ├── report.md           # Finding details
│   │   ├── poc.py              # Exploitation PoC
│   │   ├── poc_output.txt      # Execution proof
│   │   └── evidence/
│   │       ├── scan-results/   # Image scan outputs
│   │       └── k8s-configs/    # Relevant YAML manifests
├── inventory/
│   ├── images.json             # Scanned images and CVEs
│   ├── rbac-inventory.json     # Roles, bindings, service accounts
│   └── network-policies.json   # Network policy analysis
└── reports/
    └── container-security-report.md
```

## Integration

**With Cloud Security**: Cloud-hosted container platforms
- EKS/AKS/GKE → cloud IAM affects cluster access
- Container registry security → cloud storage permissions

**With Pentester Orchestrator**: Container as attack vector
- Exposed container APIs → container escape → host access
- K8s service discovery → lateral movement

## Critical Rules

- **Read-only testing** — never modify running workloads without authorization
- **Respect namespace boundaries** — only test authorized namespaces
- **Container escape is high-risk** — get explicit approval before testing
- **Log all kubectl commands** — maintain audit trail
