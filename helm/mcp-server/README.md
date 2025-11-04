# GitGuardian SecOps MCP Server Helm Chart

A Helm chart for deploying GitGuardian SecOps MCP Server in HTTP mode on Kubernetes.

## Overview

This Helm chart deploys the GitGuardian SecOps MCP (Model Context Protocol) Server in HTTP/SSE mode, allowing you to host the server as a centralized service for comprehensive security operations that can be consumed by multiple AI agents or applications.

**Authentication Model**: This server uses per-request authentication via HTTP headers. No secrets or Personal Access Tokens (PATs) are stored in the deployment. Each client request must include authentication credentials in the `Authorization` header.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- Python and `uv` available in the container image (included in the deployment)
- GitGuardian Personal Access Token (PAT) for each client with appropriate SecOps scopes

## Installation

### Quick Start

1. Install the Helm chart:

```bash
helm install secops-mcp-server ./helm/mcp-server
```

2. The SecOps server will start and be ready to accept requests with per-request authentication.

### Using a values file

Create a `my-values.yaml` file:

```yaml
# GitGuardian instance configuration
gitguardian:
  url: "https://dashboard.gitguardian.com"
  # SecOps typically requires comprehensive scopes
  scopes: "scan,incidents:read,incidents:write,sources:read,honeytokens:read,honeytokens:write"

# Service configuration
service:
  type: ClusterIP
  port: 8000

# Enable ingress if you want to expose the service externally
ingress:
  enabled: true
  className: "nginx"
  hosts:
    - host: secops-mcp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: secops-mcp-tls
      hosts:
        - secops-mcp.example.com

# Resource limits for SecOps workloads
resources:
  limits:
    cpu: 2000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi
```

Install with your custom values:

```bash
helm install secops-mcp-server ./helm/mcp-server -f my-values.yaml
```

## Configuration

### GitGuardian Configuration

#### GitGuardian SaaS (US)

Default configuration:

```yaml
gitguardian:
  url: "https://dashboard.gitguardian.com"
```

#### GitGuardian SaaS (EU)

For the EU region:

```yaml
gitguardian:
  url: "https://dashboard.eu1.gitguardian.com"
```

#### Self-Hosted GitGuardian

For self-hosted instances:

```yaml
gitguardian:
  url: "https://dashboard.gitguardian.mycorp.local"
```

### Authentication

**Important**: This MCP server uses per-request authentication. No secrets or PATs are stored in the Kubernetes deployment.

Each HTTP request to the server must include authentication via the `Authorization` header:

```bash
curl -X POST http://secops-mcp-server:8000/tools/list \
  -H "Authorization: Bearer YOUR_PERSONAL_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Supported header formats:**
- `Authorization: Bearer <token>`
- `Authorization: Token <token>`
- `Authorization: <token>`

**Why per-request authentication?**
- **Security**: No credentials stored in the cluster
- **Multi-tenancy**: Different SecOps teams can use different PATs
- **Flexibility**: Easy to rotate tokens without redeploying
- **Audit trail**: Each request is authenticated individually

### Required Scopes for SecOps

SecOps operations typically require the following scopes:
- `scan` - Scan code for secrets
- `incidents:read` - Read security incidents
- `incidents:write` - Manage and resolve incidents
- `sources:read` - Read source information
- `honeytokens:read` - List honeytokens
- `honeytokens:write` - Create and manage honeytokens

### Service Configuration

Configure how the service is exposed:

```yaml
service:
  type: ClusterIP  # Options: ClusterIP, NodePort, LoadBalancer
  port: 8000
  targetPort: 8000
```

### Ingress Configuration

To expose the SecOps MCP server externally:

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: secops-mcp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: secops-mcp-tls
      hosts:
        - secops-mcp.example.com
```

### Resource Management

SecOps workloads may require more resources:

```yaml
resources:
  limits:
    cpu: 2000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi
```

### Autoscaling

Enable horizontal pod autoscaling for variable SecOps workloads:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 75
  targetMemoryUtilizationPercentage: 80
```

### Security Context

The chart includes secure defaults:

```yaml
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000

securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1000
```

## Usage

### Connecting to the SecOps MCP Server

Once deployed, you can connect to the server using HTTP requests with Bearer token authentication:

```bash
# Get the service URL
kubectl get service secops-mcp-server

# List available SecOps tools
curl -X POST http://<service-url>:8000/tools/list \
  -H "Authorization: Bearer YOUR_PAT" \
  -H "Content-Type: application/json" \
  -d '{}'

# Example: Get authenticated user info
curl -X POST http://<service-url>:8000/tools/call \
  -H "Authorization: Bearer YOUR_PAT" \
  -H "Content-Type: application/json" \
  -d '{"name": "get_authenticated_user_info", "arguments": {}}'
```

### Using with MCP Clients

Configure your MCP client to use the HTTP transport with per-request authentication:

```json
{
  "mcpServers": {
    "GitGuardianSecOps": {
      "url": "http://secops-mcp-server:8000",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer YOUR_PERSONAL_ACCESS_TOKEN"
      }
    }
  }
}
```

## Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.registry` | Container image registry | `ghcr.io` |
| `image.repository` | Container image repository | `gitguardian/mcp-server` |
| `image.tag` | Image tag | `""` (uses chart appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.useDockerImage` | Use pre-built Docker image vs uvx | `false` |
| `mcp.port` | MCP server port | `8000` |
| `mcp.host` | MCP server host | `0.0.0.0` |
| `gitguardian.url` | GitGuardian instance URL | `https://dashboard.gitguardian.com` |
| `gitguardian.scopes` | OAuth scopes (for reference) | `""` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `8000` |
| `ingress.enabled` | Enable ingress | `false` |
| `resources.limits.cpu` | CPU limit | `1000m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `autoscaling.enabled` | Enable HPA | `false` |

## Upgrading

To upgrade the chart:

```bash
helm upgrade secops-mcp-server ./helm/mcp-server -f my-values.yaml
```

## Uninstallation

To uninstall the chart:

```bash
helm uninstall secops-mcp-server
```

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -l app.kubernetes.io/name=gitguardian-secops-mcp-server
```

### View Pod Logs

```bash
kubectl logs -l app.kubernetes.io/name=gitguardian-secops-mcp-server
```

### Check Service Endpoints

```bash
kubectl get endpoints secops-mcp-server
```

### Test Connectivity

```bash
# Port forward to test locally
kubectl port-forward service/secops-mcp-server 8000:8000

# Test the endpoint (requires a valid PAT with SecOps scopes)
curl -X POST http://localhost:8000/tools/list \
  -H "Authorization: Bearer YOUR_PAT" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Authentication Errors

If you receive 401 Unauthorized errors:
- Verify your PAT is valid and not expired
- Check the Authorization header format
- Ensure the PAT has the required SecOps scopes
- Create a new PAT at your GitGuardian dashboard

## Security Considerations

1. **No stored credentials**: The deployment does not store any PATs or secrets
2. **Per-request authentication**: Each request is authenticated individually
3. **Use TLS/HTTPS**: Enable ingress with TLS for production deployments
4. **Network policies**: Consider implementing Kubernetes network policies to restrict access
5. **RBAC**: The chart creates a service account with minimal permissions
6. **Token management**: SecOps teams are responsible for securing their own PATs
7. **Scope management**: Use least-privilege scopes for each team's PAT

## Multi-Team SecOps

This deployment supports multi-team SecOps naturally through per-request authentication:
- Different SecOps teams can use different PATs in their requests
- No shared credentials mean better security isolation between teams
- Each team's requests are authenticated and authorized independently
- Fine-grained access control through PAT scopes

## Support

For issues and questions:
- GitHub Issues: https://github.com/GitGuardian/gg-mcp/issues
- Documentation: https://docs.gitguardian.com/

## License

MIT License - see LICENSE file for details
