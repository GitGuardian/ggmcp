# Quick Installation Guide

This guide provides step-by-step instructions for deploying the GitGuardian MCP Server using Helm.

## Prerequisites

Before you begin, ensure you have:

1. A Kubernetes cluster (1.19+) with kubectl configured
2. Helm 3.2.0+ installed
3. A GitGuardian Personal Access Token (PAT) for authentication

**Note**: Unlike traditional deployments, this Helm chart does NOT require creating Kubernetes secrets for PATs. Authentication is done per-request via HTTP headers.

## Step 1: Install the Helm Chart

### Basic Installation

For a basic installation with default settings:

```bash
kubectl create namespace gitguardian  # Optional: create a dedicated namespace

helm install mcp-server ./helm/mcp-server \
  --namespace gitguardian
```

### Installation with Custom Values

For more control, use one of the example values files:

```bash
# Basic setup
helm install mcp-server ./helm/mcp-server \
  --namespace gitguardian \
  -f helm/mcp-server/examples/values-basic.yaml

# Production setup with ingress and autoscaling
helm install mcp-server ./helm/mcp-server \
  --namespace gitguardian \
  -f helm/mcp-server/examples/values-production.yaml

# Self-hosted GitGuardian
helm install mcp-server ./helm/mcp-server \
  --namespace gitguardian \
  -f helm/mcp-server/examples/values-self-hosted.yaml

# SecOps server type
helm install mcp-server ./helm/mcp-server \
  --namespace gitguardian \
  -f helm/mcp-server/examples/values-secops.yaml
```

## Step 2: Verify the Installation

Check that the pod is running:

```bash
kubectl get pods -n gitguardian -l app.kubernetes.io/name=gitguardian-mcp-server
```

Check the service:

```bash
kubectl get service -n gitguardian mcp-server
```

View logs:

```bash
kubectl logs -n gitguardian -l app.kubernetes.io/name=gitguardian-mcp-server
```

## Step 3: Test the Connection

### Port Forward (for testing)

```bash
kubectl port-forward -n gitguardian service/mcp-server 8000:8000
```

### Test the API

**Important**: You need a valid GitGuardian Personal Access Token to test the API.

```bash
# List available tools
curl -X POST http://localhost:8000/tools/list \
  -H "Authorization: Bearer YOUR_PERSONAL_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Get authenticated user info
curl -X POST http://localhost:8000/tools/call \
  -H "Authorization: Bearer YOUR_PERSONAL_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "get_authenticated_user_info", "arguments": {}}'
```

## Step 4: Configure Your MCP Client

Update your MCP client configuration to use the deployed server:

### For in-cluster clients:

```json
{
  "mcpServers": {
    "GitGuardian": {
      "url": "http://mcp-server.gitguardian.svc.cluster.local:8000",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer YOUR_PERSONAL_ACCESS_TOKEN"
      }
    }
  }
}
```

### If you configured an ingress:

```json
{
  "mcpServers": {
    "GitGuardian": {
      "url": "https://mcp-server.example.com",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer YOUR_PERSONAL_ACCESS_TOKEN"
      }
    }
  }
}
```

## Authentication

### Per-Request Authentication

This MCP server uses per-request authentication. Each HTTP request must include your GitGuardian Personal Access Token in the `Authorization` header.

**Supported formats:**
- `Authorization: Bearer YOUR_PAT`
- `Authorization: Token YOUR_PAT`
- `Authorization: YOUR_PAT`

### Creating a Personal Access Token

1. Go to your GitGuardian dashboard
2. Navigate to API > Personal Access Tokens
3. Create a new token with the required scopes:
   - For developer server: `scan`, `incidents:read`, `sources:read`
   - For honeytokens: add `honeytokens:read`, `honeytokens:write`
   - For SecOps: add `incidents:write`

### No Secrets Required

Unlike traditional deployments, you do NOT need to:
- Create Kubernetes secrets for PATs
- Store credentials in the cluster
- Manage token rotation through Kubernetes

Each client manages their own PAT and includes it in their requests.

## Upgrading

To upgrade the deployment:

```bash
helm upgrade mcp-server ./helm/mcp-server \
  --namespace gitguardian \
  -f your-values.yaml
```

## Uninstalling

To remove the deployment:

```bash
helm uninstall mcp-server --namespace gitguardian
```

## Troubleshooting

### Pod is not starting

Check pod events:
```bash
kubectl describe pod -n gitguardian -l app.kubernetes.io/name=gitguardian-mcp-server
```

### Authentication errors (401 Unauthorized)

Verify your PAT:
- Check that the token is valid and not expired
- Ensure the token has the required scopes
- Verify the Authorization header format
- Create a new PAT if needed

### Connection refused

Verify the service is correctly configured:
```bash
kubectl get endpoints -n gitguardian mcp-server
```

### Testing with curl

```bash
# Port forward the service
kubectl port-forward -n gitguardian service/mcp-server 8000:8000

# In another terminal, test the connection
curl -v -X POST http://localhost:8000/tools/list \
  -H "Authorization: Bearer YOUR_PAT" \
  -H "Content-Type: application/json" \
  -d '{}'
```

## Multi-User Setup

Since authentication is per-request, multiple users can use the same deployment with different PATs:

1. Deploy the MCP server once
2. Each user includes their own PAT in the Authorization header
3. No shared credentials or secrets needed
4. Each user's requests are authenticated independently

## Production Considerations

For production deployments:

1. **Enable TLS/HTTPS**: Use ingress with TLS certificates
   ```yaml
   ingress:
     enabled: true
     tls:
       - secretName: mcp-server-tls
         hosts:
           - mcp-server.example.com
   ```

2. **Enable autoscaling**: Handle variable load
   ```yaml
   autoscaling:
     enabled: true
     minReplicas: 2
     maxReplicas: 10
   ```

3. **Set resource limits**: Prevent resource exhaustion
   ```yaml
   resources:
     limits:
       cpu: 1000m
       memory: 512Mi
     requests:
       cpu: 200m
       memory: 256Mi
   ```

4. **Network policies**: Restrict access to the service
   ```yaml
   # Create a NetworkPolicy to allow only specific namespaces
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: mcp-server-access
   spec:
     podSelector:
       matchLabels:
         app.kubernetes.io/name: gitguardian-mcp-server
     ingress:
     - from:
       - namespaceSelector:
           matchLabels:
             allowed: "true"
   ```

5. **Monitoring**: Set up monitoring and alerting
   - Pod health checks are included
   - Add Prometheus annotations for metrics
   - Set up log aggregation

## Next Steps

- Configure ingress for external access
- Set up monitoring and alerting
- Enable autoscaling for production workloads
- Review security best practices in the main README
- Configure network policies to restrict access

For more detailed configuration options, see [README.md](./README.md).
