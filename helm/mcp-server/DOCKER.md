# Docker Image Guide

This guide explains how to build and use Docker images for the GitGuardian MCP Server.

## Overview

The Helm chart supports two deployment modes:

1. **Git-based installation** (Default): Uses `uvx` to install the MCP server directly from the Git repository at startup
2. **Pre-built Docker image**: Uses a pre-built container image with the server already installed

## Building the Docker Image

### Prerequisites

- Docker 20.10+ or compatible container runtime
- Access to the GitGuardian MCP repository

### Build Commands

#### For Developer MCP Server

```bash
# Build the image
docker build -t gitguardian-mcp-server:developer .

# Build with a specific tag
docker build -t gitguardian-mcp-server:0.1.0-developer .

# For multi-platform builds (ARM64 and AMD64)
docker buildx build --platform linux/amd64,linux/arm64 \
  -t gitguardian-mcp-server:developer .
```

#### For SecOps MCP Server

The default Dockerfile uses the developer server. To use the SecOps server, override the CMD:

```bash
# Build and override the command
docker build -t gitguardian-mcp-server:secops .

# Or run with a different command
docker run --env-file .env gitguardian-mcp-server:developer secops-mcp-server
```

### Image Structure

The Dockerfile creates a multi-stage build:

1. **Builder stage**: Installs dependencies using `uv`
2. **Production stage**: Creates a minimal runtime image with:
   - Python 3.13 slim base
   - Non-root user (uid: 1000)
   - Pre-installed dependencies
   - Security hardening (read-only root filesystem compatible)

### Testing the Image Locally

```bash
# Create a .env file with your configuration
cat > .env.docker << EOF
MCP_PORT=8000
MCP_HOST=0.0.0.0
ENABLE_LOCAL_OAUTH=false
GITGUARDIAN_URL=https://dashboard.gitguardian.com
GITGUARDIAN_PERSONAL_ACCESS_TOKEN=your_pat_here
EOF

# Run the container
docker run --rm \
  --env-file .env.docker \
  -p 8000:8000 \
  gitguardian-mcp-server:developer

# Test the server
curl -X POST http://localhost:8000/tools/list \
  -H "Authorization: Bearer your_pat_here" \
  -H "Content-Type: application/json" \
  -d '{}'
```

## Pushing to a Container Registry

### Docker Hub

```bash
# Tag the image
docker tag gitguardian-mcp-server:developer your-username/gitguardian-mcp-server:developer

# Login to Docker Hub
docker login

# Push the image
docker push your-username/gitguardian-mcp-server:developer
```

### GitHub Container Registry (GHCR)

```bash
# Tag for GHCR
docker tag gitguardian-mcp-server:developer ghcr.io/your-org/gitguardian-mcp-server:developer

# Login to GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Push the image
docker push ghcr.io/your-org/gitguardian-mcp-server:developer
```

### Amazon ECR

```bash
# Authenticate with ECR
aws ecr get-login-password --region region | docker login --username AWS --password-stdin aws_account_id.dkr.ecr.region.amazonaws.com

# Tag for ECR
docker tag gitguardian-mcp-server:developer aws_account_id.dkr.ecr.region.amazonaws.com/gitguardian-mcp-server:developer

# Push to ECR
docker push aws_account_id.dkr.ecr.region.amazonaws.com/gitguardian-mcp-server:developer
```

### Google Container Registry (GCR)

```bash
# Tag for GCR
docker tag gitguardian-mcp-server:developer gcr.io/your-project/gitguardian-mcp-server:developer

# Configure Docker for GCR
gcloud auth configure-docker

# Push to GCR
docker push gcr.io/your-project/gitguardian-mcp-server:developer
```

## Using the Docker Image with Helm

### Update values.yaml

```yaml
image:
  registry: ghcr.io  # or your registry
  repository: your-org/gitguardian-mcp-server
  tag: "developer"
  pullPolicy: IfNotPresent
  useDockerImage: true  # Important: enables Docker image mode

# If using a private registry, add pull secrets
imagePullSecrets:
  - name: regcred
```

### Create Image Pull Secret (for private registries)

```bash
kubectl create secret docker-registry regcred \
  --docker-server=ghcr.io \
  --docker-username=your-username \
  --docker-password=your-password \
  --docker-email=your-email \
  --namespace gitguardian
```

### Install with Docker Image

```bash
helm install mcp-server ./helm/mcp-server \
  --namespace gitguardian \
  --set image.registry=ghcr.io \
  --set image.repository=your-org/gitguardian-mcp-server \
  --set image.tag=developer \
  --set image.useDockerImage=true \
  --set gitguardian.existingSecret=gitguardian-pat
```

## Comparison: Git-based vs Docker Image

### Git-based Installation (Default)

**Pros:**
- No need to build/maintain Docker images
- Always gets the latest code from the repository
- Simpler CI/CD for development

**Cons:**
- Slower pod startup time (needs to download and install at startup)
- Requires internet access to GitHub during pod initialization
- Less control over exact versions
- Larger base image (needs Python + uv)

### Pre-built Docker Image

**Pros:**
- Faster pod startup time
- No internet access required after image pull
- Immutable deployments (exact version control)
- Smaller attack surface
- Better for air-gapped environments

**Cons:**
- Requires maintaining a container registry
- Need to rebuild and push for updates
- More complex CI/CD pipeline

## Production Recommendations

For production deployments, we recommend:

1. **Use pre-built Docker images** (`useDockerImage: true`)
2. **Use specific version tags** (not `latest`)
3. **Use private container registry**
4. **Implement image scanning** in CI/CD
5. **Use image pull secrets** for authentication
6. **Enable image signature verification**

Example production configuration:

```yaml
image:
  registry: your-registry.com
  repository: gitguardian/mcp-server
  tag: "0.1.0-developer"  # Specific version
  pullPolicy: IfNotPresent
  useDockerImage: true

imagePullSecrets:
  - name: registry-credentials

# Scan images in CI/CD
podAnnotations:
  container.apparmor.security.beta.kubernetes.io/mcp-server: runtime/default
```

## Automated Builds with CI/CD

### GitHub Actions Example

Create `.github/workflows/docker-build.yml`:

```yaml
name: Build and Push Docker Image

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Login to GHCR
        uses: docker/login-action@v2
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract version
        id: version
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT

      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ steps.version.outputs.VERSION }}-developer
            ghcr.io/${{ github.repository }}:latest-developer
```

## Security Scanning

### Using Trivy

```bash
# Scan the image for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image gitguardian-mcp-server:developer

# Scan with severity threshold
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL \
  gitguardian-mcp-server:developer
```

### Using Snyk

```bash
# Scan with Snyk
snyk container test gitguardian-mcp-server:developer

# Monitor the image
snyk container monitor gitguardian-mcp-server:developer
```

## Troubleshooting

### Image pull failures

```bash
# Check image pull secrets
kubectl get secret regcred -n gitguardian -o yaml

# Verify the secret is attached to service account
kubectl describe serviceaccount -n gitguardian

# Check pod events
kubectl describe pod -n gitguardian <pod-name>
```

### Container crashes

```bash
# Check logs
kubectl logs -n gitguardian <pod-name>

# Check if the command is correct
kubectl get pod -n gitguardian <pod-name> -o yaml | grep -A 5 command:
```

### Slow startup

If using git-based installation and experiencing slow startup:
1. Consider switching to pre-built Docker images
2. Check network connectivity to GitHub
3. Consider using a caching proxy

## Next Steps

- Set up automated image builds in CI/CD
- Implement image scanning and vulnerability management
- Configure image pull policies based on your environment
- Set up monitoring and alerting for image updates
