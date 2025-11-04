# Contributing to the GitGuardian MCP Server Helm Chart

Thank you for your interest in contributing to the GitGuardian MCP Server Helm chart!

## Development Setup

### Prerequisites

- Kubernetes cluster (kind, minikube, or similar for local development)
- Helm 3.2.0+
- kubectl configured to access your cluster
- Docker (for building images)

### Local Development Cluster

#### Using kind

```bash
# Create a kind cluster
kind create cluster --name mcp-dev

# Verify cluster is running
kubectl cluster-info --context kind-mcp-dev
```

#### Using minikube

```bash
# Start minikube
minikube start

# Enable ingress addon (if testing ingress)
minikube addons enable ingress
```

## Testing the Chart

### Validate Chart Syntax

```bash
# Lint the chart
helm lint helm/mcp-server

# Validate templates render correctly
helm template test helm/mcp-server --debug

# Render with specific values
helm template test helm/mcp-server -f helm/mcp-server/examples/values-production.yaml
```

### Dry Run Installation

```bash
# Perform a dry run
helm install mcp-server helm/mcp-server \
  --dry-run --debug \
  --set gitguardian.personalAccessToken=test-token
```

### Install in Development

```bash
# Create test secret
kubectl create secret generic gitguardian-pat-test \
  --from-literal=personal-access-token='test-token'

# Install the chart
helm install mcp-server-test helm/mcp-server \
  --set gitguardian.existingSecret=gitguardian-pat-test \
  --set gitguardian.url=https://dashboard.gitguardian.com

# Watch the deployment
kubectl get pods -w

# Check for issues
kubectl describe pod -l app.kubernetes.io/name=gitguardian-mcp-server
```

### Testing Upgrades

```bash
# Make changes to the chart
# Then upgrade
helm upgrade mcp-server-test helm/mcp-server \
  --set gitguardian.existingSecret=gitguardian-pat-test

# Check rollout status
kubectl rollout status deployment/mcp-server-test

# View revision history
helm history mcp-server-test
```

### Cleanup

```bash
# Uninstall the release
helm uninstall mcp-server-test

# Delete the secret
kubectl delete secret gitguardian-pat-test
```

## Chart Structure Guidelines

### File Organization

```
helm/mcp-server/
├── Chart.yaml              # Chart metadata
├── values.yaml            # Default values
├── templates/
│   ├── _helpers.tpl       # Template helpers
│   ├── deployment.yaml    # Main deployment
│   ├── service.yaml       # Service definition
│   ├── serviceaccount.yaml
│   ├── secret.yaml        # Optional secret
│   ├── ingress.yaml       # Optional ingress
│   ├── hpa.yaml          # Optional HPA
│   └── NOTES.txt         # Post-install notes
├── examples/             # Example configurations
├── README.md            # User documentation
├── INSTALL.md          # Installation guide
└── DOCKER.md          # Docker guide
```

### Template Best Practices

1. **Use helpers for repeated values**
   ```yaml
   {{- include "mcp-server.fullname" . }}
   ```

2. **Make resources conditional**
   ```yaml
   {{- if .Values.ingress.enabled }}
   # ingress resource
   {{- end }}
   ```

3. **Validate required values**
   ```yaml
   {{- if not .Values.gitguardian.existingSecret }}
   {{- fail "gitguardian.existingSecret is required" }}
   {{- end }}
   ```

4. **Add annotations for checksums**
   ```yaml
   checksum/secret: {{ include (print $.Template.BasePath "/secret.yaml") . | sha256sum }}
   ```

5. **Use toYaml for complex structures**
   ```yaml
   {{- toYaml .Values.resources | nindent 12 }}
   ```

### values.yaml Guidelines

1. **Organize logically**
   - Group related settings
   - Use consistent indentation
   - Add comments for clarity

2. **Provide sensible defaults**
   ```yaml
   resources:
     limits:
       cpu: 1000m
       memory: 512Mi
     requests:
       cpu: 100m
       memory: 128Mi
   ```

3. **Document all options**
   ```yaml
   # GitGuardian instance URL
   # Examples:
   # - US SaaS: https://dashboard.gitguardian.com
   url: "https://dashboard.gitguardian.com"
   ```

## Making Changes

### Adding a New Template

1. Create the template file in `templates/`
2. Add corresponding values in `values.yaml`
3. Test the template renders correctly
4. Update documentation

Example: Adding a PodDisruptionBudget

```yaml
# templates/pdb.yaml
{{- if .Values.podDisruptionBudget.enabled }}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "mcp-server.fullname" . }}
spec:
  minAvailable: {{ .Values.podDisruptionBudget.minAvailable }}
  selector:
    matchLabels:
      {{- include "mcp-server.selectorLabels" . | nindent 6 }}
{{- end }}
```

```yaml
# values.yaml
podDisruptionBudget:
  enabled: false
  minAvailable: 1
```

### Modifying Existing Templates

1. Review the template and understand current behavior
2. Make minimal, focused changes
3. Test with various value combinations
4. Update examples if needed
5. Document breaking changes

### Version Bumping

When making changes:

- **Patch version** (0.1.0 -> 0.1.1): Bug fixes, no breaking changes
- **Minor version** (0.1.0 -> 0.2.0): New features, no breaking changes
- **Major version** (0.1.0 -> 1.0.0): Breaking changes

Update `Chart.yaml`:
```yaml
version: 0.2.0  # Chart version
appVersion: "0.1.0"  # App version
```

## Testing Checklist

Before submitting a PR, verify:

- [ ] `helm lint` passes without errors
- [ ] `helm template` renders all templates correctly
- [ ] Chart installs successfully in a test cluster
- [ ] All example values files work
- [ ] Documentation is updated
- [ ] NOTES.txt provides helpful information
- [ ] Security context is properly configured
- [ ] Resource limits are reasonable
- [ ] Secrets are handled securely

## Common Scenarios to Test

### Different Server Types

```bash
# Test developer server
helm install test-dev helm/mcp-server \
  --set serverType=developer \
  --set gitguardian.existingSecret=pat

# Test secops server
helm install test-secops helm/mcp-server \
  --set serverType=secops \
  --set gitguardian.existingSecret=pat
```

### With and Without Ingress

```bash
# Without ingress
helm install test-no-ingress helm/mcp-server \
  --set gitguardian.existingSecret=pat

# With ingress
helm install test-ingress helm/mcp-server \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=test.local \
  --set gitguardian.existingSecret=pat
```

### Different Image Modes

```bash
# Git-based installation
helm install test-git helm/mcp-server \
  --set image.useDockerImage=false \
  --set gitguardian.existingSecret=pat

# Docker image
helm install test-docker helm/mcp-server \
  --set image.useDockerImage=true \
  --set image.repository=your-registry/mcp-server \
  --set gitguardian.existingSecret=pat
```

## Documentation

When adding features, update:

1. **README.md**: User-facing documentation
2. **INSTALL.md**: Installation instructions
3. **values.yaml**: Inline comments
4. **examples/**: Example configurations
5. **NOTES.txt**: Post-install instructions

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Update documentation
6. Submit a pull request

### PR Description Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Lint passes
- [ ] Templates render correctly
- [ ] Tested in local cluster
- [ ] Documentation updated

## Additional Notes
Any additional information
```

## Getting Help

- Open an issue on GitHub
- Check existing issues and PRs
- Review Helm documentation: https://helm.sh/docs/

## Code of Conduct

Please be respectful and constructive in all interactions with the community.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT).
