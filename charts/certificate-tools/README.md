# Certificate Tools Helm Chart

This Helm chart deploys the Certificate Tools application - a PKI and certificate management web application.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Azure Active Directory application for OAuth (optional, but recommended)

## Installation

### Basic Installation

```bash
helm install certificate-tools ./charts/certificate-tools
```

### Installation with Custom Values

```bash
helm install certificate-tools ./charts/certificate-tools \
  --set config.azure.clientId=YOUR_AZURE_CLIENT_ID \
  --set secrets.azureClientSecret=YOUR_AZURE_CLIENT_SECRET \
  --set config.externalUrl=https://certificate-tools.example.com
```

### Installation with Values File

Create a `custom-values.yaml` file:

```yaml
config:
  appTitle: "My Certificate Tools"
  externalUrl: "https://certificate-tools.example.com"
  azure:
    clientId: "your-azure-client-id"
    tenantId: "your-tenant-id"

secrets:
  azureClientSecret: "your-azure-client-secret"

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: certificate-tools.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: certificate-tools-tls
      hosts:
        - certificate-tools.example.com
```

Then install:

```bash
helm install certificate-tools ./charts/certificate-tools -f custom-values.yaml
```

## Configuration

The following table lists the configurable parameters and their default values.

### Application Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.appTitle` | Application title | `Certificate Tools` |
| `config.externalUrl` | External URL for OAuth callbacks | `""` |
| `config.azure.clientId` | Azure AD Client ID | `""` |
| `config.azure.tenantId` | Azure AD Tenant ID | `common` |
| `config.blobStorage.url` | Azure Blob Storage URL | `""` |
| `config.blobStorage.container` | Azure Blob Storage Container | `storage` |

### Secrets Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets.existingSecret` | Name of existing secret | `""` |
| `secrets.azureClientSecret` | Azure AD Client Secret | `""` |
| `secrets.flaskSecretKey` | Flask secret key | Auto-generated |

### Image Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository | `ghcr.io/gitsoep/certificate-tools` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `service.targetPort` | Container port | `5001` |

### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts | See values.yaml |
| `ingress.tls` | Ingress TLS configuration | `[]` |

### Resources

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `250m` |
| `resources.requests.memory` | Memory request | `256Mi` |

## Using External Secrets

Instead of storing secrets in values.yaml, you can use an existing Kubernetes secret:

```bash
# Create a secret
kubectl create secret generic certificate-tools-secrets \
  --from-literal=AZURE_CLIENT_SECRET=your-secret \
  --from-literal=FLASK_SECRET_KEY=your-flask-secret

# Install with existing secret
helm install certificate-tools ./charts/certificate-tools \
  --set secrets.existingSecret=certificate-tools-secrets
```

## Uninstallation

```bash
helm uninstall certificate-tools
```

## Upgrading

```bash
helm upgrade certificate-tools ./charts/certificate-tools -f custom-values.yaml
```

## Support

For issues and questions, please visit the [GitHub repository](https://github.com/gitsoep/certificate-tools).
