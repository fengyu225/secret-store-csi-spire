# SPIRE Nested Deployment with Secrets Store CSI Integration

This repository contains a multi-cluster SPIRE deployment for testing the SPIRE CSI provider of Kubernetes Secrets Store CSI.

## Architecture

The setup creates four Kind clusters in a nested SPIRE hierarchy:

```
spire-root (Root SPIRE Server)
    |
    +-- spire-subordinate-01 (Subordinate SPIRE Server)
    |
    +-- spire-subordinate-02 (Subordinate SPIRE Server)
            |
            +-- workload (Workload cluster with dual agents)
```

### Components

**Root Cluster**
- SPIRE server with PostgreSQL backend
- Upstream CA using disk-based certificates
- Node attestation for both subordinate clusters
- Controller manager for managing workload entries

**Subordinate Clusters**
- SPIRE servers using root cluster as upstream authority
- SQLite datastores
- Root agents connecting to root SPIRE server
- Controller managers for workload cluster management

**Workload Cluster**
- Two SPIRE agents (one per subordinate)
- Secrets Store CSI Driver
- SPIRE CSI Provider for workload identity provisioning
- Test workloads with CSI volume mounts

## Prerequisites

Required tools:
- Docker
- docker-compose
- Kind
- kubectl
- envsubst

## Setup

### Quick Start

```bash
cd scripts
./setup.sh
```

This will:
1. Start PostgreSQL containers
2. Create four Kind clusters
3. Load container images into clusters
4. Deploy SPIRE components
5. Install CSI drivers
6. Configure trust relationships

### Manual Steps

If you need to run individual components:

```bash
# Start databases
docker-compose -f root/docker-compose.yml up -d

# Create clusters
kind create cluster --config root/kind-config.yaml
kind create cluster --config subordinate-01/kind-config.yaml
kind create cluster --config subordinate-02/kind-config.yaml
kind create cluster --config workload/kind-config.yaml

# Deploy SPIRE (run setup.sh for full deployment)
```

## Configuration

### Trust Domain
All clusters use `example.org` as the trust domain.

### Network Ports
- Root PostgreSQL: 5432
- Subordinate-01 PostgreSQL: 5433
- Subordinate-02 PostgreSQL: 5434
- Root SPIRE NodePort: 30443
- Subordinate-01 NodePort: 30081
- Subordinate-02 NodePort: 30082

### Agent Sockets
Workload cluster agents create sockets at:
- `/run/spire/agent-sockets/child-01-socket`
- `/run/spire/agent-sockets/child-02-socket`

## Testing

### Verify Deployment

Check cluster health:
```bash
kubectl --context kind-spire-root get pods -n spire
kubectl --context kind-spire-subordinate-01 get pods -n spire
kubectl --context kind-spire-subordinate-02 get pods -n spire
kubectl --context kind-workload get pods -n spire
```

### Test Workload

The setup includes a test workload in the `app-a` namespace:

```bash
kubectl --context kind-workload get pods -n app-a

# Check mounted certificates
kubectl --context kind-workload exec -n app-a deployment/test-workload-a -- ls -la /run/spire/
```

### CSI Provider Validation

Verify the CSI provider is running:
```bash
kubectl --context kind-workload get pods -n csi
kubectl --context kind-workload get pods -n kube-system -l app=csi-secrets-store
```

Check SecretProviderClass:
```bash
kubectl --context kind-workload get secretproviderclass -A
```

## Cleanup

Remove all resources:
```bash
cd scripts
./cleanup.sh
```

## Troubleshooting

### Agent Registration

Verify agent registration on subordinate servers:
```bash
kubectl --context kind-spire-subordinate-01 exec -n spire spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server agent list
```

### CSI Mount Failures

Check CSI driver logs:
```bash
kubectl --context kind-workload logs -n kube-system daemonset/csi-secrets-store -c secrets-store
kubectl --context kind-workload logs -n csi daemonset/spire-csi-provider
```

## Development

### Building the CSI Provider

From the project root:
```bash
make build
```

The binary will be available at `bin/spire-csi-provider`.

### Image Updates

To use a custom CSI provider image:
1. Build and push your image
2. Update the image in `workload/spire-csi/spire-csi-provider.yaml`
3. Re-run the setup

## Files

Key configuration files:
- `root/configmaps/spire-server.yaml` - Root server config
- `subordinate-*/configmaps/spire-server.yaml` - Subordinate configs
- `workload/configmaps/spire-agent-child-*.yaml` - Agent configs
- `workload/spire-csi/spire-csi-provider.yaml` - CSI provider deployment
- `workload/spire-csi/workload-a.yaml` - Test workload with CSI volumes