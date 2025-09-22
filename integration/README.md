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

## Performance Testing

The repository includes a performance testing for evaluating the SPIRE CSI Provider under various load conditions. The test suite measures pod startup times, CSI mount success rates, and system resource utilization across different replica counts.

### Running Performance Tests

#### Quick Start

Run the default performance test:
```bash
cd scripts
./perf-test.sh
```

This will test with default replica counts (50, 100, 150, 200) and export results to `scripts/perf-results/`.

#### Custom Test Configurations

```bash
# Test with custom replica counts
./perf-test.sh --replicas 10,25,50,75

# Deploy pods sequentially (one-by-one) instead of all at once
./perf-test.sh --sequential

# Keep deployments between tests (no cleanup)
./perf-test.sh --no-cleanup

# Combine options
./perf-test.sh --replicas 25,50,100 --sequential --no-cleanup

# Check CSI component status before testing
./perf-test.sh --check-csi
```

### Test Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--replicas N,N,N` | Comma-separated replica counts to test | 50,100,150,200 |
| `--sequential` | Deploy pods one-by-one instead of parallel | false |
| `--no-cleanup` | Don't cleanup between different replica tests | false |
| `--no-export` | Don't export results to file | false |
| `--check-csi` | Check CSI component status and exit | - |

### Metrics Collected

The performance test collects comprehensive metrics for each test run:

#### Pod Startup Metrics
- **Total time to all pods running**: Time for all replicas to reach Running state
- **Individual pod startup times**: Time from deployment to each pod becoming ready
- **Statistical distribution**:
    - Average, Minimum, Maximum startup times
    - P50 (Median), P90, P99 percentiles
    - Time distribution in 5-second buckets

#### CSI Mount Metrics
- **Successful mounts**: Number of pods with successfully mounted CSI volumes
- **Failed mounts**: Number of volume mount failures
- **Mount success rate**: Percentage of successful mounts
- **Volume-related events**: Errors and warnings from CSI operations

#### System Metrics
- **CSI driver pods**: Number of CSI driver pods running
- **SPIRE provider pods**: Number of SPIRE CSI provider pods
- **Error counts**: CSI driver and provider errors in the last 5 minutes

### Test Output

#### Console Output
The test provides real-time feedback during execution:
```
[INFO] Measuring pod creation and startup times for 50 replicas...
  [45s] Running: 50/50 | Timed: 50 | Status: 50 Running
[PASS] All 50 pods are running in 45s

Performance Results for 50 Replicas:
===========================================
  Total test time: 48s
  Time to all pods running: 45s
  
  Pod Startup Time Statistics:
    Average: 12.5s
    Minimum: 3s
    P50 (Median): 11s
    P90: 22s
    P99: 41s
    Maximum: 43s
    
  Successful CSI mounts: 50
  Failed CSI mounts: 0
  Mount success rate: 100%
  CSI/Provider errors: 0/0
```

#### Exported Results

Results are saved in two formats:

1. **JSON Results** (`perf_test_TIMESTAMP.json`):
```json
{
  "test_number": 1,
  "replicas": 50,
  "timestamp": "2024-03-15T10:30:00Z",
  "total_test_time_seconds": 48,
  "all_pods_running_time_seconds": 45,
  "avg_startup_time": 12.5,
  "min_startup_time": 3,
  "max_startup_time": 43,
  "p50_startup_time": 11,
  "p90_startup_time": 22,
  "p99_startup_time": 41,
  "successful_mounts": 50,
  "failed_mounts": 0,
  "mount_success_rate": 100,
  "csi_driver_pods": 3,
  "provider_pods": 3,
  "csi_errors": 0,
  "provider_errors": 0
}
```

2. **Summary Report** (`perf_summary_TIMESTAMP.txt`):
    - Consolidated view of all test runs
    - Key metrics comparison across replica counts
    - Test configuration details

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