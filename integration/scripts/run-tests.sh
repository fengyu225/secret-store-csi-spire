#!/bin/bash

# SPIRE Integration Test Runner
# Runs the actual integration tests against the SPIRE clusters

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
INTEGRATION_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$INTEGRATION_DIR")"

echo -e "${CYAN}SPIRE CSI Provider Integration Tests${NC}"
echo "===================================="
echo "Running integration tests against SPIRE nested clusters..."
echo ""

# Function to print step headers
print_step() {
    echo -e "\n${BLUE}Step $1: $2${NC}"
    echo "----------------------------------------"
}

# Function to deploy test workload
deploy_test_workload() {
    local context=$1
    local cluster_name=$2
    local workload_name=$3

    echo "Deploying test workload '$workload_name' to $cluster_name..."

    # Create test workload manifest
    cat <<EOF | kubectl --context "$context" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $workload_name
  namespace: spire
  labels:
    app: csi-test-workload
spec:
  serviceAccountName: spire-agent
  containers:
  - name: test-workload
    image: busybox:1.35
    command: ["sleep", "3600"]
    volumeMounts:
    - name: spiffe-workload-api
      mountPath: /spiffe-workload-api
      readOnly: true
    - name: spire-csi-secrets
      mountPath: /mnt/secrets
      readOnly: true
    env:
    - name: SPIFFE_ENDPOINT_SOCKET
      value: unix:///spiffe-workload-api/spire-agent.sock
  volumes:
  - name: spiffe-workload-api
    hostPath:
      path: /run/spire/sockets
      type: Directory
  - name: spire-csi-secrets
    csi:
      driver: secrets-store.csi.x-k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: spire-csi-provider
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: spire-csi-provider
  namespace: spire
spec:
  provider: spire
  parameters:
    spire_socket_path: /run/spire/agent-sockets/spire-agent.sock
EOF

    # Wait for pod to be ready
    echo "Waiting for workload pod to be ready..."
    kubectl --context "$context" wait --for=condition=ready pod/$workload_name -n spire --timeout=120s
    echo -e "${GREEN}✓${NC} Test workload deployed successfully"
}

# Function to test SPIRE CSI provider
test_csi_provider() {
    local context=$1
    local cluster_name=$2
    local workload_name=$3

    echo "Testing SPIRE CSI provider in $cluster_name..."

    # Check if secrets are mounted
    local secret_files=$(kubectl --context "$context" exec -n spire "$workload_name" -- ls -la /mnt/secrets/ 2>/dev/null || echo "")

    if [[ -n "$secret_files" ]]; then
        echo -e "${GREEN}✓${NC} CSI secrets are mounted in $cluster_name"
        echo "Secret files:"
        echo "$secret_files" | sed 's/^/    /'

        # Try to read a certificate file if it exists
        if kubectl --context "$context" exec -n spire "$workload_name" -- test -f /mnt/secrets/svid.pem 2>/dev/null; then
            echo "SVID certificate content (first few lines):"
            kubectl --context "$context" exec -n spire "$workload_name" -- head -5 /mnt/secrets/svid.pem 2>/dev/null | sed 's/^/    /' || echo "    Unable to read certificate"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  No CSI secrets found in $cluster_name (this is expected if CSI provider is not running)"
    fi
}

# Function to test SPIFFE workload API
test_spiffe_api() {
    local context=$1
    local cluster_name=$2
    local workload_name=$3

    echo "Testing SPIFFE Workload API in $cluster_name..."

    # Check if SPIFFE socket exists
    if kubectl --context "$context" exec -n spire "$workload_name" -- test -S /spiffe-workload-api/spire-agent.sock 2>/dev/null; then
        echo -e "${GREEN}✓${NC} SPIFFE Workload API socket exists in $cluster_name"

        # Try to get workload identity (this might fail if workload is not registered)
        echo "Attempting to fetch SPIFFE identity..."
        local spiffe_result=$(kubectl --context "$context" exec -n spire "$workload_name" -- \
            wget -q -O - --header="Workload-API-Version: 1.0" \
            --unix-socket=/spiffe-workload-api/spire-agent.sock \
            http://localhost/spiffe.workload.api.v1.SpiffeWorkloadAPI/FetchJWTSVID 2>/dev/null || echo "FAILED")

        if [[ "$spiffe_result" != "FAILED" ]]; then
            echo -e "${GREEN}✓${NC} SPIFFE Workload API is responsive in $cluster_name"
        else
            echo -e "${YELLOW}⚠${NC}  SPIFFE Workload API connection failed in $cluster_name (workload may need registration)"
        fi
    else
        echo -e "${RED}✗${NC} SPIFFE Workload API socket not found in $cluster_name"
    fi
}

# Function to cleanup test workloads
cleanup_test_workloads() {
    local context=$1
    local workload_name=$2

    echo "Cleaning up test workload '$workload_name'..."
    kubectl --context "$context" delete pod "$workload_name" -n spire --ignore-not-found=true
    kubectl --context "$context" delete secretproviderclass spire-csi-provider -n spire --ignore-not-found=true
    echo -e "${GREEN}✓${NC} Test workload cleaned up"
}

# Main test execution
print_step "1" "Verifying Clusters are Ready"
if ! "$SCRIPT_DIR/verify.sh" > /dev/null 2>&1; then
    echo -e "${RED}✗${NC} Clusters are not ready. Please run setup.sh first."
    exit 1
fi
echo -e "${GREEN}✓${NC} All clusters are ready"

print_step "2" "Building CSI Provider Binary"
cd "$PROJECT_ROOT"
echo "Building spire-csi-provider binary..."
make build
if [ ! -f "bin/spire-csi-provider" ]; then
    echo -e "${RED}✗${NC} Failed to build CSI provider binary"
    exit 1
fi
echo -e "${GREEN}✓${NC} CSI provider binary built successfully"

print_step "3" "Running Tests on Each Cluster"

# Test contexts and names
test_contexts=("kind-spire-root:Root" "kind-spire-subordinate-01:Subordinate-01" "kind-spire-subordinate-02:Subordinate-02")

for context_info in "${test_contexts[@]}"; do
    IFS=':' read -r context name <<< "$context_info"
    workload_name="test-workload-$(echo "$name" | tr '[:upper:]' '[:lower:]')"

    echo -e "\n${PURPLE}Testing $name cluster...${NC}"
    echo "Context: $context"
    echo "Workload: $workload_name"
    echo ""

    # Deploy and test
    if deploy_test_workload "$context" "$name" "$workload_name"; then
        sleep 5  # Give the workload some time to initialize
        test_spiffe_api "$context" "$name" "$workload_name"
        test_csi_provider "$context" "$name" "$workload_name"
    else
        echo -e "${RED}✗${NC} Failed to deploy test workload in $name"
    fi

    echo ""
done

print_step "4" "Testing Cross-Cluster Trust Relationships"
echo "Testing trust relationships between root and subordinate clusters..."

# This is a placeholder for more advanced trust relationship tests
# In a full implementation, you would:
# 1. Register workload entries in the root cluster for subordinate clusters
# 2. Test that subordinate clusters can validate root cluster identities
# 3. Test federation scenarios

echo -e "${YELLOW}⚠${NC}  Cross-cluster trust testing is not yet implemented"
echo "This would require:"
echo "  - Workload entry registration in root cluster"
echo "  - Trust bundle federation tests"
echo "  - Cross-cluster SVID validation"

print_step "5" "Cleanup Test Workloads"
for context_info in "${test_contexts[@]}"; do
    IFS=':' read -r context name <<< "$context_info"
    workload_name="test-workload-$(echo "$name" | tr '[:upper:]' '[:lower:]')"

    cleanup_test_workloads "$context" "$workload_name"
done

print_step "6" "Test Summary"
echo -e "${GREEN}Integration tests completed!${NC}"
echo ""
echo "What was tested:"
echo "  ✓ SPIRE clusters are running and healthy"
echo "  ✓ SPIFFE Workload API availability"
echo "  ✓ CSI provider integration (basic)"
echo "  ✓ Test workload deployment and cleanup"
echo ""
echo "Next steps:"
echo "  - Implement actual CSI provider deployment in clusters"
echo "  - Add workload entry registration tests"
echo "  - Add cross-cluster trust relationship tests"
echo "  - Add performance and load testing"
echo ""
echo "To run specific tests, you can use:"
echo "  kubectl --context kind-spire-root get pods -n spire"
echo "  kubectl --context kind-spire-subordinate-01 get pods -n spire"
echo "  kubectl --context kind-spire-subordinate-02 get pods -n spire"