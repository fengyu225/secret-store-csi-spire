#!/bin/bash

set -e

# Source libraries
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
INTEGRATION_DIR="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/lib/common.sh"

# Configuration
readonly WORKLOAD_DIR="$INTEGRATION_DIR/workload"
readonly WORKLOAD_CONTEXT="kind-workload"
readonly SUB01_CONTEXT="kind-spire-subordinate-01"
readonly SUB02_CONTEXT="kind-spire-subordinate-02"
export SUB01_PORT="30081"
export SUB02_PORT="30082"

# Get host IP for Kind networking
get_host_ip() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "172.17.0.1"
    else
        echo "host.docker.internal"
    fi
}

# Create workload cluster
create_workload_cluster() {
    if ! kind get clusters | grep -q "workload"; then
        print_warning "Creating workload cluster..."
        kind create cluster --config "$WORKLOAD_DIR/kind-config.yaml"
        print_success "Workload cluster created"
    else
        print_success "Workload cluster exists"
    fi
}

# Setup subordinate clusters
setup_subordinate_clusters() {
    print_step "1" "Configuring Subordinate Clusters"

    # Apply NodePort services
    kubectl --context "$SUB01_CONTEXT" apply -f \
        "$INTEGRATION_DIR/subordinate-01/services/spire-server-nodeport.yaml"
    kubectl --context "$SUB02_CONTEXT" apply -f \
        "$INTEGRATION_DIR/subordinate-02/services/spire-server-nodeport.yaml"

    print_success "Subordinate clusters configured"
}

# Configure trust bundles
configure_trust_bundles() {
    print_step "2" "Configuring Trust Bundles"

    # Get bundles
    local sub01_bundle=$(kubectl --context "$SUB01_CONTEXT" -n spire exec -i spire-server-0 -c spire-server -- \
        /opt/spire/bin/spire-server bundle show -format pem 2>/dev/null)
    local sub02_bundle=$(kubectl --context "$SUB02_CONTEXT" -n spire exec -i spire-server-0 -c spire-server -- \
        /opt/spire/bin/spire-server bundle show -format pem 2>/dev/null)

    if [ -z "$sub01_bundle" ] || [ -z "$sub02_bundle" ]; then
        print_error "Failed to retrieve trust bundles"
        return 1
    fi

    # Create namespace
    kubectl --context "$WORKLOAD_CONTEXT" create namespace spire --dry-run=client -o yaml | \
        kubectl --context "$WORKLOAD_CONTEXT" apply -f -

    # Create bundle ConfigMaps
    kubectl --context "$WORKLOAD_CONTEXT" -n spire create configmap spire-bundle-child-01 \
        --from-literal=bundle.crt="$sub01_bundle" \
        --dry-run=client -o yaml | kubectl --context "$WORKLOAD_CONTEXT" apply -f -

    kubectl --context "$WORKLOAD_CONTEXT" -n spire create configmap spire-bundle-child-02 \
        --from-literal=bundle.crt="$sub02_bundle" \
        --dry-run=client -o yaml | kubectl --context "$WORKLOAD_CONTEXT" apply -f -

    print_success "Trust bundles configured"
}

# Apply agent configurations
apply_agent_configs() {
    print_step "3" "Applying Agent Configurations"

    export HOST_IP=$(get_host_ip)
    echo "Using host IP: $HOST_IP"

    # Apply templates with substitution
    envsubst < "$WORKLOAD_DIR/configmaps/spire-agent-child-01-template.yaml" | \
        kubectl --context "$WORKLOAD_CONTEXT" apply -f -

    envsubst < "$WORKLOAD_DIR/configmaps/spire-agent-child-02-template.yaml" | \
        kubectl --context "$WORKLOAD_CONTEXT" apply -f -

    print_success "Agent configurations applied"
}

# Deploy workload components
deploy_workload_components() {
    print_step "4" "Deploying Workload Components"

    cd "$WORKLOAD_DIR"
    kubectl --context "$WORKLOAD_CONTEXT" apply -k .

    print_success "Workload components deployed"
}

# Wait for components
wait_for_components() {
    print_step "5" "Waiting for Components"

    wait_for_pod "$WORKLOAD_CONTEXT" "spire" "app=spire-agent-child-01" "120s"
    wait_for_pod "$WORKLOAD_CONTEXT" "spire" "app=spire-agent-child-02" "120s"
    wait_for_pod "$WORKLOAD_CONTEXT" "spire" "app=spire-ha-agent" "120s"

    # Wait for CSI if directory exists
    if [ -d "$WORKLOAD_DIR/spire-csi" ]; then
        wait_for_pod "$WORKLOAD_CONTEXT" "kube-system" "app=csi-secrets-store" "120s" || true
        wait_for_pod "$WORKLOAD_CONTEXT" "csi" "app.kubernetes.io/name=spire-csi-provider" "120s" || true
    fi

    print_success "All components ready"
}

# Deploy test workload
deploy_test_workload() {
    if [ -f "$WORKLOAD_DIR/spire-csi/workload-a.yaml" ]; then
        print_step "6" "Deploying Test Workload"
        kubectl --context "$WORKLOAD_CONTEXT" apply -f "$WORKLOAD_DIR/spire-csi/workload-a.yaml"
        print_success "Test workload deployed"
    fi
}

# Verify setup
verify_setup() {
    print_step "7" "Verifying Setup"

    echo "Checking agent registrations..."
    kubectl --context "$SUB01_CONTEXT" exec -n spire spire-server-0 -c spire-server -- \
        /opt/spire/bin/spire-server entry show -selector k8s_psat:cluster:workloads 2>/dev/null | \
        grep -E "Entry ID|SPIFFE ID" || echo "No entries found in sub01"

    kubectl --context "$SUB02_CONTEXT" exec -n spire spire-server-0 -c spire-server -- \
        /opt/spire/bin/spire-server entry show -selector k8s_psat:cluster:workloads 2>/dev/null | \
        grep -E "Entry ID|SPIFFE ID" || echo "No entries found in sub02"

    echo -e "\nWorkload cluster pods:"
    kubectl --context "$WORKLOAD_CONTEXT" get pods -n spire --no-headers | \
        awk '{printf "  %-40s %s\n", $1, $3}'

    print_success "Verification complete"
}

# Main
main() {
    echo "======================================"
    echo "Workload Cluster Deployment"
    echo "======================================"

    # Check prerequisites
    command -v envsubst >/dev/null 2>&1 || { print_error "envsubst is required"; exit 1; }

    create_workload_cluster
    setup_subordinate_clusters
    configure_trust_bundles
    apply_agent_configs
    deploy_workload_components
    wait_for_components
    deploy_test_workload
    verify_setup

    echo ""
    echo "======================================"
    echo "Deployment Complete!"
    echo "======================================"
    echo ""
    echo "Commands:"
    echo "  kubectl --context $WORKLOAD_CONTEXT get pods -A"
    echo "  kubectl --context $WORKLOAD_CONTEXT logs -n spire daemonset/spire-agent-child-01"
}

main "$@"
