#!/bin/bash

set -e

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
readonly INTEGRATION_DIR="$(dirname "$SCRIPT_DIR")"

source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/prerequisites.sh"
source "$SCRIPT_DIR/lib/database.sh"
source "$SCRIPT_DIR/lib/cluster.sh"
source "$SCRIPT_DIR/lib/kubeconfig.sh"
source "$SCRIPT_DIR/lib/spire.sh"
source "$SCRIPT_DIR/lib/images.sh"
source "$SCRIPT_DIR/install-spire-csi.sh"


restart_spire_components() {
    echo "Restarting SPIRE components..."

    echo "  Restarting root SPIRE server..."
    kubectl --context "kind-$ROOT_CLUSTER" -n spire rollout restart statefulset/spire-server

    for cluster in "$SUB01_CLUSTER" "$SUB02_CLUSTER"; do
        echo "  Restarting SPIRE components in $cluster..."
        kubectl --context "kind-$cluster" -n spire rollout restart statefulset/spire-server
        kubectl --context "kind-$cluster" -n spire rollout restart daemonset/spire-root-agent
    done

    echo "  Restarting workload SPIRE agents..."
    kubectl --context "kind-workload" -n spire rollout restart daemonset/spire-agent-child-01
    kubectl --context "kind-workload" -n spire rollout restart daemonset/spire-agent-child-02

    echo "Waiting for components to be ready after restart..."
    sleep 10

    wait_for_pod "kind-$ROOT_CLUSTER" "spire" "app=spire-server" "120s"

    for cluster in "$SUB01_CLUSTER" "$SUB02_CLUSTER"; do
        wait_for_pod "kind-$cluster" "spire" "app=spire-server" "120s"
        wait_for_pod "kind-$cluster" "spire" "app=spire-root-agent" "120s"
    done

    wait_for_pod "kind-workload" "spire" "app=spire-agent-child-01" "120s"
    wait_for_pod "kind-workload" "spire" "app=spire-agent-child-02" "120s"

    print_success "All SPIRE components restarted successfully"
}

verify_final_setup() {
    print_step "13" "Verifying Final Setup"

    echo "Checking all components..."
    echo ""

    echo "Root Cluster ($ROOT_CLUSTER):"
    kubectl --context "kind-$ROOT_CLUSTER" get pods -n spire --no-headers | \
        awk '{printf "  %-50s %s\n", $1, $3}'

    echo ""
    echo "Subordinate-01 Cluster ($SUB01_CLUSTER):"
    kubectl --context "kind-$SUB01_CLUSTER" get pods -n spire --no-headers | \
        awk '{printf "  %-50s %s\n", $1, $3}'

    echo ""
    echo "Subordinate-02 Cluster ($SUB02_CLUSTER):"
    kubectl --context "kind-$SUB02_CLUSTER" get pods -n spire --no-headers | \
        awk '{printf "  %-50s %s\n", $1, $3}'

    echo ""
    echo "Workload Cluster:"
    echo "  SPIRE Agents:"
    kubectl --context "kind-workload" get pods -n spire --no-headers | \
        awk '{printf "    %-48s %s\n", $1, $3}'

    if kubectl --context "kind-workload" get pods -n kube-system -l app=secrets-store-csi-driver &>/dev/null; then
        echo "  CSI Components:"
        kubectl --context "kind-workload" get pods -n kube-system -l app=secrets-store-csi-driver --no-headers | \
            awk '{printf "    %-48s %s\n", $1, $3}'
    fi

    if kubectl --context "kind-workload" get pods -n csi &>/dev/null; then
        kubectl --context "kind-workload" get pods -n csi --no-headers 2>/dev/null | \
            awk '{printf "    %-48s %s\n", $1, $3}'
    fi
}

main() {
    print_step "1" "Checking Prerequisites"
    check_prerequisites || exit 1

    print_step "2" "Starting PostgreSQL Databases"
    start_databases "$INTEGRATION_DIR" || exit 1
    create_db_secret "$INTEGRATION_DIR"

    print_step "3" "Creating Kind Clusters"
    create_all_clusters "$INTEGRATION_DIR"

    print_step "4" "Preparing Container Images"
    prepare_images || exit 1

    print_step "5" "Installing Ingress Controller"
    install_ingress

    print_step "6" "Deploying Root SPIRE"
    deploy_root_spire "$INTEGRATION_DIR"

    print_step "7" "Getting Root Trust Bundle"
    sleep 10
    ROOT_BUNDLE=$(get_root_bundle) || exit 1

    print_step "8" "Deploying Subordinate SPIRE Clusters"
    deploy_subordinate_spire "$SUB01_CLUSTER" "$INTEGRATION_DIR/subordinate-01" "$ROOT_BUNDLE"
    deploy_subordinate_spire "$SUB02_CLUSTER" "$INTEGRATION_DIR/subordinate-02" "$ROOT_BUNDLE"

    print_step "9" "Setting up Kubeconfigs for Workload Cluster Node Attestation"
    setup_subordinate_kubeconfigs

    print_step "10" "Deploying Workload SPIRE Cluster"
    deploy_workload_spire "$INTEGRATION_DIR"

    print_step "11" "Installing SPIRE CSI Provider"
    install_spire_csi "$INTEGRATION_DIR"

    print_step "12" "Restarting SPIRE Components"
    restart_spire_components

    verify_final_setup

    print_step "14" "Setup Complete"
    echo -e "${GREEN}All clusters are ready with SPIRE CSI Provider installed!${NC}"
    echo ""
    echo "Cluster contexts:"
    echo "  - kind-$ROOT_CLUSTER (Root SPIRE Server)"
    echo "  - kind-$SUB01_CLUSTER (Subordinate SPIRE Server 01)"
    echo "  - kind-$SUB02_CLUSTER (Subordinate SPIRE Server 02)"
    echo "  - kind-workload (Workload cluster with CSI)"
    echo ""
    echo "Key endpoints:"
    echo "  - Root SPIRE server: localhost:$NODEPORT"
    echo ""
    echo "CSI Components:"
    echo "  - Secrets Store CSI Driver: Installed in kube-system namespace"
    echo "  - SPIRE CSI Provider: Installed in csi namespace"
    echo "  - Test workload: Available in spire namespace"
    echo ""
    echo "Next steps:"
    echo "  1. Check CSI driver logs: kubectl --context kind-workload logs -n kube-system -l app=secrets-store-csi-driver"
    echo "  2. Check SPIRE CSI provider logs: kubectl --context kind-workload logs -n csi -l app=spire-csi-provider"
    echo "  3. Check test workload: kubectl --context kind-workload get pods -n spire"
    echo "  4. Verify mounted secrets: kubectl --context kind-workload exec -n spire <workload-pod> -- ls /mnt/secrets/"
}

main "$@"