#!/bin/bash

set -e

# SCRIPT_DIR and INTEGRATION_DIR are already defined when sourced from setup.sh
if [[ -z "${SCRIPT_DIR:-}" ]]; then
    readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
    readonly INTEGRATION_DIR="$(dirname "$SCRIPT_DIR")"
fi

source "$SCRIPT_DIR/lib/common.sh"

install_spire_csi() {
    local integration_dir=$1
    local workload_context="kind-workload"
    local csi_dir="$integration_dir/workload/spire-csi"

    print_step "10" "Installing SPIRE CSI Provider"

    if [ ! -d "$csi_dir" ]; then
        print_warning "SPIRE CSI directory not found at $csi_dir, skipping CSI installation"
        return 0
    fi

    echo "Installing CSI Driver CRDs..."

    kubectl --context "$workload_context" apply -f "$csi_dir/crds/secrets-store.csi.x-k8s.io_secretproviderclasses.yaml"
    kubectl --context "$workload_context" apply -f "$csi_dir/crds/secrets-store.csi.x-k8s.io_secretproviderclasspodstatuses.yaml"

    sleep 5

    echo "Installing SPIRE CSI components using kustomize..."

    kubectl --context "$workload_context" apply -k "$csi_dir"

    echo "Waiting for CSI Driver to be ready..."

    wait_for_pod "$workload_context" "kube-system" "app=secrets-store-csi-driver" "120s" || {
        print_warning "CSI driver pods not ready yet, continuing..."
    }

    if kubectl --context "$workload_context" get daemonset -n csi spire-csi-provider &>/dev/null; then
        wait_for_pod "$workload_context" "csi" "app=spire-csi-provider" "120s" || {
            print_warning "SPIRE CSI provider pods not ready yet, continuing..."
        }
    fi

    print_success "SPIRE CSI Provider installed"

    echo ""
    echo "CSI Driver status:"
    kubectl --context "$workload_context" get pods -n kube-system -l app=secrets-store-csi-driver --no-headers 2>/dev/null | \
        awk '{printf "  %-50s %s\n", $1, $3}' || echo "  No CSI driver pods found"

    echo ""
    echo "SPIRE CSI Provider status:"
    kubectl --context "$workload_context" get pods -n csi -l app=spire-csi-provider --no-headers 2>/dev/null | \
        awk '{printf "  %-50s %s\n", $1, $3}' || echo "  No SPIRE CSI provider pods found"

    echo ""
    echo "CSI Resources created:"
    kubectl --context "$workload_context" get csidriver 2>/dev/null | grep -v NAME | \
        awk '{printf "  CSIDriver: %s\n", $1}' || echo "  No CSI drivers found"
    kubectl --context "$workload_context" get secretproviderclass -A 2>/dev/null | grep -v NAME | \
        awk '{printf "  SecretProviderClass: %s/%s\n", $1, $2}' || echo "  No SecretProviderClasses found"
}