#!/bin/bash

deploy_root_spire() {
    local integration_dir=$1
    cd "$integration_dir/root"

    kubectl --context "kind-$ROOT_CLUSTER" apply -f namespace.yaml
    kubectl --context "kind-$ROOT_CLUSTER" apply -f crds/
    sleep 5

    local sub01_ip=$(get_cluster_ip "$SUB01_CLUSTER")
    local sub02_ip=$(get_cluster_ip "$SUB02_CLUSTER")

    echo "Subordinate-01 IP: $sub01_ip"
    echo "Subordinate-02 IP: $sub02_ip"

    create_kubeconfig "$SUB01_CLUSTER" "$sub01_ip" "/tmp/subordinate-01-kubeconfig"
    create_kubeconfig "$SUB02_CLUSTER" "$sub02_ip" "/tmp/subordinate-02-kubeconfig"

    for i in 01 02; do
        kubectl --context "kind-$ROOT_CLUSTER" create secret generic "spire-server-kubeconfigs-child-${i}" \
            --namespace spire \
            --from-file=child-cluster="/tmp/subordinate-${i}-kubeconfig" \
            --dry-run=client -o yaml | kubectl --context "kind-$ROOT_CLUSTER" apply -f -
    done

    kubectl --context "kind-$ROOT_CLUSTER" apply -k .
    wait_for_pod "kind-$ROOT_CLUSTER" "spire" "app=spire-server"
    print_success "SPIRE root cluster deployed"
}

get_root_bundle() {
    local root_bundle=""

    for i in {1..10}; do
        echo "Getting trust bundle from root cluster (attempt $i/10)..."
        root_bundle=$(kubectl --context "kind-$ROOT_CLUSTER" -n spire exec -i spire-server-0 -c spire-server -- \
            /opt/spire/bin/spire-server bundle show -format pem 2>/dev/null || echo "")

        if [ -n "$root_bundle" ] && [[ "$root_bundle" == *"BEGIN CERTIFICATE"* ]]; then
            print_success "Successfully obtained root trust bundle"
            echo "$root_bundle"
            return 0
        fi
        sleep 5
    done

    print_error "Failed to get trust bundle from root server"
    return 1
}

deploy_subordinate_spire() {
    local cluster_name=$1
    local cluster_dir=$2
    local root_bundle=$3

    kubectl --context "kind-$cluster_name" apply -f "$cluster_dir/namespace.yaml"

    kubectl --context "kind-$cluster_name" create secret generic "workload-kubeconfig" \
        --namespace spire \
        --from-literal=workload-kubeconfig="" \
        --dry-run=client -o yaml | kubectl --context "kind-$cluster_name" apply -f -

    kubectl --context "kind-$cluster_name" -n spire create configmap spire-root-bundle \
        --from-literal=bundle.crt="$root_bundle" \
        --dry-run=client -o yaml | kubectl --context "kind-$cluster_name" apply -f -

    cd "$cluster_dir"
    kubectl --context "kind-$cluster_name" apply -f crds/
    sleep 5
    kubectl --context "kind-$cluster_name" apply -k .

    wait_for_pod "kind-$cluster_name" "spire" "app=spire-server"
    wait_for_pod "kind-$cluster_name" "spire" "app=spire-root-agent"
    print_success "SPIRE $cluster_name deployed"
}

get_host_ip() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "172.17.0.1"
    else
        echo "host.docker.internal"
    fi
}

deploy_workload_spire() {
    local integration_dir=$1
    local workload_context="kind-workload"
    local sub01_context="kind-spire-subordinate-01"
    local sub02_context="kind-spire-subordinate-02"
    export SUB01_PORT="30081"
    export SUB02_PORT="30082"

    echo "Deploying workload SPIRE cluster..."

    echo "Configuring trust bundles..."

    local sub01_bundle=$(kubectl --context "$sub01_context" -n spire exec -i spire-server-0 -c spire-server -- \
        /opt/spire/bin/spire-server bundle show -format pem 2>/dev/null)
    local sub02_bundle=$(kubectl --context "$sub02_context" -n spire exec -i spire-server-0 -c spire-server -- \
        /opt/spire/bin/spire-server bundle show -format pem 2>/dev/null)

    if [ -z "$sub01_bundle" ] || [ -z "$sub02_bundle" ]; then
        print_error "Failed to retrieve trust bundles"
        return 1
    fi

    kubectl --context "$workload_context" create namespace spire --dry-run=client -o yaml | \
        kubectl --context "$workload_context" apply -f -

    kubectl --context "$workload_context" -n spire create configmap spire-bundle-child-01 \
        --from-literal=bundle.crt="$sub01_bundle" \
        --dry-run=client -o yaml | kubectl --context "$workload_context" apply -f -

    kubectl --context "$workload_context" -n spire create configmap spire-bundle-child-02 \
        --from-literal=bundle.crt="$sub02_bundle" \
        --dry-run=client -o yaml | kubectl --context "$workload_context" apply -f -

    export SUB01_IP=$(docker inspect "spire-subordinate-01-control-plane" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
    export SUB02_IP=$(docker inspect "spire-subordinate-02-control-plane" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

    echo "Using Subordinate-01 IP: $SUB01_IP"
    echo "Using Subordinate-02 IP: $SUB02_IP"

    export HOST_IP=$SUB01_IP
    envsubst < "$integration_dir/workload/configmaps/spire-agent-child-01-template.yaml" | \
        kubectl --context "$workload_context" apply -f -

    export HOST_IP=$SUB02_IP
    envsubst < "$integration_dir/workload/configmaps/spire-agent-child-02-template.yaml" | \
        kubectl --context "$workload_context" apply -f -

    echo "Applying CRDs..."
    kubectl --context "$workload_context" apply -f "$integration_dir/workload/crds/"
    kubectl --context "$workload_context" apply -k "$integration_dir/workload/spire-csi/crds"

    echo "Waiting for CRDs to be established..."
    kubectl --context "$workload_context" wait --for condition=established --timeout=60s \
        crd/clusterfederatedtrustdomains.spire.spiffe.io \
        crd/clusterspiffeids.spire.spiffe.io \
        crd/clusterstaticentries.spire.spiffe.io \
        crd/controllermanagerconfigs.spire.spiffe.io || true

    if kubectl --context "$workload_context" get crd secretproviderclasses.secrets-store.csi.x-k8s.io &>/dev/null; then
        echo "Waiting for SecretProviderClass CRD to be established..."
        kubectl --context "$workload_context" wait --for condition=established --timeout=60s \
            crd/secretproviderclasses.secrets-store.csi.x-k8s.io || true
    fi

    echo "Applying SPIRE CSI Provider..."
    kubectl --context "$workload_context" apply -k "$integration_dir/workload/spire-csi/"

    sleep 10

    echo "Applying workload resources..."
    kubectl --context "$workload_context" apply -k "$integration_dir/workload/"

    print_success "Workload SPIRE cluster deployed"
}