#!/bin/bash

create_kind_cluster() {
    local cluster_name=$1
    local config_dir=$2

    echo "Creating $cluster_name cluster..."
    cd "$config_dir"

    if kind get clusters | grep -q "$cluster_name"; then
        print_warning "$cluster_name cluster already exists, deleting first..."
        kind delete cluster --name "$cluster_name"
    fi

    kind create cluster --config kind-config.yaml
    print_success "$cluster_name cluster created"
}

create_all_clusters() {
    local integration_dir=$1

    create_kind_cluster "$ROOT_CLUSTER" "$integration_dir/root"
    create_kind_cluster "$SUB01_CLUSTER" "$integration_dir/subordinate-01"
    create_kind_cluster "$SUB02_CLUSTER" "$integration_dir/subordinate-02"
    create_kind_cluster "workload" "$integration_dir/workload"
}

install_ingress() {
    kubectl --context "kind-$ROOT_CLUSTER" apply -f \
        https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

    echo "Waiting for ingress controller..."
    wait_for_pod "kind-$ROOT_CLUSTER" "ingress-nginx" "app.kubernetes.io/component=controller" "90s"
    print_success "Ingress controller ready"
}
