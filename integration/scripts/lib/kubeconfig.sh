#!/bin/bash

get_cluster_ip() {
    local cluster_name=$1
    docker inspect "${cluster_name}-control-plane" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

create_kubeconfig() {
    local cluster_name=$1
    local cluster_ip=$2
    local output_file=$3

    kubectl config view --context="kind-$cluster_name" --minify --flatten | \
        sed "s|server: https://127.0.0.1:[0-9]*|server: https://$cluster_ip:6443|g" | \
        sed '/certificate-authority-data:/d' | \
        awk '/server: https:\/\/'"$cluster_ip"':6443/{print; print "    insecure-skip-tls-verify: true"; next}1' > "$output_file"
}

setup_subordinate_kubeconfigs() {
    echo "Setting up kubeconfigs for workload cluster node attestation..."

    local workload_ip=$(get_cluster_ip "workload")
    echo "Workload cluster IP: $workload_ip"

    create_kubeconfig "workload" "$workload_ip" "/tmp/workload-kubeconfig-sub01"
    create_kubeconfig "workload" "$workload_ip" "/tmp/workload-kubeconfig-sub02"

    kubectl --context "kind-$SUB01_CLUSTER" create secret generic "workload-kubeconfig" \
        --namespace spire \
        --from-file=workload-kubeconfig="/tmp/workload-kubeconfig-sub01" \
        --dry-run=client -o yaml | kubectl --context "kind-$SUB01_CLUSTER" apply -f -

    kubectl --context "kind-$SUB02_CLUSTER" create secret generic "workload-kubeconfig" \
        --namespace spire \
        --from-file=workload-kubeconfig="/tmp/workload-kubeconfig-sub02" \
        --dry-run=client -o yaml | kubectl --context "kind-$SUB02_CLUSTER" apply -f -

    print_success "Workload cluster kubeconfigs configured"
}