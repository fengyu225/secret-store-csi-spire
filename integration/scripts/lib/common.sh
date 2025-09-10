#!/bin/bash

# Configuration - only set if not already defined
if [[ -z "${ROOT_CLUSTER:-}" ]]; then
    readonly ROOT_CLUSTER="spire-root"
    readonly SUB01_CLUSTER="spire-subordinate-01"
    readonly SUB02_CLUSTER="spire-subordinate-02"
    readonly DB_USER="spire"
    readonly DB_PASSWORD="password"
    readonly DB_NAME="spire"
    readonly NODEPORT="30443"
fi

# Colors - only set if not already defined
if [[ -z "${RED:-}" ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly NC='\033[0m'
fi

# Helper functions
print_step() {
    echo -e "\n${BLUE}Step $1: $2${NC}"
    echo "----------------------------------------"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
    return 1
}

wait_for_pod() {
    local context=$1
    local namespace=$2
    local selector=$3
    local timeout=${4:-120s}

    kubectl --context "$context" wait --namespace "$namespace" \
        --for=condition=ready pod \
        --selector="$selector" \
        --timeout="$timeout"
}