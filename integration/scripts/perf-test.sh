#!/bin/bash

# SPIRE CSI Provider Performance Test with SVID Rotation Verification

set -e

REPLICA_COUNTS=(50 100 150 200)
TEST_NAMESPACE="perf-test"
TEST_DEPLOYMENT="perf-workload"
WORKLOAD_CONTEXT="kind-workload"
SUB01_CONTEXT="kind-spire-subordinate-01"
SUB02_CONTEXT="kind-spire-subordinate-02"

SEQUENTIAL_MODE=false
CLEANUP_BETWEEN_TESTS=true
EXPORT_RESULTS=true
CHECK_SVID_ROTATION=true

readonly SVID_PATH="/run/spire/x509/cert.pem"
readonly ROTATION_CHECK_INTERVAL=10
readonly SVID_ROTATION_TIMEOUT=60

while [[ $# -gt 0 ]]; do
    case $1 in
        --sequential)
            SEQUENTIAL_MODE=true
            shift
            ;;
        --no-cleanup)
            CLEANUP_BETWEEN_TESTS=false
            shift
            ;;
        --replicas)
            IFS=',' read -ra REPLICA_COUNTS <<< "$2"
            shift 2
            ;;
        --no-export)
            EXPORT_RESULTS=false
            shift
            ;;
        --no-svid-rotation)
            CHECK_SVID_ROTATION=false
            shift
            ;;
        --svid-timeout)
            SVID_ROTATION_TIMEOUT="$2"
            shift 2
            ;;
        --check-csi)
            echo "Checking CSI components..." >&2
            echo "" >&2
            echo "CSI Driver DaemonSets in kube-system:" >&2
            kubectl get ds -n kube-system -o wide | grep -i csi >&2 || echo "  None found" >&2
            echo "" >&2
            echo "SPIRE CSI Provider in csi namespace:" >&2
            kubectl get ds -n csi -o wide 2>/dev/null >&2 || echo "  Namespace 'csi' not found" >&2
            echo "" >&2
            echo "CSI Driver pods in kube-system:" >&2
            kubectl get pods -n kube-system -o wide | grep -i csi >&2 || echo "  None found" >&2
            echo "" >&2
            echo "CSI Nodes:" >&2
            kubectl get csinodes >&2 || echo "  None found" >&2
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --sequential         Deploy pods one by one instead of all at once"
            echo "  --no-cleanup        Don't cleanup between different replica tests"
            echo "  --replicas N,N,N    Custom replica counts (default: 50,100,150,200)"
            echo "  --no-export         Don't export results to file"
            echo "  --no-svid-rotation  Skip SVID rotation verification"
            echo "  --svid-timeout N    SVID rotation timeout in seconds (default: 60)"
            echo "  --check-csi         Check CSI component status and exit"
            echo "  -h, --help          Show this help message"
            echo ""
            echo "Example:"
            echo "  $0                              # Run with defaults"
            echo "  $0 --replicas 10,20,30          # Test with custom replica counts"
            echo "  $0 --sequential --no-cleanup    # Sequential deployment, no cleanup"
            echo "  $0 --no-svid-rotation           # Skip SVID rotation checks"
            echo "  $0 --svid-timeout 120           # Wait up to 120s for SVID rotation"
            echo "  $0 --check-csi                  # Check CSI components status"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run '$0 --help' for usage information"
            exit 1
            ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
INTEGRATION_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$SCRIPT_DIR/perf-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$RESULTS_DIR/perf_test_${TIMESTAMP}.json"
SUMMARY_FILE="$RESULTS_DIR/perf_summary_${TIMESTAMP}.txt"
POD_TIMES_FILE="/tmp/pod_startup_times_${TIMESTAMP}.txt"
POD_TRACKING_FILE="/tmp/pod_tracking_${TIMESTAMP}.txt"
SVID_HASHES_FILE="/tmp/svid_hashes_${TIMESTAMP}.txt"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}SPIRE CSI Provider Performance Test${NC}"
echo -e "${CYAN}with SVID Rotation Verification${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Test Configuration:"
echo "  Replica counts: ${REPLICA_COUNTS[*]}"
echo "  Sequential mode: $SEQUENTIAL_MODE"
echo "  Cleanup between tests: $CLEANUP_BETWEEN_TESTS"
echo "  Export results: $EXPORT_RESULTS"
echo "  Check SVID rotation: $CHECK_SVID_ROTATION"
if [ "$CHECK_SVID_ROTATION" = true ]; then
    echo "  SVID rotation timeout: ${SVID_ROTATION_TIMEOUT}s"
fi
echo ""

if [ "$EXPORT_RESULTS" = true ]; then
    mkdir -p "$RESULTS_DIR"
fi

print_test() {
    echo -e "\n${BLUE}TEST: $1${NC}" >&2
    echo "=========================================" >&2
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1" >&2
}

print_failure() {
    echo -e "${RED}[FAIL]${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

print_info() {
    echo -e "${PURPLE}[INFO]${NC} $1" >&2
}

print_metric() {
    echo -e "  ${CYAN}$1:${NC} $2" >&2
}

get_svid_hash() {
    local pod_name="$1"

    if [[ -z "$pod_name" ]]; then
        echo "NOPOD"
        return 1
    fi

    local file_exists=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c test -- \
        sh -c "test -f $SVID_PATH && echo 'YES' || echo 'NO'" 2>/dev/null || echo "ERROR")

    if [[ "$file_exists" == "NO" ]]; then
        echo "NOFILE"
        return 1
    elif [[ "$file_exists" == "ERROR" ]]; then
        echo "ERROR"
        return 1
    fi

    local hash=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c test -- \
        sh -c "md5sum $SVID_PATH 2>/dev/null | cut -d' ' -f1" 2>/dev/null || echo "")

    if [[ -z "$hash" ]]; then
        hash=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c test -- \
            sh -c "sha256sum $SVID_PATH 2>/dev/null | cut -d' ' -f1 | head -c 16" 2>/dev/null || echo "")
    fi

    if [[ -z "$hash" ]]; then
        echo "EMPTY"
        return 1
    fi

    echo "$hash"
}

check_svid_provisioning() {
    local pod_name="$1"

    if [[ -z "$pod_name" ]]; then
        return 1
    fi

    local mount_exists=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c test -- \
        sh -c "test -d /run/spire && echo 'YES' || echo 'NO'" 2>/dev/null || echo "ERROR")

    if [[ "$mount_exists" != "YES" ]]; then
        return 1
    fi

    local x509_exists=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c test -- \
        sh -c "test -d /run/spire/x509 && echo 'YES' || echo 'NO'" 2>/dev/null || echo "ERROR")

    if [[ "$x509_exists" != "YES" ]]; then
        return 1
    fi

    local svid_exists=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c test -- \
        sh -c "test -f $SVID_PATH && echo 'YES' || echo 'NO'" 2>/dev/null || echo "ERROR")

    if [[ "$svid_exists" != "YES" ]]; then
        return 1
    fi

    return 0
}

wait_for_svid_rotation() {
    local pod_name="$1"
    local initial_hash="$2"
    local timeout="$3"
    local elapsed=0

    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] ||
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] ||
       [[ -z "$initial_hash" ]]; then
        return 1
    fi

    while [ $elapsed -lt $timeout ]; do
        sleep $ROTATION_CHECK_INTERVAL
        elapsed=$((elapsed + ROTATION_CHECK_INTERVAL))

        local current_hash=$(get_svid_hash "$pod_name")

        if [[ "$current_hash" == "NOPOD" ]] || [[ "$current_hash" == "NOFILE" ]] ||
           [[ "$current_hash" == "ERROR" ]] || [[ "$current_hash" == "EMPTY" ]] ||
           [[ -z "$current_hash" ]]; then
            continue
        fi

        if [[ "$current_hash" != "$initial_hash" ]]; then
            return 0  # Rotation successful
        fi
    done

    return 1  # Rotation failed/timed out
}

create_perf_deployment() {
    local replicas=$1

    cat <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $TEST_NAMESPACE
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-workload-sa
  namespace: $TEST_NAMESPACE
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: spire
  namespace: $TEST_NAMESPACE
spec:
  provider: spire
  parameters:
    useCase: "mesh"
    trustDomain: "example.org"
    objects: |
      - objectName: "x509"
        type: "x509-svid"
        filePermission: 0640
        paths:
          - "x509/cert.pem"
          - "x509/key.pem"
          - "x509/bundle.pem"
      - objectName: "app1-jwt"
        type: "jwt-svid"
        filePermission: 0640
        audience:
          - "app1"
        paths:
          - "jwt/app1.token"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $TEST_DEPLOYMENT
  namespace: $TEST_NAMESPACE
  labels:
    test: performance
spec:
  replicas: $replicas
  selector:
    matchLabels:
      app: $TEST_DEPLOYMENT
  template:
    metadata:
      labels:
        app: $TEST_DEPLOYMENT
        spiffe.io/spire-managed-identity: "true"
        test-replica-count: "$replicas"
    spec:
      serviceAccountName: test-workload-sa
      containers:
        - name: test
          image: alpine:3.19
          imagePullPolicy: Never
          command: ["sleep", "3600"]
          resources:
            requests:
              memory: "4Mi"
              cpu: "1m"
            limits:
              memory: "8Mi"
              cpu: "2m"
          volumeMounts:
            - name: spire-svids
              mountPath: "/run/spire"
              readOnly: true
      volumes:
        - name: spire-svids
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: "spire"
EOF
}

cleanup_test_namespace() {
    print_info "Cleaning up test namespace..."
    kubectl --context "$WORKLOAD_CONTEXT" delete namespace "$TEST_NAMESPACE" --ignore-not-found=true --wait=false

    local max_wait=60
    local elapsed=0
    while kubectl --context "$WORKLOAD_CONTEXT" get namespace "$TEST_NAMESPACE" &>/dev/null; do
        if [ $elapsed -ge $max_wait ]; then
            print_warning "Namespace deletion timed out after ${max_wait}s"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
}

get_pod_status_distribution() {
    kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
        -l app="$TEST_DEPLOYMENT" --no-headers 2>/dev/null | \
        awk '{print $3}' | sort | uniq -c | \
        awk '{printf "%d %s, ", $1, $2}' | sed 's/, $//'
}

calculate_percentile() {
    local percentile=$1
    local sorted_file=$2

    local count=$(wc -l < "$sorted_file" 2>/dev/null || echo "0")
    if [ "$count" = "0" ]; then
        echo "0"
        return
    fi

    local index=$(echo "($count * $percentile / 100) + 0.5" | bc 2>/dev/null || echo "1")
    index=${index%%.*}
    if [ "$index" -lt 1 ]; then
        index=1
    fi

    sed -n "${index}p" "$sorted_file" 2>/dev/null || echo "0"
}

measure_pod_times_with_status() {
    local replicas=$1
    local deployment_start=$(date +%s)

    print_info "Measuring pod creation and startup times for $replicas replicas..."

    > "$POD_TIMES_FILE"
    > "$POD_TRACKING_FILE"

    local running_count=0
    local max_wait=300
    local check_interval=1
    local elapsed=0
    local deployment_epoch=$deployment_start

    # Use associative arrays to track pods (if bash 4+, otherwise use files)
    declare -A pod_tracked 2>/dev/null || local use_files=true

    while true; do
        local status_dist=$(get_pod_status_distribution)

        while read -r line; do
            [[ -z "$line" ]] && continue

            local pod_name=$(echo "$line" | awk '{print $1}')
            local ready=$(echo "$line" | awk '{print $2}')
            local pod_status=$(echo "$line" | awk '{print $3}')

            if [[ -n "$use_files" ]]; then
                if ! grep -q "^${pod_name}|" "$POD_TRACKING_FILE" 2>/dev/null; then
                    echo "${pod_name}|pending|${deployment_epoch}" >> "$POD_TRACKING_FILE"
                fi
            else
                if [[ -z "${pod_tracked[$pod_name]:-}" ]]; then
                    pod_tracked[$pod_name]="pending"
                    echo "${pod_name}|pending|${deployment_epoch}" >> "$POD_TRACKING_FILE"
                fi
            fi

            if [ "$pod_status" = "Running" ] && [ "$ready" = "1/1" ]; then
                local already_timed=false

                if [[ -n "$use_files" ]]; then
                    if grep -q "^${pod_name}|running|" "$POD_TRACKING_FILE" 2>/dev/null; then
                        already_timed=true
                    fi
                else
                    if [[ "${pod_tracked[$pod_name]:-}" == "running" ]]; then
                        already_timed=true
                    fi
                fi

                if [[ "$already_timed" == "false" ]]; then
                    local current_time=$(date +%s)
                    local startup_time=$((current_time - deployment_epoch))

                    if [[ -n "$use_files" ]]; then
                        grep -v "^${pod_name}|" "$POD_TRACKING_FILE" 2>/dev/null > "${POD_TRACKING_FILE}.tmp" || true
                        echo "${pod_name}|running|${startup_time}" >> "${POD_TRACKING_FILE}.tmp"
                        mv "${POD_TRACKING_FILE}.tmp" "$POD_TRACKING_FILE"
                    else
                        pod_tracked[$pod_name]="running"
                        sed -i.bak "/^${pod_name}|/d" "$POD_TRACKING_FILE" 2>/dev/null || true
                        echo "${pod_name}|running|${startup_time}" >> "$POD_TRACKING_FILE"
                    fi

                    echo "$startup_time" >> "$POD_TIMES_FILE"
                fi
            fi
        done < <(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
            -l app="$TEST_DEPLOYMENT" --no-headers 2>/dev/null)

        running_count=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
            -l app="$TEST_DEPLOYMENT" --no-headers 2>/dev/null | \
            awk '$3=="Running" && $2=="1/1" {count++} END {print count+0}')

        running_count=${running_count:-0}

        local pods_with_times=$(wc -l < "$POD_TIMES_FILE" 2>/dev/null | tr -d ' ')
        pods_with_times=${pods_with_times:-0}
        echo -ne "\r  [${elapsed}s] Running: $running_count/$replicas | Timed: $pods_with_times | Status: $status_dist    " >&2

        if [ "$running_count" -ge "$replicas" ]; then
            if [ "$pods_with_times" -ge "$running_count" ] || [ "$elapsed" -ge "$((max_wait))" ]; then
                break
            fi
        elif [ "$elapsed" -ge "$max_wait" ]; then
            break
        fi

        sleep $check_interval
        elapsed=$((elapsed + check_interval))
    done

    echo "" >&2

    local final_timed_count=$(wc -l < "$POD_TIMES_FILE" 2>/dev/null | tr -d ' ')
    if [ "$running_count" -gt "$final_timed_count" ] && [ "$elapsed" -lt "$max_wait" ]; then
        print_info "Final verification pass to capture remaining pod timings..."
        sleep 2

        while read -r line; do
            [[ -z "$line" ]] && continue

            local pod_name=$(echo "$line" | awk '{print $1}')
            local ready=$(echo "$line" | awk '{print $2}')
            local pod_status=$(echo "$line" | awk '{print $3}')

            if [ "$pod_status" = "Running" ] && [ "$ready" = "1/1" ]; then
                if ! grep -q "^${pod_name}|running|" "$POD_TRACKING_FILE" 2>/dev/null; then
                    local current_time=$(date +%s)
                    local startup_time=$((current_time - deployment_epoch))
                    echo "${pod_name}|running|${startup_time}" >> "$POD_TRACKING_FILE"
                    echo "$startup_time" >> "$POD_TIMES_FILE"
                fi
            fi
        done < <(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
            -l app="$TEST_DEPLOYMENT" --no-headers 2>/dev/null)
    fi

    if [ "$running_count" -ge "$replicas" ]; then
        print_success "All $replicas pods are running in ${elapsed}s"
    else
        print_failure "Only $running_count/$replicas pods became running in ${max_wait}s"
    fi

    local avg_time="0"
    local min_time="0"
    local max_time="0"
    local p50="0"
    local p90="0"
    local p99="0"
    local pod_count=0

    if [ -s "$POD_TIMES_FILE" ]; then
        sort -n "$POD_TIMES_FILE" > "${POD_TIMES_FILE}.sorted"

        pod_count=$(wc -l < "$POD_TIMES_FILE" | tr -d ' ')
        min_time=$(head -1 "${POD_TIMES_FILE}.sorted" 2>/dev/null || echo "0")
        max_time=$(tail -1 "${POD_TIMES_FILE}.sorted" 2>/dev/null || echo "0")
        avg_time=$(awk '{sum+=$1} END {if(NR>0) printf "%.2f", sum/NR; else print "0"}' "$POD_TIMES_FILE" 2>/dev/null || echo "0")
        p50=$(calculate_percentile 50 "${POD_TIMES_FILE}.sorted")
        p90=$(calculate_percentile 90 "${POD_TIMES_FILE}.sorted")
        p99=$(calculate_percentile 99 "${POD_TIMES_FILE}.sorted")

        print_info "Collected timing data for $pod_count/$replicas pods"
        if [ "$pod_count" -lt "$running_count" ]; then
            print_warning "Missing timing data for $((running_count - pod_count)) pods (may have started before measurement began)"
        fi

        if [ "$pod_count" -gt 0 ]; then
            print_info "Startup time distribution: Min=${min_time}s, P50=${p50}s, P90=${p90}s, Max=${max_time}s"

            if [ "$pod_count" -gt 5 ]; then
                print_info "Time distribution (5-second buckets):"
                awk '{
                    bucket = int($1/5)*5
                    buckets[bucket]++
                }
                END {
                    for (b in buckets) {
                        printf "    %3d-%3ds: %d pods\n", b, b+4, buckets[b]
                    }
                }' "$POD_TIMES_FILE" | sort -n >&2
            fi
        fi
    else
        print_warning "No pod timing data collected!"
    fi

    echo "${elapsed}|${avg_time}|${min_time}|${max_time}|${p50}|${p90}|${p99}"
}

measure_csi_mounts() {
    local replicas=$1

    print_info "Checking CSI volume mount status for $replicas replicas..."

    local mounted_count=0
    local failed_mounts=0
    local pending_mounts=0

    local running_pods=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
        -l app="$TEST_DEPLOYMENT" --no-headers 2>/dev/null | \
        awk '$3=="Running" && $2=="1/1" {count++} END {print count+0}')

    local container_creating=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
        -l app="$TEST_DEPLOYMENT" --no-headers 2>/dev/null | \
        awk '$3=="ContainerCreating" {count++} END {print count+0}')

    local volume_errors=$(kubectl --context "$WORKLOAD_CONTEXT" get events \
        -n "$TEST_NAMESPACE" --no-headers 2>/dev/null | \
        grep -i "volume\|mount\|csi\|secret" | \
        grep -i "failed\|error\|timeout" | wc -l || echo "0")

    if [ "$volume_errors" -gt 0 ]; then
        print_warning "Found $volume_errors volume-related error events. Sample:"
        kubectl --context "$WORKLOAD_CONTEXT" get events \
            -n "$TEST_NAMESPACE" --no-headers 2>/dev/null | \
            grep -i "volume\|mount\|csi\|secret" | \
            grep -i "failed\|error\|timeout" | \
            head -3 | while read line; do
                echo "    $line" >&2
            done
    fi

    mounted_count=${running_pods:-0}
    failed_mounts=${volume_errors:-0}
    pending_mounts=${container_creating:-0}

    print_metric "Successful CSI mounts" "$mounted_count"
    print_metric "Pending CSI mounts" "$pending_mounts"
    print_metric "Failed mount events" "$failed_mounts"

    echo "${mounted_count},${failed_mounts}"
}

measure_svid_rotation() {
    local replicas=$1

    if [ "$CHECK_SVID_ROTATION" = false ]; then
        echo "0,0,0"  # rotated_count, failed_rotations, skipped_count
        return 0
    fi

    print_info "Testing SVID rotation for ALL $replicas replicas (timeout: ${SVID_ROTATION_TIMEOUT}s)..."

    > "$SVID_HASHES_FILE"
    local rotated_count=0
    local failed_rotations=0
    local skipped_count=0

    local pod_names=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
        -l app="$TEST_DEPLOYMENT" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

    if [[ -z "$pod_names" ]]; then
        print_warning "No pods found for SVID rotation testing"
        echo "0,${replicas},0"
        return 1
    fi

    local pod_array=($pod_names)
    local total_pods=${#pod_array[@]}

    print_info "Collecting initial SVID hashes from ALL $total_pods pods..."

    # Step 1: Get initial hashes from all pods (using temp file for bash 3.x compatibility)
    local initial_hashes_file="/tmp/initial_hashes_${TIMESTAMP}.txt"
    > "$initial_hashes_file"

    local pod_index=0
    for pod_name in "${pod_array[@]}"; do
        pod_index=$((pod_index + 1))
        echo -ne "\r  Collecting initial SVID hashes: $pod_index/$total_pods pods..." >&2

        if check_svid_provisioning "$pod_name"; then
            local initial_hash=$(get_svid_hash "$pod_name")

            if [[ "$initial_hash" != "NOFILE" ]] && [[ "$initial_hash" != "ERROR" ]] &&
               [[ "$initial_hash" != "NOPOD" ]] && [[ "$initial_hash" != "EMPTY" ]] &&
               [[ -n "$initial_hash" ]]; then
                echo "${pod_name}|${initial_hash}" >> "$initial_hashes_file"
                echo "${pod_name}:${initial_hash}:initial" >> "$SVID_HASHES_FILE"
            else
                skipped_count=$((skipped_count + 1))
                if [ "$pod_index" -le 5 ]; then
                    print_warning "Skipping pod $pod_name - SVID not accessible (status: $initial_hash)"
                fi
            fi
        else
            skipped_count=$((skipped_count + 1))
            if [ "$pod_index" -le 5 ]; then
                print_warning "Skipping pod $pod_name - SVID not provisioned"
            fi
        fi
    done

    echo "" >&2

    local tested_pods=$(wc -l < "$initial_hashes_file" 2>/dev/null | tr -d ' ')
    tested_pods=${tested_pods:-0}

    if [ $tested_pods -eq 0 ]; then
        print_warning "No pods with valid SVIDs found for rotation testing"
        rm -f "$initial_hashes_file"
        echo "0,${total_pods},0"
        return 1
    fi

    print_info "Collected initial hashes from $tested_pods pods"

    # Step 2: Wait for rotation period
    print_info "Waiting ${SVID_ROTATION_TIMEOUT}s for SVID rotation to occur..."
    local wait_interval=10
    local elapsed=0
    while [ $elapsed -lt $SVID_ROTATION_TIMEOUT ]; do
        sleep $wait_interval
        elapsed=$((elapsed + wait_interval))
        echo -ne "\r  Waiting for rotation: ${elapsed}/${SVID_ROTATION_TIMEOUT}s..." >&2
    done
    echo "" >&2

    # Step 3: Check all pods for rotation
    print_info "Checking all pods for SVID rotation..."
    local check_index=0
    while IFS='|' read -r pod_name initial_hash; do
        [[ -z "$pod_name" ]] && continue
        check_index=$((check_index + 1))
        echo -ne "\r  Checking rotation: $check_index/$tested_pods pods..." >&2

        local current_hash=$(get_svid_hash "$pod_name")

        if [[ "$current_hash" != "NOFILE" ]] && [[ "$current_hash" != "ERROR" ]] &&
           [[ "$current_hash" != "NOPOD" ]] && [[ "$current_hash" != "EMPTY" ]] &&
           [[ -n "$current_hash" ]]; then

            if [[ "$current_hash" != "$initial_hash" ]]; then
                rotated_count=$((rotated_count + 1))
                echo "${pod_name}:${initial_hash}:${current_hash}:rotated" >> "$SVID_HASHES_FILE"
            else
                failed_rotations=$((failed_rotations + 1))
                echo "${pod_name}:${initial_hash}:${current_hash}:no_rotation" >> "$SVID_HASHES_FILE"
            fi
        else
            failed_rotations=$((failed_rotations + 1))
            echo "${pod_name}:${initial_hash}:${current_hash}:read_error" >> "$SVID_HASHES_FILE"
        fi
    done < "$initial_hashes_file"

    rm -f "$initial_hashes_file"

    echo "" >&2

    local rotation_rate=0
    if [ $tested_pods -gt 0 ]; then
        rotation_rate=$(echo "scale=1; $rotated_count * 100 / $tested_pods" | bc 2>/dev/null || echo "0")
    fi

    print_metric "Total pods found" "$total_pods"
    print_metric "Pods tested for rotation" "$tested_pods"
    print_metric "SVIDs rotated successfully" "$rotated_count"
    print_metric "SVID rotation failures" "$failed_rotations"
    print_metric "Pods skipped (no SVID)" "$skipped_count"
    print_metric "SVID rotation success rate" "${rotation_rate}%"

    if [ $rotated_count -gt 0 ]; then
        print_success "SVID rotation is working (${rotated_count}/${tested_pods} pods)"
    elif [ $failed_rotations -gt 0 ]; then
        print_failure "SVID rotation failed for all tested pods"
    else
        print_warning "No pods available for SVID rotation testing"
    fi

    if [ $skipped_count -gt 5 ]; then
        print_info "Note: $skipped_count pods were skipped (first 5 warnings shown to avoid spam)"
    fi

    echo "${rotated_count},${failed_rotations},${skipped_count}"
}

get_csi_metrics() {
    print_info "Collecting CSI driver metrics..."

    local csi_pods=0

    for ds_name in "csi-secrets-store" "secrets-store-csi-driver"; do
        local count=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n kube-system \
            -o wide --no-headers 2>/dev/null | \
            grep "$ds_name" | wc -l)
        if [ "$count" -gt 0 ]; then
            csi_pods=$count
            break
        fi
    done

    local provider_pods=0
    for ns in csi spire-system spire; do
        for label in "app=spire-csi-provider" "app=spire-csi-driver"; do
            local count=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$ns" \
                -l "$label" --no-headers 2>/dev/null | wc -l)
            if [ "$count" -gt 0 ]; then
                provider_pods=$count
                break 2
            fi
        done
    done

    local csi_errors=0
    local provider_errors=0

    if [ "$csi_pods" -gt 0 ]; then
        csi_errors=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n kube-system \
            -o name 2>/dev/null | \
            grep -E "(csi-secrets-store|secrets-store)" | \
            xargs -I {} kubectl --context "$WORKLOAD_CONTEXT" logs {} -n kube-system \
            --tail=100 --since=5m 2>/dev/null | \
            grep -c "ERROR\|error\|Error" || echo "0")
    fi

    if [ "$provider_pods" -gt 0 ]; then
        provider_errors=$(kubectl --context "$WORKLOAD_CONTEXT" logs -n csi \
            -l app=spire-csi-provider --tail=100 --since=5m 2>/dev/null | \
            grep -c "ERROR\|error\|Error" || echo "0")
    fi

    print_metric "CSI driver pods" "$csi_pods"
    print_metric "SPIRE CSI provider pods" "$provider_pods"
    print_metric "CSI driver errors (last 5m)" "$csi_errors"
    print_metric "SPIRE provider errors (last 5m)" "$provider_errors"

    echo "${csi_pods},${provider_pods},${csi_errors},${provider_errors}"
}

safe_divide() {
    local numerator="${1:-0}"
    local denominator="${2:-1}"
    local scale="${3:-2}"

    numerator=$(echo "$numerator" | grep -o '[0-9.]*' | head -1)
    denominator=$(echo "$denominator" | grep -o '[0-9.]*' | head -1)

    numerator=${numerator:-0}
    denominator=${denominator:-1}

    if [ "$denominator" = "0" ]; then
        echo "0"
        return
    fi

    echo "scale=$scale; $numerator / $denominator" | bc 2>/dev/null || echo "0"
}

run_perf_test() {
    local replicas=$1
    local test_num=$2

    print_test "Performance Test #$test_num: $replicas Replicas with SVID Rotation"

    local start_time=$(date +%s)

    print_info "Deploying workload with $replicas replicas..."
    create_perf_deployment "$replicas" | kubectl --context "$WORKLOAD_CONTEXT" apply -f -

    sleep 2

    local pod_metrics=$(measure_pod_times_with_status "$replicas")

    local total_time=$(echo "$pod_metrics" | cut -d'|' -f1)
    local avg_time=$(echo "$pod_metrics" | cut -d'|' -f2)
    local min_time=$(echo "$pod_metrics" | cut -d'|' -f3)
    local max_time=$(echo "$pod_metrics" | cut -d'|' -f4)
    local p50_time=$(echo "$pod_metrics" | cut -d'|' -f5)
    local p90_time=$(echo "$pod_metrics" | cut -d'|' -f6)
    local p99_time=$(echo "$pod_metrics" | cut -d'|' -f7)

    mount_metrics=$(measure_csi_mounts "$replicas" | tail -1)
    successful_mounts=$(echo "$mount_metrics" | cut -d',' -f1)
    failed_mounts=$(echo "$mount_metrics" | cut -d',' -f2)
    successful_mounts=${successful_mounts:-0}
    failed_mounts=${failed_mounts:-0}

    svid_metrics=$(measure_svid_rotation "$replicas" | tail -1)
    svid_rotated=$(echo "$svid_metrics" | cut -d',' -f1)
    svid_failed=$(echo "$svid_metrics" | cut -d',' -f2)
    svid_skipped=$(echo "$svid_metrics" | cut -d',' -f3)
    svid_rotated=${svid_rotated:-0}
    svid_failed=${svid_failed:-0}
    svid_skipped=${svid_skipped:-0}

    csi_metrics=$(get_csi_metrics | tail -1)
    csi_pods=$(echo "$csi_metrics" | cut -d',' -f1)
    provider_pods=$(echo "$csi_metrics" | cut -d',' -f2)
    csi_errors=$(echo "$csi_metrics" | cut -d',' -f3)
    provider_errors=$(echo "$csi_metrics" | cut -d',' -f4)

    csi_pods=${csi_pods:-0}
    provider_pods=${provider_pods:-0}
    csi_errors=${csi_errors:-0}
    provider_errors=${provider_errors:-0}

    local end_time=$(date +%s)
    local test_total_time=$((end_time - start_time))

    mount_rate=$(safe_divide "$successful_mounts" "$replicas" 1)
    mount_rate=$(echo "$mount_rate * 100" | bc 2>/dev/null || echo "0")

    local svid_rotation_rate=0
    local svid_tested=$((svid_rotated + svid_failed))
    if [ $svid_tested -gt 0 ]; then
        svid_rotation_rate=$(safe_divide "$svid_rotated" "$svid_tested" 1)
        svid_rotation_rate=$(echo "$svid_rotation_rate * 100" | bc 2>/dev/null || echo "0")
    fi

    echo "" >&2
    echo "Performance Results for $replicas Replicas:" >&2
    echo "===========================================" >&2
    print_metric "Total test time" "${test_total_time}s"
    print_metric "Time to all pods running" "${total_time}s"
    echo "" >&2
    echo "  Pod Startup Time Statistics:" >&2
    print_metric "  Average" "${avg_time}s"
    print_metric "  Minimum" "${min_time}s"
    print_metric "  P50 (Median)" "${p50_time}s"
    print_metric "  P90" "${p90_time}s"
    print_metric "  P99" "${p99_time}s"
    print_metric "  Maximum" "${max_time}s"
    echo "" >&2
    echo "  CSI Mount Statistics:" >&2
    print_metric "  Successful CSI mounts" "$successful_mounts"
    print_metric "  Failed CSI mounts" "$failed_mounts"
    print_metric "  Mount success rate" "${mount_rate}%"
    echo "" >&2
    echo "  SVID Rotation Statistics:" >&2
    if [ "$CHECK_SVID_ROTATION" = true ]; then
        print_metric "  SVID rotations successful" "$svid_rotated"
        print_metric "  SVID rotation failures" "$svid_failed"
        print_metric "  SVID rotation success rate" "${svid_rotation_rate}%"
    else
        print_metric "  SVID rotation testing" "DISABLED"
    fi
    echo "" >&2
    print_metric "CSI/Provider errors" "${csi_errors}/${provider_errors}"

    if [ "$EXPORT_RESULTS" = true ]; then
        cat >> "$RESULTS_FILE" <<EOF
{
  "test_number": $test_num,
  "replicas": $replicas,
  "timestamp": "$(date -Iseconds)",
  "total_test_time_seconds": $test_total_time,
  "all_pods_running_time_seconds": ${total_time:-0},
  "avg_startup_time": ${avg_time:-0},
  "min_startup_time": ${min_time:-0},
  "max_startup_time": ${max_time:-0},
  "p50_startup_time": ${p50_time:-0},
  "p90_startup_time": ${p90_time:-0},
  "p99_startup_time": ${p99_time:-0},
  "successful_mounts": $successful_mounts,
  "failed_mounts": $failed_mounts,
  "mount_success_rate": ${mount_rate:-0},
  "svid_rotated": $svid_rotated,
  "svid_rotation_failures": $svid_failed,
  "svid_rotation_success_rate": ${svid_rotation_rate:-0},
  "svid_rotation_enabled": $([ "$CHECK_SVID_ROTATION" = true ] && echo "true" || echo "false"),
  "csi_driver_pods": ${csi_pods:-0},
  "provider_pods": ${provider_pods:-0},
  "csi_errors": ${csi_errors:-0},
  "provider_errors": ${provider_errors:-0}
},
EOF
    fi

    rm -f "$POD_TIMES_FILE" "${POD_TIMES_FILE}.sorted" "${POD_TIMES_FILE}.tracked" "$POD_TRACKING_FILE" "${POD_TRACKING_FILE}.bak" "$SVID_HASHES_FILE"

    if [ "$CLEANUP_BETWEEN_TESTS" = true ]; then
        cleanup_test_namespace
    fi
}

pre_test_validation() {
    print_test "Pre-Test Validation"

    if ! kubectl --context "$WORKLOAD_CONTEXT" cluster-info &>/dev/null; then
        print_failure "Cannot access workload cluster"
        exit 1
    fi
    print_success "Workload cluster accessible"

    local csi_driver_exists=0
    local csi_driver_name=""

    for ds_name in "csi-secrets-store" "secrets-store-csi-driver"; do
        if kubectl --context "$WORKLOAD_CONTEXT" get daemonset "$ds_name" -n kube-system &>/dev/null; then
            csi_driver_exists=1
            csi_driver_name="$ds_name"
            break
        fi
    done

    if [ "$csi_driver_exists" -eq 0 ]; then
        print_failure "CSI driver DaemonSet not found in kube-system"
        exit 1
    else
        print_success "Found CSI driver DaemonSet: $csi_driver_name"

        local node_count=$(kubectl --context "$WORKLOAD_CONTEXT" get nodes --no-headers 2>/dev/null | wc -l)
        local csi_running=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n kube-system \
            -o wide --no-headers 2>/dev/null | \
            grep "$csi_driver_name" | \
            awk '$3=="Running" {count++} END {print count+0}')

        if [ "$csi_running" -lt "$node_count" ]; then
            print_warning "CSI driver not running on all nodes ($csi_running/$node_count)"
        else
            print_success "CSI driver running on all nodes ($csi_running/$node_count)"
        fi
    fi

    local provider_running=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n csi \
        --no-headers 2>/dev/null | \
        grep -E "(spire-csi-provider|spire-csi-driver)" | \
        awk '$3=="Running" {count++} END {print count+0}')

    if [ "$provider_running" -gt 0 ]; then
        print_success "SPIRE CSI provider is running ($provider_running pods)"
    else
        print_warning "SPIRE CSI provider may not be running"
    fi

    print_info "Checking CSI driver registration..."
    local csi_nodes=$(kubectl --context "$WORKLOAD_CONTEXT" get csinodes --no-headers 2>/dev/null | wc -l)
    if [ "$csi_nodes" -gt 0 ]; then
        print_success "CSI nodes registered: $csi_nodes"
    fi

    if [ "$CHECK_SVID_ROTATION" = true ]; then
        print_info "Validating SPIRE agents for SVID rotation testing..."

        local agent_01_running=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n spire \
            -l app=spire-agent-child-01 --no-headers 2>/dev/null | \
            awk '$3=="Running" {count++} END {print count+0}')

        local agent_02_running=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n spire \
            -l app=spire-agent-child-02 --no-headers 2>/dev/null | \
            awk '$3=="Running" {count++} END {print count+0}')

        if [ "$agent_01_running" -gt 0 ] || [ "$agent_02_running" -gt 0 ]; then
            print_success "SPIRE agents are running (agent-01: $agent_01_running, agent-02: $agent_02_running)"
        else
            print_warning "No SPIRE agents found - SVID rotation may not work"
        fi
    fi

    cleanup_test_namespace
}

generate_summary() {
    if [ "$EXPORT_RESULTS" != true ]; then
        return
    fi

    print_test "Generating Summary Report"

    cat > "$SUMMARY_FILE" <<EOF
SPIRE CSI Provider Performance Test Summary
==========================================
Test Date: $(date)
Test Configuration:
  - Replica counts tested: ${REPLICA_COUNTS[*]}
  - Sequential mode: $SEQUENTIAL_MODE
  - Pod resources: 1m CPU, 4Mi memory (minimal)
  - SVID rotation testing: $CHECK_SVID_ROTATION
$([ "$CHECK_SVID_ROTATION" = true ] && echo "  - SVID rotation timeout: ${SVID_ROTATION_TIMEOUT}s" || echo "")

Performance Results:
EOF

    if [ -f "$RESULTS_FILE" ]; then
        # Fix for macOS sed - use portable approach
        # Remove trailing comma
        if [ "$(tail -c 2 "$RESULTS_FILE")" = "," ]; then
            truncate -s -2 "$RESULTS_FILE" 2>/dev/null || \
            head -c -2 "$RESULTS_FILE" > "${RESULTS_FILE}.tmp" && mv "${RESULTS_FILE}.tmp" "$RESULTS_FILE"
        fi

        # Add closing bracket
        echo "]" >> "$RESULTS_FILE"

        # Add opening bracket at beginning
        echo "[" > "${RESULTS_FILE}.tmp"
        cat "$RESULTS_FILE" >> "${RESULTS_FILE}.tmp"
        mv "${RESULTS_FILE}.tmp" "$RESULTS_FILE"

        if command -v jq &>/dev/null; then
            if [ "$CHECK_SVID_ROTATION" = true ]; then
                jq -r '.[] | "Replicas: \(.replicas) - Startup: Avg=\(.avg_startup_time)s, P90=\(.p90_startup_time)s - Mount Success: \(.mount_success_rate)% - SVID Rotation: \(.svid_rotation_success_rate)%"' \
                    "$RESULTS_FILE" >> "$SUMMARY_FILE"
            else
                jq -r '.[] | "Replicas: \(.replicas) - Startup: Avg=\(.avg_startup_time)s, P90=\(.p90_startup_time)s - Mount Success: \(.mount_success_rate)%"' \
                    "$RESULTS_FILE" >> "$SUMMARY_FILE"
            fi
        fi
    fi

    echo "" >> "$SUMMARY_FILE"

    print_success "Results exported to $RESULTS_DIR/"
}

main() {
    echo "Starting performance tests with SVID rotation verification..." >&2
    echo "" >&2

    pre_test_validation

    if [ "$EXPORT_RESULTS" = true ]; then
        echo "" > "$RESULTS_FILE"
    fi

    local test_num=1
    for replicas in "${REPLICA_COUNTS[@]}"; do
        run_perf_test "$replicas" "$test_num"
        test_num=$((test_num + 1))

        if [ $test_num -le ${#REPLICA_COUNTS[@]} ] && [ "$CLEANUP_BETWEEN_TESTS" = true ]; then
            print_info "Waiting 10s before next test..."
            sleep 10
        fi
    done

    generate_summary

    if [ "$CLEANUP_BETWEEN_TESTS" = false ]; then
        print_info "Cleaning up test resources..."
        cleanup_test_namespace
    fi

    echo "" >&2
    echo -e "${CYAN}========================================${NC}" >&2
    echo -e "${CYAN}Performance Testing Complete${NC}" >&2
    echo -e "${CYAN}========================================${NC}" >&2

    if [ "$EXPORT_RESULTS" = true ]; then
        echo "" >&2
        echo "Results saved to:" >&2
        echo "  JSON: $RESULTS_FILE" >&2
        echo "  Summary: $SUMMARY_FILE" >&2
    fi
}

cleanup_on_exit() {
    print_warning "Test interrupted, cleaning up..."
    cleanup_test_namespace
    rm -f "$POD_TIMES_FILE" "${POD_TIMES_FILE}.sorted" "${POD_TIMES_FILE}.tracked" "$POD_TRACKING_FILE" "${POD_TRACKING_FILE}.bak" "$SVID_HASHES_FILE"
}

trap cleanup_on_exit EXIT INT TERM

main "$@"