#!/bin/bash

# SPIRE CSI Provider HA/Failover Integration Test
# Using certificate hash for tracking SVID rotation

set -e

INTERACTIVE_MODE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interactive)
            INTERACTIVE_MODE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -i, --interactive    Pause between each test for user confirmation"
            echo "  -h, --help          Show this help message"
            echo ""
            echo "Example:"
            echo "  $0                  # Run all tests automatically"
            echo "  $0 --interactive    # Pause between each test"
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

readonly TEST_NAMESPACE="app-a"
readonly TEST_WORKLOAD="test-workload-a"
readonly SUB01_CONTEXT="kind-spire-subordinate-01"
readonly SUB02_CONTEXT="kind-spire-subordinate-02"
readonly WORKLOAD_CONTEXT="kind-workload"
readonly SVID_PATH="/run/spire/x509/cert.pem"
readonly ROTATION_CHECK_INTERVAL=10
readonly MAX_WAIT_TIME=120

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}SPIRE CSI Provider HA/Failover Test v3${NC}"
echo -e "${CYAN}========================================${NC}"
if [ "$INTERACTIVE_MODE" = true ]; then
    echo -e "${YELLOW}Running in INTERACTIVE mode${NC}"
else
    echo "Running in automatic mode"
fi
echo ""

wait_for_user() {
    if [ "$INTERACTIVE_MODE" = true ]; then
        echo ""
        echo -e "${YELLOW}Press ENTER to continue to the next test...${NC}"
        read -r
    fi
}

print_test() {
    echo -e "\n${BLUE}TEST $1: $2${NC}"
    echo "----------------------------------------"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_info() {
    echo -e "${PURPLE}[INFO]${NC} $1"
}

get_svid_hash() {
    local pod_name=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
        -l app="$TEST_WORKLOAD" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [[ -z "$pod_name" ]]; then
        echo "NOPOD"
        return 1
    fi
    
    # First check if the file exists
    local file_exists=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
        sh -c "test -f $SVID_PATH && echo 'YES' || echo 'NO'" 2>/dev/null || echo "ERROR")
    
    if [[ "$file_exists" == "NO" ]]; then
        echo "NOFILE"
        return 1
    elif [[ "$file_exists" == "ERROR" ]]; then
        echo "ERROR"
        return 1
    fi
    
    local hash=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
        sh -c "md5sum $SVID_PATH 2>/dev/null | cut -d' ' -f1" 2>/dev/null || echo "")
    
    if [[ -z "$hash" ]]; then
        hash=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
            sh -c "sha256sum $SVID_PATH 2>/dev/null | cut -d' ' -f1 | head -c 16" 2>/dev/null || echo "")
    fi
    
    if [[ -z "$hash" ]]; then
        echo "EMPTY"
        return 1
    fi
    
    echo "$hash"
}

get_svid_info() {
    local pod_name=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
        -l app="$TEST_WORKLOAD" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [[ -z "$pod_name" ]]; then
        return 1
    fi
    
    echo ""
    echo "SVID Certificate Details:"
    echo "-------------------------"
    
    echo "Command: ls -la $SVID_PATH"
    kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
        ls -la "$SVID_PATH" 2>/dev/null || echo "  Cannot stat file"
    
    echo ""
    echo "Command: head -3 $SVID_PATH"
    kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
        head -3 "$SVID_PATH" 2>/dev/null || echo "  Cannot read certificate"
    
    echo ""
    echo "Command: stat -c '%y' $SVID_PATH"
    kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
        stat -c '%y' "$SVID_PATH" 2>/dev/null || echo "  Cannot get modification time"
    
    echo ""
}

check_svid_provisioning() {
    local pod_name=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
        -l app="$TEST_WORKLOAD" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [[ -z "$pod_name" ]]; then
        print_failure "No test workload pod found"
        return 1
    fi
    
    echo ""
    echo "Checking SVID provisioning status..."
    echo "===================================="
    
    echo ""
    echo "Command: test -d /run/spire && echo 'YES' || echo 'NO'"
    local mount_exists=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
        sh -c "test -d /run/spire && echo 'YES' || echo 'NO'" 2>/dev/null)
    echo "Result: $mount_exists"
    
    if [[ "$mount_exists" == "NO" ]]; then
        print_failure "CSI mount point /run/spire does not exist"
        return 1
    fi
    
    echo ""
    echo "Command: ls -la /run/spire/"
    echo "Contents of /run/spire:"
    kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
        ls -la /run/spire/ 2>/dev/null || print_warning "Cannot list /run/spire"
    
    echo ""
    echo "Command: test -d /run/spire/x509 && echo 'YES' || echo 'NO'"
    local x509_exists=$(kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
        sh -c "test -d /run/spire/x509 && echo 'YES' || echo 'NO'" 2>/dev/null)
    echo "Result: $x509_exists"
    
    if [[ "$x509_exists" == "YES" ]]; then
        echo ""
        echo "Command: ls -la /run/spire/x509/"
        echo "Contents of /run/spire/x509:"
        kubectl --context "$WORKLOAD_CONTEXT" exec -n "$TEST_NAMESPACE" "$pod_name" -c alpine -- \
            ls -la /run/spire/x509/ 2>/dev/null || print_warning "Cannot list x509 directory"
        
        get_svid_info
        
        return 0
    else
        print_warning "No x509 directory found - SVIDs may not be provisioned"
        return 1
    fi
}

wait_for_svid_rotation() {
    local initial_hash=$1
    local timeout=$2
    local should_rotate=$3
    local elapsed=0
    
    echo ""
    echo "Monitoring SVID rotation..."
    echo "==========================="
    
    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] ||
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] || 
       [[ -z "$initial_hash" ]]; then
        print_failure "Invalid initial SVID hash: '$initial_hash'"
        print_info "SVIDs may not be provisioned correctly"
        check_svid_provisioning
        return 1
    fi
    
    echo ""
    echo "Initial SVID hash: ${initial_hash:0:16}..."
    echo "Expected behavior: $(if [ "$should_rotate" = true ]; then echo "Should rotate"; else echo "Should NOT rotate"; fi)"
    echo "Timeout: $timeout seconds"
    echo "Check interval: $ROTATION_CHECK_INTERVAL seconds"
    echo ""
    echo "Starting rotation check..."
    echo "---------------------------"
    
    while [ $elapsed -lt $timeout ]; do
        sleep $ROTATION_CHECK_INTERVAL
        elapsed=$((elapsed + ROTATION_CHECK_INTERVAL))
        
        echo ""
        echo "[$elapsed s] Checking SVID hash..."
        echo "Command: md5sum /run/spire/x509/cert.pem | cut -d' ' -f1"
        local current_hash=$(get_svid_hash)
        
        if [[ "$current_hash" == "NOPOD" ]]; then
            print_failure "Pod not found"
            return 1
        elif [[ "$current_hash" == "NOFILE" ]]; then
            print_warning "[$elapsed s] SVID file does not exist"
            continue
        elif [[ "$current_hash" == "ERROR" ]]; then
            print_warning "[$elapsed s] Error reading SVID"
            continue
        elif [[ "$current_hash" == "EMPTY" ]] || [[ -z "$current_hash" ]]; then
            print_warning "[$elapsed s] SVID hash is empty"
            continue
        fi
        
        echo "[$elapsed s] Current SVID hash: ${current_hash:0:16}..."
        
        if [ "$should_rotate" = true ]; then
            if [[ "$current_hash" != "$initial_hash" ]]; then
                echo ""
                print_success "SVID rotated successfully!"
                echo "  Old hash: ${initial_hash:0:16}..."
                echo "  New hash: ${current_hash:0:16}..."
                get_svid_info
                return 0
            else
                echo "[$elapsed s] Hash unchanged, waiting for rotation..."
            fi
        else
            if [[ "$current_hash" != "$initial_hash" ]]; then
                echo ""
                print_failure "SVID rotated when it shouldn't have"
                echo "  Old hash: ${initial_hash:0:16}..."
                echo "  New hash: ${current_hash:0:16}..."
                return 1
            else
                echo "[$elapsed s] Hash unchanged (expected behavior)"
            fi
        fi
    done
    
    echo ""
    if [ "$should_rotate" = true ]; then
        print_failure "SVID did not rotate within $timeout seconds"
        echo "Hash remained: ${initial_hash:0:16}..."
        return 1
    else
        print_success "SVID did not rotate as expected"
        echo "Hash remained: ${initial_hash:0:16}..."
        return 0
    fi
}

scale_spire_server() {
    local context=$1
    local replicas=$2
    local cluster_name=$3
    
    echo ""
    echo "Scaling SPIRE server in $cluster_name to $replicas replicas..."
    echo "=============================================================="
    
    echo ""
    echo "Command: kubectl --context $context scale statefulset spire-server -n spire --replicas=$replicas"
    kubectl --context "$context" scale statefulset spire-server -n spire --replicas=$replicas
    
    if [ "$replicas" -gt 0 ]; then
        echo ""
        echo "Waiting for SPIRE server to be ready..."
        echo "Command: kubectl --context $context wait --for=condition=ready pod -l app=spire-server -n spire --timeout=60s"
        kubectl --context "$context" wait --for=condition=ready pod \
            -l app=spire-server -n spire --timeout=60s 2>/dev/null || {
            print_warning "SPIRE server not ready within timeout"
        }
    else
        echo ""
        echo "Waiting for pods to terminate (5 seconds)..."
        sleep 5
        echo ""
        echo "Command: kubectl --context $context get pods -n spire -l app=spire-server --no-headers | wc -l"
        local pod_count=$(kubectl --context "$context" get pods -n spire \
            -l app=spire-server --no-headers 2>/dev/null | wc -l)
        echo "Remaining pods: $pod_count"
        
        if [ "$pod_count" -eq 0 ]; then
            print_success "SPIRE server scaled down successfully"
        else
            print_warning "Some server pods may still be terminating"
        fi
    fi
}

check_agent_health() {
    local agent_name=$1
    local context=$2
    
    echo ""
    echo "Checking $agent_name health..."
    echo "------------------------------"
    
    echo "Command: kubectl --context $context get pods -n spire -l app=$agent_name -o jsonpath='{.items[*].status.phase}'"
    local agent_status=$(kubectl --context "$context" get pods -n spire \
        -l app="$agent_name" -o jsonpath='{.items[*].status.phase}' 2>/dev/null)
    echo "Status: $agent_status"
    
    if [[ "$agent_status" == *"Running"* ]]; then
        print_info "$agent_name pods are running"
        echo ""
        echo "Command: kubectl --context $context logs -n spire daemonset/$agent_name --tail=5 --since=30s | grep -E '(error|connected|failed)'"
        echo "Recent log entries:"
        kubectl --context "$context" logs -n spire daemonset/"$agent_name" \
            --tail=5 --since=30s 2>/dev/null | grep -E "(error|connected|failed)" || echo "  No errors found in recent logs"
    else
        print_warning "$agent_name pods are not running properly"
    fi
}

ensure_test_workload_with_svids() {
    echo ""
    echo "Checking for test workload..."
    echo "=============================="
    
    echo ""
    echo "Command: kubectl --context $WORKLOAD_CONTEXT get pods -n $TEST_NAMESPACE -l app=$TEST_WORKLOAD --no-headers | wc -l"
    local pod_exists=$(kubectl --context "$WORKLOAD_CONTEXT" get pods -n "$TEST_NAMESPACE" \
        -l app="$TEST_WORKLOAD" --no-headers 2>/dev/null | wc -l)
    echo "Number of pods found: $pod_exists"
    
    if [ "$pod_exists" -eq 0 ]; then
        print_warning "Test workload not found, deploying..."
        echo ""
        echo "Command: kubectl --context $WORKLOAD_CONTEXT apply -f $INTEGRATION_DIR/workload/spire-csi/workload-a.yaml"
        kubectl --context "$WORKLOAD_CONTEXT" apply -f "$INTEGRATION_DIR/workload/spire-csi/workload-a.yaml"
        
        echo ""
        echo "Waiting for test workload to be ready..."
        kubectl --context "$WORKLOAD_CONTEXT" wait --for=condition=ready pod \
            -l app="$TEST_WORKLOAD" -n "$TEST_NAMESPACE" --timeout=60s || {
            print_failure "Test workload failed to become ready"
            exit 1
        }
    fi
    
    print_success "Test workload pod exists"
    
    echo ""
    echo "Waiting for CSI to provision SVIDs (10 seconds)..."
    sleep 10
    
    if ! check_svid_provisioning; then
        print_failure "SVIDs are not provisioned correctly"
        exit 1
    fi
    
    print_success "SVIDs are provisioned"
}

pre_test_validation() {
    print_test "0" "Pre-Test Validation"
    
    echo ""
    echo "Checking cluster accessibility..."
    echo "================================="
    for context in "$SUB01_CONTEXT" "$SUB02_CONTEXT" "$WORKLOAD_CONTEXT"; do
        echo ""
        echo "Command: kubectl --context $context cluster-info"
        if ! kubectl --context "$context" cluster-info &>/dev/null; then
            print_failure "Cannot access cluster: $context"
            exit 1
        fi
        print_success "Cluster accessible: $context"
    done
    
    echo ""
    echo "Checking subordinate servers..."
    echo "================================"
    for context in "$SUB01_CONTEXT" "$SUB02_CONTEXT"; do
        echo ""
        echo "Command: kubectl --context $context get pods -n spire -l app=spire-server --no-headers | wc -l"
        local server_running=$(kubectl --context "$context" get pods -n spire \
            -l app=spire-server --no-headers 2>/dev/null | wc -l)
        echo "Server pods found: $server_running"
        
        if [ "$server_running" -eq 0 ]; then
            print_warning "SPIRE server not running in $context, starting..."
            scale_spire_server "$context" 1 "$context"
        else
            print_success "SPIRE server already running in $context"
        fi
    done
    
    ensure_test_workload_with_svids
    
    echo ""
    echo "Getting initial SVID hash..."
    echo "============================="
    echo ""
    echo "Command: md5sum /run/spire/x509/cert.pem | cut -d' ' -f1"
    local initial_hash=$(get_svid_hash)
    echo "Result: $initial_hash"
    
    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] || 
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] || 
       [[ -z "$initial_hash" ]]; then
        print_failure "Cannot read valid SVID hash from test workload"
        print_info "SVID status: $initial_hash"
        check_svid_provisioning
        exit 1
    fi
    
    print_success "Initial SVID hash: ${initial_hash:0:16}..."
    
    echo ""
    echo "Checking agent health..."
    echo "========================"
    check_agent_health "spire-agent-child-01" "$WORKLOAD_CONTEXT"
    check_agent_health "spire-agent-child-02" "$WORKLOAD_CONTEXT"
}

test_1_scale_down_sub01() {
    print_test "1" "Scale Down Subordinate-01 Server"
    
    local initial_hash=$(get_svid_hash)
    
    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] || 
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] || 
       [[ -z "$initial_hash" ]]; then
        print_failure "Cannot get SVID hash before test"
        return 1
    fi
    
    print_info "Current SVID hash: ${initial_hash:0:16}..."
    
    scale_spire_server "$SUB01_CONTEXT" 0 "subordinate-01"
    
    echo ""
    echo "Waiting for agents to detect server failure (10 seconds)..."
    sleep 10
    
    check_agent_health "spire-agent-child-01" "$WORKLOAD_CONTEXT"
    check_agent_health "spire-agent-child-02" "$WORKLOAD_CONTEXT"
    
    echo ""
    print_info "Subordinate-01 is down, Subordinate-02 is still running"
    print_info "SVID should still rotate via subordinate-02..."
    
    return 0
}

test_2_verify_rotation_with_one_server() {
    print_test "2" "Verify SVID Rotation with One Server"
    
    local initial_hash=$(get_svid_hash)
    
    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] || 
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] || 
       [[ -z "$initial_hash" ]]; then
        print_failure "Cannot get SVID hash for rotation test"
        return 1
    fi
    
    if wait_for_svid_rotation "$initial_hash" 90 true; then
        echo ""
        print_success ">>> TEST PASSED: SVID rotates with only subordinate-02 running <<<"
        return 0
    else
        echo ""
        print_failure ">>> TEST FAILED: SVID did not rotate with subordinate-02 running <<<"
        return 1
    fi
}

test_3_scale_down_sub02() {
    print_test "3" "Scale Down Subordinate-02 Server"
    
    local initial_hash=$(get_svid_hash)
    
    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] || 
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] || 
       [[ -z "$initial_hash" ]]; then
        print_failure "Cannot get SVID hash before test"
        return 1
    fi
    
    print_info "Current SVID hash: ${initial_hash:0:16}..."
    
    scale_spire_server "$SUB02_CONTEXT" 0 "subordinate-02"
    
    echo ""
    echo "Waiting for agents to detect server failure (10 seconds)..."
    sleep 10
    
    check_agent_health "spire-agent-child-01" "$WORKLOAD_CONTEXT"
    check_agent_health "spire-agent-child-02" "$WORKLOAD_CONTEXT"
    
    echo ""
    print_info "Both subordinate servers are now down"
    print_info "SVID rotation should stop..."
    
    return 0
}

test_4_verify_no_rotation() {
    print_test "4" "Verify SVID Rotation Stops"
    
    local initial_hash=$(get_svid_hash)
    
    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] || 
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] || 
       [[ -z "$initial_hash" ]]; then
        print_failure "Cannot get SVID hash for no-rotation test"
        return 1
    fi
    
    if wait_for_svid_rotation "$initial_hash" 60 false; then
        echo ""
        print_success ">>> TEST PASSED: SVID did not rotate with both servers down <<<"
        return 0
    else
        echo ""
        print_failure ">>> TEST FAILED: SVID rotated when both servers were down <<<"
        return 1
    fi
}

test_5_scale_up_sub01() {
    print_test "5" "Scale Up Subordinate-01 Server"
    
    local initial_hash=$(get_svid_hash)
    
    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] || 
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] || 
       [[ -z "$initial_hash" ]]; then
        print_failure "Cannot get SVID hash before test"
        return 1
    fi
    
    print_info "Current SVID hash: ${initial_hash:0:16}..."
    
    scale_spire_server "$SUB01_CONTEXT" 1 "subordinate-01"
    
    echo ""
    echo "Waiting for agents to reconnect (15 seconds)..."
    sleep 15
    
    check_agent_health "spire-agent-child-01" "$WORKLOAD_CONTEXT"
    check_agent_health "spire-agent-child-02" "$WORKLOAD_CONTEXT"
    
    echo ""
    print_info "Subordinate-01 is back up"
    print_info "SVID rotation should resume..."
    
    return 0
}

test_6_verify_rotation_resumes() {
    print_test "6" "Verify SVID Rotation Resumes"
    
    local initial_hash=$(get_svid_hash)
    
    if [[ "$initial_hash" == "NOFILE" ]] || [[ "$initial_hash" == "ERROR" ]] || 
       [[ "$initial_hash" == "NOPOD" ]] || [[ "$initial_hash" == "EMPTY" ]] || 
       [[ -z "$initial_hash" ]]; then
        print_failure "Cannot get SVID hash for rotation resume test"
        return 1
    fi
    
    if wait_for_svid_rotation "$initial_hash" 90 true; then
        echo ""
        print_success ">>> TEST PASSED: SVID rotation resumed after server recovery <<<"
        return 0
    else
        echo ""
        print_failure ">>> TEST FAILED: SVID rotation did not resume after server recovery <<<"
        return 1
    fi
}

cleanup() {
    print_test "7" "Cleanup and Restore"
    
    echo ""
    echo "Restoring subordinate servers..."
    echo "================================="
    
    scale_spire_server "$SUB01_CONTEXT" 1 "subordinate-01"
    scale_spire_server "$SUB02_CONTEXT" 1 "subordinate-02"
    
    echo ""
    echo "Waiting for services to stabilize (10 seconds)..."
    sleep 10
    
    echo ""
    echo "Verifying server restoration..."
    echo "================================"
    for context in "$SUB01_CONTEXT" "$SUB02_CONTEXT"; do
        echo ""
        echo "Command: kubectl --context $context get pods -n spire -l app=spire-server -o jsonpath='{.items[*].status.phase}'"
        local server_running=$(kubectl --context "$context" get pods -n spire \
            -l app=spire-server -o jsonpath='{.items[*].status.phase}' 2>/dev/null)
        echo "Server status in $context: $server_running"
        
        if [[ "$server_running" == *"Running"* ]]; then
            print_success "Server restored in $context"
        else
            print_warning "Server may not be fully restored in $context"
        fi
    done
    
    echo ""
    print_success "Cleanup complete"
}

main() {
    local test_results=()
    local failed_tests=0
    
    pre_test_validation
    
    echo ""
    print_success "Pre-test validation complete. Starting HA tests..."
    
    tests=(
        "test_1_scale_down_sub01"
        "test_2_verify_rotation_with_one_server"
        "test_3_scale_down_sub02"
        "test_4_verify_no_rotation"
        "test_5_scale_up_sub01"
        "test_6_verify_rotation_resumes"
    )
    
    for test in "${tests[@]}"; do
        wait_for_user
        
        if $test; then
            test_results+=("$test: PASSED")
        else
            test_results+=("$test: FAILED")
            ((failed_tests++))
        fi
        
        sleep 5
    done
    
    wait_for_user
    cleanup
    
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}Test Summary${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    for result in "${test_results[@]}"; do
        if [[ "$result" == *"PASSED"* ]]; then
            echo -e "${GREEN}[PASS]${NC} $result"
        else
            echo -e "${RED}[FAIL]${NC} $result"
        fi
    done
    
    echo ""
    if [ $failed_tests -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}$failed_tests test(s) failed${NC}"
        exit 1
    fi
}

trap cleanup EXIT

main "$@"