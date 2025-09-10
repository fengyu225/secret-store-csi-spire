#!/bin/bash

check_prerequisites() {
    local required_tools=("kind" "kubectl" "docker" "docker-compose" "envsubst")
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        else
            print_success "$tool is available"
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        return 1
    fi

    return 0
}
