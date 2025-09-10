#!/bin/bash

# Image Management Library
# Provides functions to pull and load container images for the integration setup

readonly IMAGES_CONFIG="$SCRIPT_DIR/images.env"

# Source the images configuration
if [[ -f "$IMAGES_CONFIG" ]]; then
    source "$IMAGES_CONFIG"
else
    echo "Error: Images configuration file not found at $IMAGES_CONFIG"
    exit 1
fi

# Pull all required images
pull_all_images() {
    echo "Pulling all required container images..."
    
    local failed_images=()
    local pulled_count=0
    local total_count=${#ALL_IMAGES[@]}
    
    for image in "${ALL_IMAGES[@]}"; do
        echo "  Pulling $image..."
        if docker pull "$image"; then
            ((pulled_count++))
            echo "    Successfully pulled $image"
        else
            failed_images+=("$image")
            echo "    Failed to pull $image"
        fi
    done
    
    echo ""
    echo "Image pull summary:"
    echo "  Total images: $total_count"
    echo "  Successfully pulled: $pulled_count"
    echo "  Failed: ${#failed_images[@]}"
    
    if [[ ${#failed_images[@]} -gt 0 ]]; then
        echo ""
        echo "Failed to pull the following images:"
        for image in "${failed_images[@]}"; do
            echo "  - $image"
        done
        return 1
    fi
    
    echo "  All images pulled successfully"
    return 0
}

# Load images into a specific kind cluster
load_images_to_cluster() {
    local cluster_name="$1"
    
    if [[ -z "$cluster_name" ]]; then
        echo "Error: Cluster name is required"
        return 1
    fi
    
    echo "Loading images into kind cluster: $cluster_name"
    
    local failed_images=()
    local loaded_count=0
    local total_count=${#ALL_IMAGES[@]}
    
    for image in "${ALL_IMAGES[@]}"; do
        echo "  Loading $image into $cluster_name..."
        if kind load docker-image "$image" --name "$cluster_name"; then
            ((loaded_count++))
            echo "    Successfully loaded $image"
        else
            failed_images+=("$image")
            echo "    Failed to load $image"
        fi
    done
    
    echo ""
    echo "Image load summary for $cluster_name:"
    echo "  Total images: $total_count"
    echo "  Successfully loaded: $loaded_count"  
    echo "  Failed: ${#failed_images[@]}"
    
    if [[ ${#failed_images[@]} -gt 0 ]]; then
        echo ""
        echo "Failed to load the following images into $cluster_name:"
        for image in "${failed_images[@]}"; do
            echo "  - $image"
        done
        return 1
    fi
    
    echo "  All images loaded successfully into $cluster_name"
    return 0
}

# Load images into all kind clusters
load_images_to_all_clusters() {
    echo "Loading images into all kind clusters..."
    
    local clusters=("$ROOT_CLUSTER" "$SUB01_CLUSTER" "$SUB02_CLUSTER" "workload")
    local failed_clusters=()
    
    for cluster in "${clusters[@]}"; do
        echo ""
        if load_images_to_cluster "$cluster"; then
            echo "Successfully loaded images into $cluster"
        else
            failed_clusters+=("$cluster")
            echo "Failed to load images into $cluster"
        fi
    done
    
    echo ""
    echo "Overall load summary:"
    echo "  Total clusters: ${#clusters[@]}"
    echo "  Successfully loaded: $((${#clusters[@]} - ${#failed_clusters[@]}))"
    echo "  Failed: ${#failed_clusters[@]}"
    
    if [[ ${#failed_clusters[@]} -gt 0 ]]; then
        echo ""
        echo "Failed to load images into the following clusters:"
        for cluster in "${failed_clusters[@]}"; do
            echo "  - $cluster"
        done
        return 1
    fi
    
    echo "  All images loaded successfully into all clusters"
    return 0
}

# Prepare all images (pull and load into all clusters)
prepare_images() {
    echo "========================================="
    echo "Preparing Container Images"
    echo "========================================="
    
    # Pull all images
    if ! pull_all_images; then
        echo "Error: Failed to pull some images"
        return 1
    fi
    
    echo ""
    
    # Load images into all clusters
    if ! load_images_to_all_clusters; then
        echo "Error: Failed to load images into some clusters"
        return 1
    fi
    
    echo ""
    echo "All container images prepared successfully"
    return 0
}

# Check if an image exists locally
image_exists_locally() {
    local image="$1"
    docker image inspect "$image" &>/dev/null
}

# Verify all images are available locally
verify_images() {
    echo "Verifying all required images are available locally..."
    
    local missing_images=()
    local available_count=0
    
    for image in "${ALL_IMAGES[@]}"; do
        if image_exists_locally "$image"; then
            ((available_count++))
            echo "  $image"
        else
            missing_images+=("$image")
            echo "  $image (not found locally)"
        fi
    done
    
    echo ""
    echo "Image verification summary:"
    echo "  Total images: ${#ALL_IMAGES[@]}"
    echo "  Available locally: $available_count"
    echo "  Missing: ${#missing_images[@]}"
    
    if [[ ${#missing_images[@]} -gt 0 ]]; then
        echo ""
        echo "Missing images:"
        for image in "${missing_images[@]}"; do
            echo "  - $image"
        done
        return 1
    fi
    
    echo "  All required images are available locally"
    return 0
}