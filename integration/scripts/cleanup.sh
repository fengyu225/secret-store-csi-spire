#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
INTEGRATION_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${RED}SPIRE Integration Test Cleanup${NC}"
echo "=============================="
echo "This will destroy all Kind clusters and PostgreSQL containers"
echo ""

read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled"
    exit 0
fi

echo -e "\n${BLUE}Cleaning up Kind clusters...${NC}"

clusters=("spire-root" "spire-subordinate-01" "spire-subordinate-02" "workload")
for cluster in "${clusters[@]}"; do
    if kind get clusters | grep -q "$cluster"; then
        echo "Deleting cluster: $cluster"
        kind delete cluster --name "$cluster"
        echo -e "${GREEN}✓${NC} $cluster deleted"
    else
        echo -e "${YELLOW}✓${NC} $cluster does not exist"
    fi
done

echo -e "\n${BLUE}Stopping PostgreSQL containers...${NC}"
cd "$INTEGRATION_DIR/root"
if [ -f "docker-compose.yml" ]; then
    docker-compose down -v
    echo -e "${GREEN}✓${NC} PostgreSQL containers stopped and volumes removed"
else
    echo -e "${YELLOW}✓${NC} No docker-compose.yml found"
fi

echo -e "\n${GREEN}Cleanup complete!${NC}"
echo "All Kind clusters and PostgreSQL containers have been removed."
