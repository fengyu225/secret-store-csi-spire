#!/bin/bash

start_databases() {
    local integration_dir=$1
    cd "$integration_dir/root"

    docker-compose up -d
    print_success "PostgreSQL databases started"

    echo "Waiting for databases to be ready..."
    for i in {1..30}; do
        if docker-compose exec -T postgres pg_isready -U "$DB_USER" > /dev/null 2>&1; then
            print_success "PostgreSQL is ready"
            return 0
        fi
        echo "Waiting for PostgreSQL... ($i/30)"
        sleep 2
    done

    print_error "PostgreSQL failed to start"
    return 1
}

create_db_secret() {
    local integration_dir=$1
    cat > "$integration_dir/root/secrets.env" <<EOF
DB_CONNECTION_STRING=postgresql://${DB_USER}:${DB_PASSWORD}@host.docker.internal:5432/${DB_NAME}?sslmode=disable
EOF
}
