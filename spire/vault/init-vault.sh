#!/bin/bash

VAULT_ADDR='https://127.0.0.1:8200'
VAULT_TOKEN='root'
VAULT_SKIP_VERIFY='true'

export VAULT_ADDR VAULT_TOKEN VAULT_SKIP_VERIFY

mkdir -p certs config data

until docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 vault status -tls-skip-verify' > /dev/null 2>&1; do
    echo "Waiting for Vault to start..."
    sleep 1
done

# Enable PKI secret engine at path pki_root with longer TTL for SPIRE
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault secrets enable -tls-skip-verify -path=pki_root pki'
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault secrets tune -tls-skip-verify -max-lease-ttl=87600h pki_root'

# Generate root CA
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault write -tls-skip-verify pki_root/root/generate/internal \
    common_name="SPIRE Root CA" \
    ttl=87600h \
    key_type="ec" \
    key_bits=384 \
    issuer_name="spire-root-2025"'

docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault write -tls-skip-verify pki_root/config/urls \
    issuing_certificates="https://vault:8200/v1/pki_root/ca" \
    crl_distribution_points="https://vault:8200/v1/pki_root/crl"'

# Enable cert auth method
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault auth enable -tls-skip-verify cert'
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault auth tune -tls-skip-verify -max-lease-ttl=87600h cert'

# Generate client certificate for SPIRE server
openssl genrsa -out certs/client.key 4096
openssl req -new -key certs/client.key -out certs/client.csr \
    -subj "/CN=spire-server/O=SPIRE"
openssl x509 -req -in certs/client.csr \
    -signkey certs/client.key \
    -out certs/client.crt \
    -days 3650 \
    -sha256

# Create policy for SPIRE server
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault policy write -tls-skip-verify spire-server-policy - <<EOF
path "pki_root/root/sign-intermediate" {
  capabilities = ["create", "update"]
}

path "pki_root/cert/ca" {
  capabilities = ["read"]
}

path "pki_root/crl" {
  capabilities = ["read"]
}

path "auth/cert/login" {
  capabilities = ["create", "read"]
}

path "pki_root/config/*" {
  capabilities = ["read"]
}

path "pki_root/roles/*" {
  capabilities = ["create", "read", "update"]
}

path "pki_root/issue/*" {
  capabilities = ["create", "update"]
}
EOF'

# Configure cert auth for SPIRE server with file from the container path
docker-compose cp certs/client.crt vault:/vault/certs/client.crt
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault write -tls-skip-verify auth/cert/certs/spire-server \
    display_name="spire-server" \
    policies="spire-server-policy" \
    certificate=@/vault/certs/client.crt \
    ttl=87600h \
    allowed_common_names="spire-server" \
    allowed_organizations="SPIRE" \
    require_matching_certificates=true'

# Save CA certificate
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault read -tls-skip-verify -field=certificate pki_root/cert/ca' > certs/ca.crt

# Create the Kubernetes secret with base64 encoded certificates
echo "Creating base64 encoded certificates for Kubernetes secret..."
CA_CERT=$(cat certs/ca.crt | base64)
CLIENT_CERT=$(cat certs/client.crt | base64)
CLIENT_KEY=$(cat certs/client.key | base64)

cat > vault-certs-secret.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: vault-certs
  namespace: spire
type: Opaque
data:
  ca.crt: ${CA_CERT}
  client.crt: ${CLIENT_CERT}
  client.key: ${CLIENT_KEY}
EOF

echo "Vault setup complete!"
echo "Files generated:"
echo "- Client certificate: certs/client.crt"
echo "- Client key: certs/client.key"
echo "- CA certificate: certs/ca.crt"
echo "- Kubernetes secret: vault-certs-secret.yaml"
echo ""
echo "UI Access:"
echo "URL: https://localhost:8200"
echo "Token: root"

# Verify
echo -e "\nVerifying auth methods..."
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault auth list -tls-skip-verify'

echo -e "\nVerifying certificate auth configuration..."
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault read -tls-skip-verify auth/cert/certs/spire-server'

echo -e "\nVerifying policy..."
docker-compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=root vault policy read -tls-skip-verify spire-server-policy'