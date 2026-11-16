#!/usr/bin/env bash
# ==============================================================================
# kr0n mTLS Certificate Generator
# Generates a Root CA, Auth Server Certificate, and Gateway Client Certificate
# for zero-trust internal gRPC communication between Gateway and Auth microservices.
# ==============================================================================

set -euo pipefail

OUT_DIR="${1:-./certs}"
DAYS_VALID=365
CA_DAYS_VALID=3650

echo "==> Generating kr0n mTLS certificates in: ${OUT_DIR}"
mkdir -p "${OUT_DIR}/ca" "${OUT_DIR}/auth" "${OUT_DIR}/gateway"

# ------------------------------------------------------------------------------
# 1. Root Certificate Authority (CA)
# ------------------------------------------------------------------------------
echo "--> [1/3] Generating Root CA..."
openssl ecparam -name prime256v1 -genkey -noout -out "${OUT_DIR}/ca/ca.key"

cat <<EOF > "${OUT_DIR}/ca/ca.cnf"
[req]
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_ca

[req_distinguished_name]
CN = kr0n Root CA
O  = kr0n
OU = Security

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

openssl req -new -x509 -days "${CA_DAYS_VALID}" \
  -key "${OUT_DIR}/ca/ca.key" \
  -out "${OUT_DIR}/ca/ca.crt" \
  -config "${OUT_DIR}/ca/ca.cnf"

# ------------------------------------------------------------------------------
# 2. Auth gRPC Server Certificate
# ------------------------------------------------------------------------------
echo "--> [2/3] Generating Auth gRPC Server certificate..."
openssl ecparam -name prime256v1 -genkey -noout -out "${OUT_DIR}/auth/server.key"

cat <<EOF > "${OUT_DIR}/auth/server.cnf"
[req]
distinguished_name = req_distinguished_name
prompt = no
req_extensions = v3_req

[req_distinguished_name]
CN = auth.internal
O  = kr0n
OU = Auth

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = auth.internal
DNS.2 = auth
DNS.3 = localhost
IP.1  = 127.0.0.1
IP.2  = 0.0.0.0
EOF

openssl req -new \
  -key "${OUT_DIR}/auth/server.key" \
  -out "${OUT_DIR}/auth/server.csr" \
  -config "${OUT_DIR}/auth/server.cnf"

openssl x509 -req -days "${DAYS_VALID}" \
  -in "${OUT_DIR}/auth/server.csr" \
  -CA "${OUT_DIR}/ca/ca.crt" \
  -CAkey "${OUT_DIR}/ca/ca.key" \
  -CAcreateserial \
  -out "${OUT_DIR}/auth/server.crt" \
  -extfile "${OUT_DIR}/auth/server.cnf" \
  -extensions v3_req

# ------------------------------------------------------------------------------
# 3. Gateway mTLS Client Certificate
# ------------------------------------------------------------------------------
echo "--> [3/3] Generating Gateway mTLS Client certificate..."
openssl ecparam -name prime256v1 -genkey -noout -out "${OUT_DIR}/gateway/client.key"

cat <<EOF > "${OUT_DIR}/gateway/client.cnf"
[req]
distinguished_name = req_distinguished_name
prompt = no
req_extensions = v3_req

[req_distinguished_name]
CN = kr0n-gateway
O  = kr0n
OU = Gateway

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = kr0n-gateway
DNS.2 = gateway
DNS.3 = localhost
EOF

openssl req -new \
  -key "${OUT_DIR}/gateway/client.key" \
  -out "${OUT_DIR}/gateway/client.csr" \
  -config "${OUT_DIR}/gateway/client.cnf"

openssl x509 -req -days "${DAYS_VALID}" \
  -in "${OUT_DIR}/gateway/client.csr" \
  -CA "${OUT_DIR}/ca/ca.crt" \
  -CAkey "${OUT_DIR}/ca/ca.key" \
  -CAcreateserial \
  -out "${OUT_DIR}/gateway/client.crt" \
  -extfile "${OUT_DIR}/gateway/client.cnf" \
  -extensions v3_req

# Cleanup CSRs and configs
rm -f "${OUT_DIR}/ca/ca.cnf" \
      "${OUT_DIR}/auth/server.cnf" "${OUT_DIR}/auth/server.csr" \
      "${OUT_DIR}/gateway/client.cnf" "${OUT_DIR}/gateway/client.csr" \
      "${OUT_DIR}/ca/ca.srl"

# Set strict permissions
chmod 600 "${OUT_DIR}/ca/ca.key" "${OUT_DIR}/auth/server.key" "${OUT_DIR}/gateway/client.key"
chmod 644 "${OUT_DIR}/ca/ca.crt" "${OUT_DIR}/auth/server.crt" "${OUT_DIR}/gateway/client.crt"

ABS_DIR="$(cd "${OUT_DIR}" && pwd)"

echo "==> Certificates successfully generated in: ${ABS_DIR}"
echo ""
echo "Files created:"
echo "  CA:       ${ABS_DIR}/ca/ca.crt"
echo "  Auth:     ${ABS_DIR}/auth/server.crt, ${ABS_DIR}/auth/server.key"
echo "  Gateway:  ${ABS_DIR}/gateway/client.crt, ${ABS_DIR}/gateway/client.key"
echo ""
echo "=============================================================================="
echo "Environment configuration for mTLS:"
echo "=============================================================================="
echo "# Auth Service:"
echo "AUTH_GRPC_TLS_CERT_FILE=${ABS_DIR}/auth/server.crt"
echo "AUTH_GRPC_TLS_KEY_FILE=${ABS_DIR}/auth/server.key"
echo "AUTH_GRPC_CLIENT_CA_FILE=${ABS_DIR}/ca/ca.crt"
echo "AUTH_GRPC_ALLOWED_CLIENTS=kr0n-gateway,gateway"
echo ""
echo "# Gateway (via gateway.yaml or environment):"
echo "AUTH_GRPC_TLS_ENABLED=true"
echo "AUTH_GRPC_TLS_CA_FILE=${ABS_DIR}/ca/ca.crt"
echo "GATEWAY_GRPC_TLS_CERT_FILE=${ABS_DIR}/gateway/client.crt"
echo "GATEWAY_GRPC_TLS_KEY_FILE=${ABS_DIR}/gateway/client.key"
echo "AUTH_GRPC_SERVER_NAME=auth.internal"
echo "=============================================================================="
