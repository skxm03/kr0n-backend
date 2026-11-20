#!/usr/bin/env bash
# ==============================================================================
# kr0n Environment & Configuration Pre-Flight Validator
# Checks .env completeness, TLS certificates, keys, and backing dependencies.
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
BOLD="\033[1m"
RESET="\033[0m"

ERRORS=0
WARNINGS=0

pass() {
  echo -e "  [${GREEN}✓${RESET}] $1"
}

fail() {
  echo -e "  [${RED}✗${RESET}] $1"
  ERRORS=$((ERRORS + 1))
}

warn() {
  echo -e "  [${YELLOW}!${RESET}] $1"
  WARNINGS=$((WARNINGS + 1))
}

info() {
  echo -e "  [${BLUE}i${RESET}] $1"
}

echo -e "\n${BOLD}==============================================================================${RESET}"
echo -e "${BOLD}              kr0n Environment & Pre-Flight Configuration Check               ${RESET}"
echo -e "${BOLD}==============================================================================${RESET}\n"

# ------------------------------------------------------------------------------
# 1. Environment File Check
# ------------------------------------------------------------------------------
echo -e "${BOLD}1. Checking Environment Files (.env)...${RESET}"

ENV_FILE=""
if [ -f ".env" ]; then
  ENV_FILE=".env"
  pass "Root .env found"
elif [ -f "control-plane/.env" ]; then
  ENV_FILE="control-plane/.env"
  pass "control-plane/.env found"
else
  fail "No .env file found at root or in control-plane/! Run: cp .env.example .env"
fi

if [ -n "${ENV_FILE}" ]; then
  # Source .env safely
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

# ------------------------------------------------------------------------------
# 2. Core Infrastructure Variables
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}2. Checking Backing Services & Network Endpoints...${RESET}"

check_var() {
  local var_name="$1"
  local expected_desc="$2"
  local val="${!var_name:-}"

  if [ -z "${val}" ]; then
    fail "${var_name} is empty or missing (${expected_desc})"
  else
    pass "${var_name}=${val}"
  fi
}

check_var "KR0N_ENV" "dev or production"
check_var "DATABASE_URL" "PostgreSQL connection string (e.g. port 5433 for dev)"
check_var "REDIS_ADDR" "Redis address (e.g. localhost:6379)"
check_var "RABBITMQ_URL" "RabbitMQ AMQP URL (e.g. amqp://guest:guest@localhost:5672/)"
check_var "SMTP_ADDR" "SMTP server address (e.g. localhost:1025)"
check_var "AUTH_GRPC_ADDR" "Auth gRPC address (e.g. 127.0.0.1:50051)"
check_var "GATEWAY_HTTP_ADDR" "Gateway HTTP address (e.g. :8080)"
check_var "GITHUB_GRPC_ADDR" "GitHub gRPC address (e.g. 127.0.0.1:50052)"

# Check DB Port specifically for 5433 in dev
if [[ "${DATABASE_URL:-}" =~ :5433/ ]]; then
  pass "DATABASE_URL is correctly targeting port 5433 (host mapped dev container)"
elif [[ "${DATABASE_URL:-}" =~ :5432/ ]]; then
  warn "DATABASE_URL targets port 5432. If using Docker Compose dev containers, port 5433 is recommended to prevent host conflicts."
fi

# ------------------------------------------------------------------------------
# 3. TLS Certificates & Keys Verification
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}3. Checking mTLS & TLS Certificates on Disk...${RESET}"

check_file() {
  local label="$1"
  local file_path="$2"
  local required="${3:-true}"

  if [ -z "${file_path}" ]; then
    if [ "${required}" = "true" ]; then
      fail "${label}: file path is not set in .env"
    else
      warn "${label}: not configured (optional in dev)"
    fi
    return
  fi

  # Resolve relative to root or control-plane
  local resolved="${file_path}"
  if [ ! -f "${resolved}" ] && [ -f "control-plane/${file_path}" ]; then
    resolved="control-plane/${file_path}"
  fi

  if [ -f "${resolved}" ]; then
    # If it's a certificate, test validity with openssl if available
    if [[ "${resolved}" == *.crt || "${resolved}" == *.pem ]]; then
      if command -v openssl >/dev/null 2>&1; then
        if openssl x509 -in "${resolved}" -noout -subject >/dev/null 2>&1; then
          local subj
          subj=$(openssl x509 -in "${resolved}" -noout -subject 2>/dev/null | sed 's/subject=//')
          pass "${label} found at ${file_path} (${subj})"
        else
          # Might be private key
          pass "${label} found at ${file_path}"
        fi
      else
        pass "${label} found at ${file_path}"
      fi
    else
      pass "${label} found at ${file_path}"
    fi
  else
    if [ "${required}" = "true" ]; then
      fail "${label} NOT found at ${file_path} (Run 'make certs' to generate)"
    else
      warn "${label} not found at ${file_path}"
    fi
  fi
}

check_file "Root CA Certificate" "${AUTH_GRPC_CLIENT_CA_FILE:-certs/ca/ca.crt}" true
check_file "Auth Server Certificate" "${AUTH_GRPC_TLS_CERT_FILE:-certs/auth/server.crt}" true
check_file "Auth Server Private Key" "${AUTH_GRPC_TLS_KEY_FILE:-certs/auth/server.key}" true
check_file "Gateway Client Certificate" "${GATEWAY_GRPC_TLS_CERT_FILE:-certs/gateway/client.crt}" true
check_file "Gateway Client Private Key" "${GATEWAY_GRPC_TLS_KEY_FILE:-certs/gateway/client.key}" true
check_file "GitHub Server Certificate" "${GITHUB_TLS_CERT_FILE:-certs/github/server.crt}" true
check_file "GitHub Server Private Key" "${GITHUB_TLS_KEY_FILE:-certs/github/server.key}" true

# ------------------------------------------------------------------------------
# 4. GitHub App Credentials & Private Key
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}4. Checking GitHub App Credentials & Secrets...${RESET}"

GH_KEY_PATH="${GITHUB_APP_PRIVATE_KEY_PATH:-${GITHUB_APP_PRIVATE_KEY:-}}"
if [ -n "${GH_KEY_PATH}" ]; then
  # Check if it is a file path
  GH_RESOLVED="${GH_KEY_PATH}"
  if [ ! -f "${GH_RESOLVED}" ] && [ -f "control-plane/${GH_KEY_PATH}" ]; then
    GH_RESOLVED="control-plane/${GH_KEY_PATH}"
  fi

  if [ -f "${GH_RESOLVED}" ]; then
    if grep -q "BEGIN.*PRIVATE KEY" "${GH_RESOLVED}"; then
      pass "GitHub App Private Key found at ${GH_KEY_PATH} (valid PEM header)"
    else
      warn "File at ${GH_KEY_PATH} does not appear to be a PEM private key"
    fi
  elif [[ "${GH_KEY_PATH}" =~ BEGIN.*PRIVATE\ KEY ]]; then
    pass "GitHub App Private Key is configured inline via PEM string"
  else
    fail "GitHub App Private Key file NOT found at: ${GH_KEY_PATH}"
  fi
else
  warn "GITHUB_APP_PRIVATE_KEY is empty (GitHub App integration will return 503 until set)"
fi

if [ -z "${GITHUB_APP_ID:-}" ]; then
  info "GITHUB_APP_ID is not set (required for GitHub App token generation)"
else
  pass "GITHUB_APP_ID=${GITHUB_APP_ID}"
fi

if [ -z "${GITHUB_CLIENT_ID:-}" ] || [ -z "${GITHUB_CLIENT_SECRET:-}" ]; then
  info "GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are empty (GitHub OAuth login disabled)"
else
  pass "GitHub OAuth Client ID configured"
fi

# ------------------------------------------------------------------------------
# 5. Backing Services Live Connectivity (Optional check)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}5. Checking Local Backing Services (Docker Containers)...${RESET}"

check_port() {
  local name="$1"
  local host="$2"
  local port="$3"

  if nc -z -w 1 "${host}" "${port}" >/dev/null 2>&1; then
    pass "${name} is reachable on ${host}:${port}"
  else
    warn "${name} is not responding on ${host}:${port} (Run 'make dev-infra' to start)"
  fi
}

check_port "PostgreSQL" "127.0.0.1" 5433
check_port "Redis" "127.0.0.1" 6379
check_port "RabbitMQ" "127.0.0.1" 5672
check_port "Mailpit SMTP" "127.0.0.1" 1025

# ------------------------------------------------------------------------------
# Final Summary
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}==============================================================================${RESET}"
if [ ${ERRORS} -eq 0 ]; then
  if [ ${WARNINGS} -eq 0 ]; then
    echo -e "${GREEN}${BOLD} All pre-flight configuration and certificate checks passed!${RESET}"
  else
    echo -e "${YELLOW}${BOLD} Pre-flight checks passed with ${WARNINGS} warning(s). Environment is ready to run.${RESET}"
  fi
  echo -e "${BOLD}==============================================================================${RESET}\n"
  exit 0
else
  echo -e "${RED}${BOLD} Configuration check failed with ${ERRORS} error(s) and ${WARNINGS} warning(s).${RESET}"
  echo -e "Please review the errors above before launching services."
  echo -e "${BOLD}==============================================================================${RESET}\n"
  exit 1
fi
