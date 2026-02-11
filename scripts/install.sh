#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA_FILE="${ROOT_DIR}/scripts/schema.sql"

if [[ ! -f "${SCHEMA_FILE}" ]]; then
  echo "Missing schema file: ${SCHEMA_FILE}" >&2
  exit 1
fi

if [[ $EUID -eq 0 ]]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  echo "This script requires root privileges (sudo not found)." >&2
  exit 1
fi

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo "dnf"
    return
  fi
  echo "unsupported"
}

install_dependencies() {
  local pm
  pm="$(detect_pkg_manager)"
  case "${pm}" in
    apt)
      ${SUDO} apt-get update
      ${SUDO} apt-get install -y \
        ca-certificates curl git \
        golang-go \
        mysql-server mysql-client \
        nginx iptables fail2ban \
        openvpn easy-rsa
      ;;
    dnf)
      ${SUDO} dnf install -y \
        ca-certificates curl git \
        golang \
        mysql-server mysql \
        nginx iptables-nft fail2ban \
        openvpn easy-rsa
      ;;
    *)
      echo "Unsupported package manager. Install dependencies manually and rerun." >&2
      exit 1
      ;;
  esac
}

prompt() {
  local var_name="$1"
  local label="$2"
  local default="${3:-}"
  local value=""

  if [[ -n "${default}" ]]; then
    read -r -p "${label} [${default}]: " value
    value="${value:-$default}"
  else
    read -r -p "${label}: " value
  fi

  printf -v "${var_name}" "%s" "${value}"
}

prompt_secret() {
  local var_name="$1"
  local label="$2"
  local value=""
  read -r -s -p "${label}: " value
  echo
  printf -v "${var_name}" "%s" "${value}"
}

escape_sql_value() {
  local raw="$1"
  raw="${raw//\\/\\\\}"
  raw="${raw//\'/\\\'}"
  printf "%s" "${raw}"
}

normalize_ns_host() {
  local host="$1"
  host="${host// /}"
  host="${host,,}"
  if [[ -n "${host}" && "${host}" != *"." ]]; then
    host="${host}."
  fi
  printf "%s" "${host}"
}

MYSQL_HOST=""
MYSQL_PORT=""
MYSQL_ROOT_USER=""
MYSQL_ROOT_PASSWORD=""
APP_DB_NAME=""
APP_DB_USER=""
APP_DB_PASSWORD=""
APP_LISTEN_ADDR=""
APP_BASE_URL=""
ADMIN_USER=""
ADMIN_PASSWORD=""
USE_DNS=""
USE_DNSSEC=""
NS1=""
NS2=""

echo "Installing system dependencies..."
install_dependencies

echo "Ensuring services are enabled..."
${SUDO} systemctl enable --now mysql 2>/dev/null || ${SUDO} systemctl enable --now mysqld 2>/dev/null || true
${SUDO} systemctl enable --now nginx 2>/dev/null || true

prompt MYSQL_HOST "MySQL host" "127.0.0.1"
prompt MYSQL_PORT "MySQL port" "3306"
prompt MYSQL_ROOT_USER "MySQL admin user" "root"
prompt_secret MYSQL_ROOT_PASSWORD "MySQL admin password (leave empty for socket auth)"
prompt APP_DB_NAME "Application database name" "goresolver"
prompt APP_DB_USER "Application database user" "goresolver"
prompt_secret APP_DB_PASSWORD "Application database password"
if [[ -z "${APP_DB_PASSWORD}" ]]; then
  echo "Database password cannot be empty." >&2
  exit 1
fi

prompt APP_LISTEN_ADDR "App listen address" ":8888"
prompt APP_BASE_URL "App base URL" "http://localhost:8888"

prompt ADMIN_USER "Initial admin username" "admin"
prompt_secret ADMIN_PASSWORD "Initial admin password"
if [[ -z "${ADMIN_PASSWORD}" ]]; then
  echo "Admin password cannot be empty." >&2
  exit 1
fi

read -r -p "Enable the built-in DNS server? [y/N]: " USE_DNS
USE_DNS="${USE_DNS,,}"

if [[ "${USE_DNS}" == "y" || "${USE_DNS}" == "yes" ]]; then
  prompt NS1 "Primary nameserver hostname" "ns1.example.com"
  prompt NS2 "Secondary nameserver hostname" "ns2.example.com"
  NS1="$(normalize_ns_host "${NS1}")"
  NS2="$(normalize_ns_host "${NS2}")"
  read -r -p "Enable DNSSEC signing? [y/N]: " USE_DNSSEC
  USE_DNSSEC="${USE_DNSSEC,,}"
fi

MYSQL_ARGS=(-h "${MYSQL_HOST}" -P "${MYSQL_PORT}" -u "${MYSQL_ROOT_USER}")
if [[ -n "${MYSQL_ROOT_PASSWORD}" ]]; then
  MYSQL_ARGS+=("-p${MYSQL_ROOT_PASSWORD}")
fi

mysql_exec() {
  mysql "${MYSQL_ARGS[@]}" "$@"
}

echo "Creating database and user..."
APP_DB_NAME_ESC="$(escape_sql_value "${APP_DB_NAME}")"
APP_DB_USER_ESC="$(escape_sql_value "${APP_DB_USER}")"
APP_DB_PASSWORD_ESC="$(escape_sql_value "${APP_DB_PASSWORD}")"

mysql_exec -e "CREATE DATABASE IF NOT EXISTS \`${APP_DB_NAME_ESC}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql_exec -e "CREATE USER IF NOT EXISTS '${APP_DB_USER_ESC}'@'%' IDENTIFIED BY '${APP_DB_PASSWORD_ESC}';"
mysql_exec -e "GRANT ALL PRIVILEGES ON \`${APP_DB_NAME_ESC}\`.* TO '${APP_DB_USER_ESC}'@'%'; FLUSH PRIVILEGES;"

echo "Applying schema..."
mysql_exec "${APP_DB_NAME}" < "${SCHEMA_FILE}"

echo "Seeding admin user..."
ADMIN_HASH="$(cd "${ROOT_DIR}" && go run ./scripts/hash_password.go "${ADMIN_PASSWORD}")"
ADMIN_USER_ESC="$(escape_sql_value "${ADMIN_USER}")"
ADMIN_HASH_ESC="$(escape_sql_value "${ADMIN_HASH}")"
mysql_exec "${APP_DB_NAME}" -e \
  "INSERT INTO users (username, password_hash) VALUES ('${ADMIN_USER_ESC}', '${ADMIN_HASH_ESC}') \
   ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash);"

echo "Seeding application settings..."
APP_LISTEN_ADDR_ESC="$(escape_sql_value "${APP_LISTEN_ADDR}")"
APP_BASE_URL_ESC="$(escape_sql_value "${APP_BASE_URL}")"
mysql_exec "${APP_DB_NAME}" -e \
  "INSERT INTO app_settings (setting_key, setting_value) VALUES
    ('app.listen_addr', '${APP_LISTEN_ADDR_ESC}'),
    ('app.base_url', '${APP_BASE_URL_ESC}')
   ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);"

if [[ "${USE_DNS}" == "y" || "${USE_DNS}" == "yes" ]]; then
  NS1_NO_DOT="${NS1%.}"
  NS2_NO_DOT="${NS2%.}"
  NS_HOSTS="${NS1},${NS2}"
  NS_HOSTS_ESC="$(escape_sql_value "${NS_HOSTS}")"
  NS1_ESC="$(escape_sql_value "${NS1}")"
  NS1_NO_DOT_ESC="$(escape_sql_value "${NS1_NO_DOT}")"
  mysql_exec "${APP_DB_NAME}" -e \
    "INSERT INTO app_settings (setting_key, setting_value) VALUES
      ('dns.enabled', '1'),
      ('dns.dnssec_enabled', '$( [[ "${USE_DNSSEC}" == "y" || "${USE_DNSSEC}" == "yes" ]] && echo 1 || echo 0 )'),
      ('dns.ns_hosts', '${NS_HOSTS_ESC}'),
      ('dns.primary_ns', '${NS1_NO_DOT_ESC}'),
      ('dns.soa_mname', '${NS1_ESC}')
     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);"
else
  mysql_exec "${APP_DB_NAME}" -e \
    "INSERT INTO app_settings (setting_key, setting_value) VALUES
      ('dns.enabled', '0'),
      ('dns.dnssec_enabled', '0')
     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);"
fi

echo "Downloading Go modules and building binary..."
cd "${ROOT_DIR}"
go mod download
mkdir -p bin
go build -o bin/goresolver ./cmd/server

ENV_FILE="${ROOT_DIR}/.env"
DB_DSN="${APP_DB_USER}:${APP_DB_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${APP_DB_NAME}"
cat > "${ENV_FILE}" <<EOF
DB_DSN=${DB_DSN}
EOF

echo
echo "Install complete."
echo "Database and tables were created."
echo "Credentials:"
echo "  Admin user: ${ADMIN_USER}"
echo "  DB user:    ${APP_DB_USER}"
echo
echo "Environment file written to ${ENV_FILE}"
echo "Run with:"
echo "  export DB_DSN='${DB_DSN}'"
echo "  ./bin/goresolver"
