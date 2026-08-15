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

    # Packages needed for external repositories
    ${SUDO} apt-get install -y \
        ca-certificates curl gnupg git

    # Fluent Bit repository
    if [[ ! -f /usr/share/keyrings/fluentbit-keyring.gpg ]]; then
        curl -fsSL https://packages.fluentbit.io/fluentbit.key \
            | gpg --dearmor \
            | ${SUDO} tee /usr/share/keyrings/fluentbit-keyring.gpg >/dev/null
    fi

    . /etc/os-release
    CODENAME="${VERSION_CODENAME:-bookworm}"

    echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/debian/${CODENAME} ${CODENAME} main" \
        | ${SUDO} tee /etc/apt/sources.list.d/fluent-bit.list >/dev/null

    ${SUDO} apt-get update

    ${SUDO} apt-get install -y \
        golang-go \
        fluent-bit \
        default-mysql-server default-mysql-client \
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

detect_easyrsa_source_dir() {
  if [[ -x "/usr/share/easy-rsa/easyrsa" ]]; then
    echo "/usr/share/easy-rsa"
    return
  fi
  if [[ -x "/usr/share/easy-rsa/3/easyrsa" ]]; then
    echo "/usr/share/easy-rsa/3"
    return
  fi
  if command -v easyrsa >/dev/null 2>&1; then
    dirname "$(command -v easyrsa)"
    return
  fi
  echo ""
}

detect_openvpn_group() {
  if getent group nogroup >/dev/null 2>&1; then
    echo "nogroup"
  else
    echo "nobody"
  fi
}

ensure_openvpn_pki() {
  local ca_dir="$1"
  local pki_dir="$2"
  local ccd_dir="$3"
  local server_cn="$4"
  local source_dir
  local local_easyrsa

  echo "Preparing OpenVPN PKI directories..."
  ${SUDO} mkdir -p "${ca_dir}" "${pki_dir}" "${ccd_dir}"

  local_easyrsa="${ca_dir}/easyrsa"
  if [[ ! -x "${local_easyrsa}" ]]; then
    source_dir="$(detect_easyrsa_source_dir)"
    if [[ -z "${source_dir}" ]]; then
      echo "Could not locate easy-rsa files on disk." >&2
      exit 1
    fi
    echo "Copying easy-rsa files into ${ca_dir}..."
    ${SUDO} cp -a "${source_dir}/." "${ca_dir}/"
    ${SUDO} chmod +x "${local_easyrsa}"
  fi

  if [[ ! -f "${pki_dir}/ca.crt" ]]; then
    echo "Initializing easy-rsa PKI..."
    ${SUDO} bash -c "cd '${ca_dir}' && EASYRSA_BATCH=1 EASYRSA_PKI='${pki_dir}' '${local_easyrsa}' init-pki"
    ${SUDO} bash -c "cd '${ca_dir}' && EASYRSA_BATCH=1 EASYRSA_PKI='${pki_dir}' '${local_easyrsa}' build-ca nopass"
  fi

  if [[ ! -f "${pki_dir}/issued/${server_cn}.crt" || ! -f "${pki_dir}/private/${server_cn}.key" ]]; then
    echo "Generating OpenVPN server certificate and key..."
    ${SUDO} bash -c "cd '${ca_dir}' && EASYRSA_BATCH=1 EASYRSA_PKI='${pki_dir}' '${local_easyrsa}' build-server-full '${server_cn}' nopass"
  fi

  if [[ ! -f "${pki_dir}/dh.pem" ]]; then
    echo "Generating Diffie-Hellman parameters (this may take a while)..."
    ${SUDO} bash -c "cd '${ca_dir}' && EASYRSA_BATCH=1 EASYRSA_PKI='${pki_dir}' '${local_easyrsa}' gen-dh"
  fi

  if [[ ! -f "${ca_dir}/ta.key" ]]; then
    echo "Generating tls-auth key..."
    if ! ${SUDO} openvpn --genkey secret "${ca_dir}/ta.key" >/dev/null 2>&1; then
      ${SUDO} openvpn --genkey --secret "${ca_dir}/ta.key"
    fi
  fi
}

write_openvpn_server_config() {
  local ca_dir="$1"
  local pki_dir="$2"
  local ccd_dir="$3"
  local server_cn="$4"
  local proto="$5"
  local port="$6"
  local subnet="$7"
  local netmask="$8"
  local conf_path="$9"
  local conf_dir
  local ovpn_group

  conf_dir="$(dirname "${conf_path}")"
  ovpn_group="$(detect_openvpn_group)"

  ${SUDO} mkdir -p "${conf_dir}" "${ccd_dir}" /var/log/openvpn

  if [[ ! -f "${conf_path}" ]]; then
    echo "Writing OpenVPN server config to ${conf_path}..."
    ${SUDO} tee "${conf_path}" >/dev/null <<CONFEOF
port ${port}
proto ${proto}
dev tun
user nobody
group ${ovpn_group}
persist-key
persist-tun
topology subnet
server ${subnet} ${netmask}
ifconfig-pool-persist /var/log/openvpn/ipp.txt
client-config-dir ${ccd_dir}
keepalive 10 120
tls-server
ca ${pki_dir}/ca.crt
cert ${pki_dir}/issued/${server_cn}.crt
key ${pki_dir}/private/${server_cn}.key
dh ${pki_dir}/dh.pem
tls-auth ${ca_dir}/ta.key 0
cipher AES-256-CBC
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
auth SHA256
verb 3
explicit-exit-notify 1
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
CONFEOF
  else
    echo "OpenVPN config already exists at ${conf_path}; leaving it unchanged."
  fi
}

enable_openvpn_service() {
  local conf_path="$1"
  local conf_name
  local unit=""

  conf_name="$(basename "${conf_path}")"
  conf_name="${conf_name%.conf}"

  if systemctl list-unit-files | grep -q '^openvpn-server@\.service'; then
    unit="openvpn-server@${conf_name}"
  elif systemctl list-unit-files | grep -q '^openvpn@\.service'; then
    unit="openvpn@${conf_name}"
  fi

  if [[ -n "${unit}" ]]; then
    echo "Enabling OpenVPN service (${unit})..."
    ${SUDO} systemctl enable --now "${unit}" >/dev/null 2>&1 || true
  else
    echo "OpenVPN systemd unit template not detected; skipping auto-enable."
  fi
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
OPENVPN_REMOTE_HOST=""
OPENVPN_REMOTE_PORT=""
OPENVPN_PROTO=""
OPENVPN_SUBNET=""
OPENVPN_NETMASK=""
OPENVPN_SERVER_CN="server"
OPENVPN_CA_DIR="/root/openvpn-ca"
OPENVPN_PKI_DIR="/root/openvpn-ca/pki"
OPENVPN_CCD_DIR="/etc/openvpn/ccd"
OPENVPN_SERVER_CONF=""
OPENVPN_EASYRSA_PATH=""

echo "Installing system dependencies..."
install_dependencies

echo "Ensuring services are enabled..."
${SUDO} systemctl enable --now mariadb 2>/dev/null \
    || ${SUDO} systemctl enable --now mysql 2>/dev/null \
    || ${SUDO} systemctl enable --now mysqld 2>/dev/null \
    || true
${SUDO} systemctl enable --now nginx 2>/dev/null || true

echo "Installing Fluent Bit configuration..."
FLUENT_BIT_SRC="${ROOT_DIR}/scripts/fluent-bit.conf"
FLUENT_BIT_DST="/etc/fluent-bit/fluent-bit.conf"
if [[ -f "${FLUENT_BIT_SRC}" ]]; then
  ${SUDO} mkdir -p "$(dirname "${FLUENT_BIT_DST}")"
  ${SUDO} cp "${FLUENT_BIT_SRC}" "${FLUENT_BIT_DST}"
  ${SUDO} chmod 644 "${FLUENT_BIT_DST}"
else
  echo "Warning: Fluent Bit config not found at ${FLUENT_BIT_SRC}; skipping copy."
fi

echo "Ensuring Fluent Bit service is enabled..."
${SUDO} systemctl enable --now fluent-bit 2>/dev/null || ${SUDO} systemctl enable --now td-agent-bit 2>/dev/null || true

if [[ -d "/etc/openvpn/server" ]]; then
  OPENVPN_SERVER_CONF="/etc/openvpn/server/server.conf"
else
  OPENVPN_SERVER_CONF="/etc/openvpn/server.conf"
fi

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

APP_BASE_HOST="$(printf "%s" "${APP_BASE_URL}" | sed -E 's|^[a-zA-Z]+://||; s|/.*$||; s|:.*$||')"
if [[ -z "${APP_BASE_HOST}" ]]; then
  APP_BASE_HOST="127.0.0.1"
fi

prompt OPENVPN_REMOTE_HOST "OpenVPN public host/IP for clients" "${APP_BASE_HOST}"
prompt OPENVPN_REMOTE_PORT "OpenVPN UDP port" "1194"
prompt OPENVPN_PROTO "OpenVPN protocol (udp/tcp)" "udp"
prompt OPENVPN_SUBNET "OpenVPN subnet" "10.8.0.0"
prompt OPENVPN_NETMASK "OpenVPN netmask" "255.255.255.0"
OPENVPN_PROTO="${OPENVPN_PROTO,,}"
if [[ "${OPENVPN_PROTO}" != "udp" && "${OPENVPN_PROTO}" != "tcp" ]]; then
  OPENVPN_PROTO="udp"
fi

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

echo "Bootstrapping OpenVPN server keys/certs..."
ensure_openvpn_pki \
  "${OPENVPN_CA_DIR}" \
  "${OPENVPN_PKI_DIR}" \
  "${OPENVPN_CCD_DIR}" \
  "${OPENVPN_SERVER_CN}"
write_openvpn_server_config \
  "${OPENVPN_CA_DIR}" \
  "${OPENVPN_PKI_DIR}" \
  "${OPENVPN_CCD_DIR}" \
  "${OPENVPN_SERVER_CN}" \
  "${OPENVPN_PROTO}" \
  "${OPENVPN_REMOTE_PORT}" \
  "${OPENVPN_SUBNET}" \
  "${OPENVPN_NETMASK}" \
  "${OPENVPN_SERVER_CONF}"
enable_openvpn_service "${OPENVPN_SERVER_CONF}"
OPENVPN_EASYRSA_PATH="${OPENVPN_CA_DIR}/easyrsa"

if [[ -z "${MYSQL_ROOT_PASSWORD}" ]] \
    && [[ "${MYSQL_HOST}" == "127.0.0.1" || "${MYSQL_HOST}" == "localhost" ]]; then

    # Debian/MariaDB default: root authenticates through Unix socket.
    MYSQL_USE_SOCKET_AUTH=1
else
    MYSQL_USE_SOCKET_AUTH=0

    MYSQL_ARGS=(
        -h "${MYSQL_HOST}"
        -P "${MYSQL_PORT}"
        -u "${MYSQL_ROOT_USER}"
    )

    if [[ -n "${MYSQL_ROOT_PASSWORD}" ]]; then
        MYSQL_ARGS+=("-p${MYSQL_ROOT_PASSWORD}")
    fi
fi

mysql_exec() {
    if [[ "${MYSQL_USE_SOCKET_AUTH}" == "1" ]]; then
        ${SUDO} mysql "$@"
    else
        mysql "${MYSQL_ARGS[@]}" "$@"
    fi
}
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
OPENVPN_REMOTE_HOST_ESC="$(escape_sql_value "${OPENVPN_REMOTE_HOST}")"
OPENVPN_REMOTE_PORT_ESC="$(escape_sql_value "${OPENVPN_REMOTE_PORT}")"
OPENVPN_CA_DIR_ESC="$(escape_sql_value "${OPENVPN_CA_DIR}")"
OPENVPN_PKI_DIR_ESC="$(escape_sql_value "${OPENVPN_PKI_DIR}")"
OPENVPN_CCD_DIR_ESC="$(escape_sql_value "${OPENVPN_CCD_DIR}")"
OPENVPN_EASYRSA_PATH_ESC="$(escape_sql_value "${OPENVPN_EASYRSA_PATH}")"
mysql_exec "${APP_DB_NAME}" -e \
  "INSERT INTO app_settings (setting_key, setting_value) VALUES
    ('app.listen_addr', '${APP_LISTEN_ADDR_ESC}'),
    ('app.base_url', '${APP_BASE_URL_ESC}'),
    ('openvpn.remote_host', '${OPENVPN_REMOTE_HOST_ESC}'),
    ('openvpn.remote_port', '${OPENVPN_REMOTE_PORT_ESC}'),
    ('openvpn.ca_dir', '${OPENVPN_CA_DIR_ESC}'),
    ('openvpn.pki_dir', '${OPENVPN_PKI_DIR_ESC}'),
    ('openvpn.ccd_dir', '${OPENVPN_CCD_DIR_ESC}'),
    ('openvpn.easy_rsa_path', '${OPENVPN_EASYRSA_PATH_ESC}')
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
cat > "${ENV_FILE}" <<ENVEOF
DB_DSN=${DB_DSN}
ENVEOF

echo
echo "Install complete."
echo "Database and tables were created."
echo "OpenVPN assets are ready:"
echo "  PKI dir:       ${OPENVPN_PKI_DIR}"
echo "  Server config: ${OPENVPN_SERVER_CONF}"
echo "  CCD dir:       ${OPENVPN_CCD_DIR}"
echo "Credentials:"
echo "  Admin user: ${ADMIN_USER}"
echo "  DB user:    ${APP_DB_USER}"
echo
echo "Environment file written to ${ENV_FILE}"
echo "Run with:"
echo "  export DB_DSN='${DB_DSN}'"
echo "  ./bin/goresolver"
