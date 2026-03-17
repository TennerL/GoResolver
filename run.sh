#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf "%s" "${value}"
}

strip_wrapping_quotes() {
  local value="$1"
  if [[ ${#value} -ge 2 ]]; then
    if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
      value="${value:1:${#value}-2}"
    fi
  fi
  printf "%s" "${value}"
}

load_env_file() {
  [[ -f "${ENV_FILE}" ]] || return 0

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line}" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue
    [[ "${line}" == *=* ]] || continue

    local key="${line%%=*}"
    local value="${line#*=}"

    key="$(trim "${key}")"
    key="${key#export }"
    key="$(trim "${key}")"
    value="$(trim "${value}")"
    value="$(strip_wrapping_quotes "${value}")"

    [[ -n "${key}" ]] || continue
    export "${key}=${value}"
  done < "${ENV_FILE}"
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
    return
  fi

  od -An -N 32 -tx1 /dev/urandom | tr -d ' \n'
}

append_env_var() {
  local key="$1"
  local value="$2"

  touch "${ENV_FILE}"
  if ! grep -Eq "^${key}=" "${ENV_FILE}"; then
    printf "%s=%s\n" "${key}" "${value}" >> "${ENV_FILE}"
  fi
  export "${key}=${value}"
}

ensure_env_var() {
  local key="$1"
  local value="$2"

  if [[ -z "${!key:-}" ]]; then
    append_env_var "${key}" "${value}"
  fi
}

ensure_env_comments() {
  touch "${ENV_FILE}"
  if ! grep -Eq "^# Optional rotation secrets$" "${ENV_FILE}"; then
    cat >> "${ENV_FILE}" <<'EOF'
# Optional rotation secrets
# GORESOLVER_SESSION_SECRET_PREVIOUS=
# GORESOLVER_VPN_ENCRYPTION_SECRET_PREVIOUS=
EOF
  fi
}

load_env_file

DEFAULT_DB_DSN="goresolver:goresolver@tcp(127.0.0.1:3306)/goresolver"
ensure_env_var "DB_DSN" "${DEFAULT_DB_DSN}"
ensure_env_var "GORESOLVER_SESSION_SECRET" "$(random_secret)"
ensure_env_var "GORESOLVER_VPN_ENCRYPTION_SECRET" "$(random_secret)"
ensure_env_var "GORESOLVER_SESSION_SECURE" "0"
ensure_env_comments

cd "${ROOT_DIR}"

if [[ $# -gt 0 ]]; then
  exec "$@"
fi

exec go run ./cmd/server
