#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="web-file-manager"
REPO_URL="${REPO_URL:-https://github.com/tominadev/web-file-manager.git}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/${APP_NAME}}"
SOURCE_DIR="${SOURCE_DIR:-/opt/${APP_NAME}-src}"
DATA_DIR="${DATA_DIR:-/var/lib/${APP_NAME}/data}"
ENV_DIR="${ENV_DIR:-/etc/${APP_NAME}}"
SERVICE_USER="${SERVICE_USER:-wfm}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
GO_VERSION="${GO_VERSION:-1.27.1}"
GO_ARCH="$(dpkg --print-architecture)"

log() { printf '[%s] %s\n' "${APP_NAME}" "$*"; }
die() { printf '[%s] ERROR: %s\n' "${APP_NAME}" "$*" >&2; exit 1; }

if [[ "${1:-}" == "configure" || "${1:-}" == "config" ]]; then
  [[ "${EUID}" -eq 0 ]] || die "Run this command as root"
  shift
  listen_addr=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --addr)
        [[ $# -ge 2 ]] || die "--addr requires a value, for example :8080"
        listen_addr="$2"
        shift 2
        ;;
      *) die "Unknown configure option: $1" ;;
    esac
  done
  [[ -n "${listen_addr}" ]] || die "Usage: deploy.sh configure --addr :8080"
  [[ "${listen_addr}" != *$'\n'* && "${listen_addr}" != *$'\r'* && "${listen_addr}" != *' '* ]] || die "Invalid listen address"
  ENV_FILE="${ENV_DIR}/${APP_NAME}.env"
  [[ -f "${ENV_FILE}" ]] || die "Configuration file not found: ${ENV_FILE}"
  tmp_env="$(mktemp)"
  awk -v address="${listen_addr}" '
    BEGIN { updated = 0 }
    /^WFM_ADDR=/ { print "WFM_ADDR=" address; updated = 1; next }
    { print }
    END { if (!updated) print "WFM_ADDR=" address }
  ' "${ENV_FILE}" > "${tmp_env}"
  chmod 0600 "${tmp_env}"
  chown root:root "${tmp_env}"
  mv "${tmp_env}" "${ENV_FILE}"
  install -d -m 0755 "/etc/systemd/system/${APP_NAME}.service.d"
  cat > "/etc/systemd/system/${APP_NAME}.service.d/privileged-port.conf" <<'EOF'
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOF
  chmod 0644 "/etc/systemd/system/${APP_NAME}.service.d/privileged-port.conf"
  systemctl daemon-reload
  systemctl restart "${APP_NAME}.service"
  if ! systemctl is-active --quiet "${APP_NAME}.service"; then
    systemctl --no-pager --full status "${APP_NAME}.service" || true
    journalctl -u "${APP_NAME}.service" -n 50 --no-pager || true
    exit 1
  fi
  log "Listening address updated to ${listen_addr}"
  systemctl --no-pager --full status "${APP_NAME}.service"
  exit 0
fi

[[ "${EUID}" -eq 0 ]] || die "Run this script as root: sudo bash deploy.sh"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

export DEBIAN_FRONTEND=noninteractive
log "Installing system packages"
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git build-essential openssl systemd

case "${GO_ARCH}" in
  amd64) GO_TARBALL_ARCH="amd64"; GO_SHA256="63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445" ;;
  arm64) GO_TARBALL_ARCH="arm64"; GO_SHA256="3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec" ;;
  *) die "Unsupported Debian architecture: ${GO_ARCH}" ;;
esac

if [[ ! -x /usr/local/go/bin/go ]] || [[ "$(/usr/local/go/bin/go version 2>/dev/null || true)" != "go version go${GO_VERSION} linux/${GO_TARBALL_ARCH}" ]]; then
  log "Installing official Go ${GO_VERSION} for ${GO_TARBALL_ARCH}"
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' EXIT
  go_archive="go${GO_VERSION}.linux-${GO_TARBALL_ARCH}.tar.gz"
  curl -fsSL --retry 3 -o "${tmp_dir}/${go_archive}" "https://go.dev/dl/${go_archive}"
  printf '%s  %s\n' "${GO_SHA256}" "${tmp_dir}/${go_archive}" | sha256sum -c -
  if [[ -e /usr/local/go ]]; then
    mv /usr/local/go "/usr/local/go.previous.$(date +%Y%m%d%H%M%S)"
  fi
  tar -C /usr/local -xzf "${tmp_dir}/${go_archive}"
fi
export PATH="/usr/local/go/bin:${PATH}"
export GOTOOLCHAIN=local
go version

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  log "Creating service user ${SERVICE_USER}"
  useradd --system --home-dir "/var/lib/${APP_NAME}" --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

log "Downloading source from ${REPO_URL}"
if [[ -d "${SOURCE_DIR}/.git" ]]; then
  git -C "${SOURCE_DIR}" fetch origin "${BRANCH}"
  git -C "${SOURCE_DIR}" checkout "${BRANCH}"
  git -C "${SOURCE_DIR}" pull --ff-only origin "${BRANCH}"
else
  install -d -m 0755 "$(dirname "${SOURCE_DIR}")"
  git clone --branch "${BRANCH}" --depth 1 "${REPO_URL}" "${SOURCE_DIR}"
fi

log "Building ${APP_NAME}"
install -d -m 0755 "${INSTALL_DIR}"
pushd "${SOURCE_DIR}" >/dev/null
go mod download
go build -trimpath -ldflags='-s -w' -o "${INSTALL_DIR}/${APP_NAME}" .
popd >/dev/null
chown root:root "${INSTALL_DIR}/${APP_NAME}"
chmod 0755 "${INSTALL_DIR}/${APP_NAME}"

log "Preparing encrypted data storage"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0700 "${DATA_DIR}"
install -d -o root -g root -m 0750 "${ENV_DIR}"
ENV_FILE="${ENV_DIR}/${APP_NAME}.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  umask 077
  master_key="$(openssl rand -base64 32)"
  {
    printf 'WFM_ADDR=:8080\n'
    printf 'WFM_DATA_DIR=%s\n' "${DATA_DIR}"
    printf 'WFM_MASTER_KEY=%s\n' "${master_key}"
  } > "${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
  log "Generated a new persistent master key in ${ENV_FILE}"
else
  log "Keeping the existing master key in ${ENV_FILE}"
fi

log "Installing systemd service"
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Web File Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=/var/lib/${APP_NAME}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/${APP_NAME}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "${SERVICE_FILE}"

systemctl daemon-reload
systemctl enable "${APP_NAME}.service"
systemctl restart "${APP_NAME}.service"

if ! systemctl is-active --quiet "${APP_NAME}.service"; then
  systemctl --no-pager --full status "${APP_NAME}.service" || true
  die "Service failed to start. Check: journalctl -u ${APP_NAME} -n 100 --no-pager"
fi

log "Deployment complete"
log "Open http://127.0.0.1:8080"
log "Service status: systemctl status ${APP_NAME}"
log "Logs: journalctl -u ${APP_NAME} -f"
