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

log() { printf '[%s] %s\n' "${APP_NAME}" "$*"; }
die() { printf '[%s] ERROR: %s\n' "${APP_NAME}" "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "Run this script as root: sudo bash deploy.sh"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

export DEBIAN_FRONTEND=noninteractive
log "Installing system packages"
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git golang-go build-essential openssl systemd

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
    printf 'WFM_ADDR=127.0.0.1:8080\n'
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
