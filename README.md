# Web File Manager

Module: `github.com/tominadev/web-file-manager`

This is an MVP with English UI. It supports user registration, login, password changes, upload, download, and deletion.

The first registered user is automatically given the administrator role. After signing in, users can see their role in the navigation bar. Administrators see an `Admin` button that opens `/admin`; this area is limited to user management and role visibility. The administrator can return to the personal file area through `My files`.

Each user gets an RSA-3072 key pair. Every uploaded file gets a random AES-256-GCM data key; that key is wrapped with the user's RSA public key. The user's private key is encrypted at rest with a server master key.

For development, the server creates `data/.master.key` when `WFM_MASTER_KEY` is not set. In production, provide a stable 32-byte base64 key through a secret manager:

```bash
export WFM_MASTER_KEY="$(openssl rand -base64 32)"
```

Run it with:

```bash
go mod tidy
go run .
```

Open <http://127.0.0.1:8080>.

## One-click Debian deployment

On a fresh Debian server with systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/tominadev/web-file-manager/main/deploy.sh | sudo bash
```

The script installs Git, Go, build tools, and systemd service configuration. It builds the application from the `main` branch, creates the `wfm` service account, generates a persistent master key under `/etc/web-file-manager/`, and starts `web-file-manager.service`.

Useful commands:

```bash
systemctl status web-file-manager
journalctl -u web-file-manager -f
systemctl restart web-file-manager
```

The default listener is `:8080`, so it accepts connections on all network interfaces. Put it behind an HTTPS reverse proxy and firewall before exposing it publicly.

Configuration:

```bash
WFM_ADDR=:8080 WFM_DATA_DIR=./data go run .
```

This MVP uses JSON metadata, in-memory sessions, and reads an upload into memory with a 100 MB limit. Production hardening should add a database, persistent sessions, HTTPS, CSRF protection, and chunked encryption for large files.
