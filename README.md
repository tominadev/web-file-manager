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

Configuration:

```bash
WFM_ADDR=:8080 WFM_DATA_DIR=./data go run .
```

This MVP uses JSON metadata, in-memory sessions, and reads an upload into memory with a 100 MB limit. Production hardening should add a database, persistent sessions, HTTPS, CSRF protection, and chunked encryption for large files.
