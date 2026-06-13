# dwCloud

dwCloud is a lightweight alternative to the Nextcloud server, with support for Nextcloud and WebDAV clients.

This project is still in development. Do not rely on it for anything important yet: the database schema is not finalized, and there will be breaking changes before 1.0.

Automatic database backup is not provided. Back up the Postgres database and `STORAGE_DIR`. The initial idea was to use extended attributes as a metadata backup solution and only require backup of `STORAGE_DIR`, but that was abandoned because of the performance impact.

## Tailscale and Caddy

It's probably a bad idea to expose to the WAN, so secure it behind tailscale/netbird.

The easiest way to get this setup is with caddy and tailscale, setup caddy and reverse proxy cloud.example.com to `dwcloud:8080`, <br>
Then setup your dns to point cloud.example.com to your servers tailscale IP. You can setup the Idp however you want and just set the callback url to be https://cloud.example.com/auth/callback/{IDP_ID_N}

## Getting Started With Docker Compose

The provided `docker-compose.yaml` starts:

- `db`: Postgres
- `dwcloud`: dwCloud, built from the GitHub repository

The compose file builds dwCloud from:

```yaml
https://github.com/dulanw/dwCloud.git#${DWCLOUD_GIT_REF:-main}
```

If you change `Containerfile`, `.dockerignore`, or app code locally, commit and push those changes to the branch referenced by `DWCLOUD_GIT_REF` before relying on the remote GitHub build context.

Create a `.env` file next to `docker-compose.yaml`:

```env
PROTOCOL=http
DOMAIN=localhost:8080
LISTEN_ADDRESS:8080

POSTGRES_PASSWORD=change-this
POSTGRES_DB=postgres

SESSION_KEY=change-this-to-a-long-random-string
SESSION_DURATION=4h

IDP_CLIENT_ID_1=
IDP_SECRET_1=
IDP_ENDPOINT_1=https://auth.example.com
IDP_SCOPES_1=openid,email,profile,groups
IDP_ID_1=pocketid
IDP_NAME_1=Pocket ID
IDP_LOGO_FILE_1=pocketid.svg
```

Start the stack:

```bash
docker compose up -d --build
```

Open:

```text
http://localhost:8080
```

After the app starts, the first user who signs in becomes the admin user. Create and sign in with the intended admin account first.

For a real deployment, put dwCloud behind HTTPS reverse-proxy (caddy) and set:

```env
PROTOCOL=https
DOMAIN=cloud.example.com
```

OIDC callback URLs are generated as:

```text
{PROTOCOL}://{DOMAIN}/auth/callback/{IDP_ID_N}
```

For the default Pocket ID config, register this callback URL in Pocket ID:

```text
http://localhost:8080/auth/callback/pocketid
```

or, for production:

```text
https://cloud.example.com/auth/callback/pocketid
```

### Windows (WSL2)

Fix permission issue when you mount vhdx or windows directory to be used for uploads/storage.

```
chown -R 100:101 /mnt/host/wsl/vol1-vhdx/nextcloud/uploads /mnt/host/wsl/vol1-vhdx/nextcloud/storage
chmod -R u+rwX,g+rwX /mnt/host/wsl/vol1-vhdx/nextcloud/uploads /mnt/host/wsl/vol1-vhdx/nextcloud/storage
```

## Identity Provider Setup

dwCloud uses OpenID Connect for browser login. You need at least one OIDC identity provider configured.

Pocket ID is a good default for self-hosting because it is a simple OIDC provider built around passkeys:

- Pocket ID repo: https://github.com/pocket-id/pocket-id
- Pocket ID installation docs: https://pocket-id.org/docs/setup/installation/

After Pocket ID is running:

1. Sign in to Pocket ID.
2. Create an OIDC client for dwCloud.
3. Add the callback URL shown above.
4. Copy the client ID into `IDP_CLIENT_ID_1`.
5. Copy the client secret into `IDP_SECRET_1`.
6. Set `IDP_ENDPOINT_1` to your Pocket ID base URL, for example `https://auth.example.com`.

Other OIDC providers can also be used, such as Google, Keycloak, Authentik, Authelia, Zitadel, Auth0, or Azure Entra ID. GitHub's normal sign-in integration is OAuth2 rather than a drop-in OIDC issuer for this app, so use an OIDC broker/provider if you want GitHub-backed login.

## Environment Variables

You can configure multiple identity providers by repeating the indexed IDP variables:

```text
IDP_CLIENT_ID_1, IDP_SECRET_1, ...
IDP_CLIENT_ID_2, IDP_SECRET_2, ...
```

Stop at the first missing `IDP_CLIENT_ID_N`; later providers will not be read.

### App

| Variable | Required | Example | Description |
|---|---:|---|---|
| `PROTOCOL` | yes | `https` | Public protocol used to build absolute URLs and OIDC callback URLs. |
| `DOMAIN` | yes | `cloud.example.com` | Public host, optionally with port. Do not include `http://` or `https://`. |
| `LISTEN_ADDRESS` | yes | `:8080` | Address the Go server listens on inside the container. The compose file sets this to `:8080`. |
| `SESSION_KEY` | yes | long random string | Secret used to sign session cookies. Use a high-entropy value and keep it stable across restarts. |
| `SESSION_DURATION` | no | `4h` | Session lifetime. Defaults to `4h` if omitted. |
| `STORAGE_DIR` | yes | `/data/storage` | User file storage path. In Docker this is backed by `./storage`. |
| `UPLOAD_DIR` | yes | `/data/uploads` | Temporary upload/chunk path. Do not put this inside `STORAGE_DIR`. |

### Postgres

| Variable | Required | Example | Description |
|---|---:|---|---|
| `POSTGRES_ADDRESS` | yes | `db:5432` | Host and port for Postgres. The compose file sets this for the app. |
| `POSTGRES_USER` | yes | `postgres` | Database user. |
| `POSTGRES_PASSWORD` | yes | `change-this` | Database password. |
| `POSTGRES_DB` | yes | `postgres` | Database name. |

### Identity Providers

| Variable | Required | Example | Description |
|---|---:|---|---|
| `IDP_CLIENT_ID_N` | yes | `abc123` | OIDC client ID from the provider. |
| `IDP_SECRET_N` | yes | `secret` | OIDC client secret from the provider. |
| `IDP_ENDPOINT_N` | yes | `https://auth.example.com` | OIDC issuer/base URL. The app discovers provider metadata from this URL. |
| `IDP_SCOPES_N` | yes | `openid,email,profile,groups` | Comma-separated OIDC scopes. `openid` is added automatically if missing. |
| `IDP_ID_N` | yes | `pocketid` | Stable provider ID used in routes, including `/auth/callback/{IDP_ID_N}`. |
| `IDP_NAME_N` | yes | `Pocket ID` | Display name shown on the login button. |
| `IDP_LOGO_N` | yes | `/app/static/logo/pocketid.svg` | Filesystem path to an SVG logo. The compose file derives this from `IDP_LOGO_FILE_N`. |
| `IDP_LOGO_FILE_N` | compose-only | `pocketid.svg` | Convenience variable for selecting a file under `/app/static/logo/`. |

## Development Setup

### GoLand

For local development in GoLand, install the EnvFile plugin, add .env file in the project dir, under Run/Debug 
Configuration → EnvFile, add `Type=.env` `Path=.env`.

Set the Go tool arguments/build tags to:

```text
-tags=DEBUG
```

The `DEBUG` tag enables the debug-only WebDAV code in `handlers/webdav_debug.go`.

### Templ HTML Generation

With `templ` installed and available on your `PATH`, run:

```bash
templ generate --watch
```

Remove `--watch` to generate once.

### CSS File Generation

With the Tailwind standalone binary installed and available on your `PATH`, run:

```bash
tailwindcss -i ./static/css/input.css -o ./static/css/styles.css --watch
```

Remove `--watch` to build once.

## Litmus Test

Install litmus in WSL:

```bash
sudo apt update
sudo apt install litmus
```

Create an app password in the dwCloud web UI and use that password for litmus:

```bash
litmus http://localhost:8080/remote.php/dav/files/<username>/ <username> <app-password>
```

Example:

```bash
litmus http://192.168.50.115:8080/remote.php/dav/files/dwettasinghe1682/ dwettasinghe6799 <app-password-generated-in-ui>
```

## AI Usage

This project has used a combination of Claude Code and Codex AI to generate most of the HTMX templates, the file preview service was implemented completely by codex & claude code, and claude code was used to review the project.
