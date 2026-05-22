# templ-quickstart

## Introduction

Do not rely on this for anything important yet, it is still in development. The DB schema isn't finalized yet,
and there will be breaking changes. 1.0 will be released when the DB schema is finalized, and migrations will be
provided from then on for any future updates.

Automatic database backup will not be provided, but you can use the provided docker-compose.yml to run a postgres
container and back up the postgres database and the `STORAGE_DIR`. The initial idea was to use xattr to store database
metadata as a backup solution and to only require backup of the `STORAGE_DIR`, but this was abandoned in favor of a 
more traditional backup solution due to the performance impact.

Lightweight alternative to the nextcloud server, compatible with nextcloud and webdav clients.
This is a work in progress, but the most basic functionality is working.

## AI Usage
This project has used a combination of Claude Code and Codex AI to generate most of the HTMX templates.

### Environment Variables

You can have multiple identity providers, you must have env variables for each IDP with IDP_VAR_1 ... IDP_VAR_N. <br>

Make sure that you do not place the UPLOAD_DIR and STORAGE_DIR in the same directory, or UPLOAD_DIR inside STORAGE_DIR.

```env
PROTOCOL=http
DOMAIN=localhost:8080
LISTEN_ADDRESS=:8080

IDP_CLIENT_ID_1=
IDP_SECRET_1=
IDP_ENDPOINT_1=
IDP_SCOPES_1="openid,email,profile,groups"
IDP_ID_1=pocketid
IDP_NAME_1=Pocket ID
IDP_LOGO_1=./logo/pocketid.svg

SESSION_KEY=random-string-here
SESSION_DURATION=4h
STORAGE_DIR=./storage
UPLOAD_DIR=./uploads

POSTGRES_ADDRESS=localhost:50159
POSTGRES_USER=postgres
POSTGRES_PASSWORD=random-string-here
POSTGRES_DB=postgres
```

## Development Setup

### Templ HTML Generation

With templ installed and the binary somewhere on your PATH, run the following to generate your HTML components and templates (remove --watch to simply build and not hot reload)

```bash
templ generate --watch
```

### CSS File Generation

With the [Tailwind Binary](https://tailwindcss.com/blog/standalone-cli) installed and moved somewhere on your PATH, run the following to generate your CSS output for your tailwind classes (remove --watch to simply build and not hot reload)

```bash
tailwindcss -i ./static/css/input.css -o ./static/css/styles.css --watch
```

### Litmus Test

Install litmus in wsl `sudo apt update && sudo apt install litmus` and run the command
`litmus <server>/remote.php/dav/files/dwettasinghe1682/ <username> <password>`

make sure to create an app password in the webui and use that password.

```bash
litmus http://192.168.50.115:8080/remote.php/dav/files/dwettasinghe1682/ dwettasinghe6799 98588918749879fb1aedbbc99b60da6a5815d7496a2e63cc427cc301535a1b183b59eb8f
```
