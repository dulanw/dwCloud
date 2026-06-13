# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25
ARG TAILWIND_VERSION=v4.3.1

FROM golang:${GO_VERSION}-alpine AS build

ARG TAILWIND_VERSION

RUN apk add --no-cache ca-certificates git

WORKDIR /src
COPY . .

# Build the Tailwind stylesheet. styles.css is generated (git-ignored), so it must
# be produced here or the embedded static assets ship without any CSS.
RUN wget -qO /usr/local/bin/tailwindcss \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64-musl" \
    && chmod +x /usr/local/bin/tailwindcss \
    && tailwindcss -i ./static/css/input.css -o ./static/css/styles.css --minify

RUN go mod download
RUN go run github.com/a-h/templ/cmd/templ@v0.3.977 generate
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/dwcloud .

FROM alpine:3.22

# vips-tools (vipsthumbnail) and ffmpeg power image/video preview generation.
# Without them the preview service starts but silently produces no thumbnails.
RUN apk add --no-cache ca-certificates tzdata vips-tools ffmpeg \
	&& addgroup -S dwcloud \
	&& adduser -S -G dwcloud dwcloud \
	&& mkdir -p /app /data/storage /data/uploads \
	&& chown -R dwcloud:dwcloud /app /data

WORKDIR /app
COPY --from=build /out/dwcloud /app/dwcloud
COPY --from=build /src/static /app/static

USER dwcloud
EXPOSE 8080

ENTRYPOINT ["/app/dwcloud"]
