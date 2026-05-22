# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS build

RUN apk add --no-cache ca-certificates git

WORKDIR /src
COPY . .

RUN go mod download
RUN go run github.com/a-h/templ/cmd/templ@v0.3.977 generate
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/dwcloud .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
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
