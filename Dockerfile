# example build:
# docker build . -t certwarden-client:v0.6.0

# example run
# NOTE: If you don't want or need auto container restart, you can skip mounting docker.sock
# NOTE: no port to publish: the client polls the Cert Warden server and runs no server itself
# docker run -d --name certwarden-client -e TZ=Europe/Stockholm -v /var/run/docker.sock:/var/run/docker.sock -e [config vars here] ghcr.io/mishkatik/certwarden-client:latest

# Versions - keep Dockerfile and DockerfileLocal in sync
ARG ALPINE_VERSION=3.21
ARG GO_VERSION=1.24.2
# https://hub.docker.com/_/alpine
# https://hub.docker.com/_/golang

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

# informational only; the image builds from this repository's source tree
ARG VERSION

WORKDIR /

COPY ./ ./src

RUN cd /src && \
    go build -o ./certwarden-client ./pkg/main

FROM alpine:${ALPINE_VERSION}

WORKDIR /app

# timezone support
RUN apk add --no-cache tzdata

# copy app
COPY --from=build /src/certwarden-client .
COPY ./README.md .
COPY ./CHANGELOG.md .
COPY ./LICENSE.md .

CMD ["/app/certwarden-client"]
