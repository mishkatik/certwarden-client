# Cert Warden Client
Centralized Certificate Management
Conveniently Leverage Let&apos;s Encrypt to Secure Your Infrastructure

## More Information
https://www.certwarden.com/

## Client
Cert Warden Client fetches certificates from Cert Warden and polls the
server for updates, every 6 hours by default (`CW_CLIENT_POLL_INTERVAL`).
Polls are conditional requests (ETag): the server sends the key and
certificate only when they changed. The client runs no server and
publishes no ports.

The client can also restart docker containers after it writes new
certificate files.

You need Cert Warden server v0.18.2 or newer.

## About this fork
This fork of https://github.com/gregtwallace/certwarden-client replaces
the webhook push with polling. Images live at
`ghcr.io/mishkatik/certwarden-client` and
`docker.io/mishkatik/certwarden-client`.

Configure the client with environment variables.
[pkg/main/config.go](pkg/main/config.go) lists them all,
[docker-compose.example.yml](docker-compose.example.yml) is a compose
file to adapt, and [CHANGELOG.md](CHANGELOG.md) lists the differences
from upstream.
