# Cert Warden Client Changelog

## [v0.6.0] - 2026-09-05

This release replaces webhook pushes with polling: the client asks the
Cert Warden server for its key/cert on a schedule and no longer runs an
https server.

> [!CAUTION]
> Breaking changes:
> - Removed the client https server and the webhook route. Port 5055 is
>   unused; drop any port mapping and firewall rules.
> - On the Cert Warden server, clear the `Post Processing` -> `Client`
>   settings (client address and AES key) of each certificate, otherwise
>   the server logs an error on every renewal when it cannot reach the
>   client.
> - The client ignores `CW_CLIENT_BIND_ADDRESS`, `CW_CLIENT_BIND_PORT`
>   and `CW_CLIENT_<n>_AES_KEY_BASE64` and logs a warning if they are
>   set. It also ignores `CW_CLIENT_<n>_KEY_NAME`. Existing
>   configurations keep working.
> - `CW_CLIENT_<n>_CERT_NAME` now defines which certificate indexes
>   exist (previously `CW_CLIENT_<n>_AES_KEY_BASE64` did).
> - Requires Cert Warden server v0.18.2 or newer.

Added:
- Poll the server for key/cert updates. The first poll runs at startup
  and then every `CW_CLIENT_POLL_INTERVAL` (Go duration, default `6h`,
  minimum `1m`). After a failed poll the client retries after 15
  minutes, doubling on each consecutive failure up to the poll interval.
- Polls are conditional (`If-None-Match` / ETag): an unchanged key/cert
  costs one request with no body.
- Each poll is one request to
  `/certwarden/api/v1/download/privatecertchains/<CERT_NAME>` (with
  `apiKey: <CERT_APIKEY>.<KEY_APIKEY>`). It returns the key and the
  certificate chain of the same order, so they match. The server logs
  each request (2 Info lines); a short poll interval fills its log.

Changed:
- The client no longer exits when it cannot fetch certificate 0 or an
  api key is wrong; it logs an error and keeps retrying. If you switch a
  certificate to another private key on the server, update
  `CW_CLIENT_<n>_KEY_APIKEY` and restart the client.
- The client validates a key/cert pair before storing it in memory, so
  an invalid pair never reaches the disk.
- The docker image builds from this repository and goes to
  `ghcr.io/mishkatik/certwarden-client` only.

Removed:
- https server, webhook route and AES payload decryption.


## [v0.5.0] - 2025-04-30

Add multiple certificate support. Review the config file for updated
environment config names:
https://github.com/mishkatik/certwarden-client/blob/main/pkg/main/config.go
Backwards compatibility was maintained for existing installs.

The ability to specify the name of key.pem and certchain.pem was added.

Go and all dependencies updated.


## [v0.4.0] - 2025-01-22

Update Go & Alpine to the latest version, updated the Docker client pkg, 
and allow specifying environment vars related to the Docker client 
connection (e.g., `DOCKER_HOST`).

Also, remove backwards compatibility with LeGo CertHub and changes from
using a custom http Client to a custom http Transport.


## [v0.3.1] - 2024-06-26

Fix incorrect parsing of cert and key file permission environment
variables. Also set default key permissions to `0600`.


## [v0.3.0] - 2024-04-15

Name changed to Cert Warden.

> [!CAUTION]
> The environment variable names were changed. Since the client is still
> in a relatively alpha stage, I did not implement any backward compat
> and you will need to update your environment variable names.

The client route that the client listens for was changed, but backward 
compat actions were taken on this front (the new server version will send 
to both routes and the new client will listen for both). This will be
dropped eventually but for now keeps the breaking change contained to the
environment variable names.

In addition to the name change and compatibility issue, this release
updates some dependencies.


## [v0.2.1] - 2024-03-06

Update to Go 1.22.1, which includes some security fixes.


## [v0.2.0] - 2024-02-12

First 'real' release. Some bug fixes and dependency updates from the
last version.


## [v0.1.7] - 2024-01-11

- Add a log message for no write and up to date.


## [v0.1.6] - 2024-01-10

- Clarify log message about file write.


## [v0.1.5] - 2024-01-10

- Fix incorrect scheduling of file write job when not needed.


## [v0.1.4] - 2024-01-10

- Add timezone support.
- Change writing files options from specific time to a time window.
- Support multiple weekday selection for write windows.
- Add option to stop docker containers instead of restart.


## [v0.1.3] - 2024-01-06

Add file write update schedule. Files will only be written at 
the specified time and subsequently containers will only restart 
when files are written.

If any files are missing, the client disregards scheduling and 
updates right away (on the assumption the dependent applications 
are, or will, fail without the missing files).


## [v0.1.2] - 2024-01-06

Add docker API version negotiation.


## [v0.1.1] - 2024-01-06

Change default cert storage path.


## [v0.1.0] - 2024-01-06

Initial release.
