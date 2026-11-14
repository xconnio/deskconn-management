# Configuration and deployment

DeskConn Management requires PostgreSQL and a running
[DeskConn Hub](https://github.com/xconnio/deskconn-hub). It joins the shared
`io.xconn.deskconn` realm as a service using CryptoSign.

The Docker image, Compose service, database, and several environment variables
retain the historical `deskconn-account-service` name. These identifiers have
not been renamed with the repository.

## Environment

Run `make setup` once, then edit its generated `.env`. Re-running `make setup`
overwrites `.env` with `example.env`; to refresh dependencies without replacing
configuration, use:

```sh
uv pip install -e '.[test]'
```

| Variable | Purpose |
| --- | --- |
| `DESKCONN_DATABASE_URL` | SQLAlchemy connection URL using `postgresql+asyncpg` |
| `DESKCONN_POSTGRES_HOST` | PostgreSQL host used by the example connection URL |
| `ACCOUNT_SERVICE_DB_USER`, `ACCOUNT_SERVICE_DB_PASSWORD` | Management database credentials; also used by database initialization |
| `ROUTER_DB_USER`, `ROUTER_DB_PASSWORD` | Hub database credentials created by database initialization |
| `ROUTER_URL` | Hub WAMP endpoint; for local RawSocket, use `rs://127.0.0.1:8084/rs` |
| `DESKCONN_ACCOUNT_AUTHID` | Service identity; the supplied deployment uses `deskconn-account-service` |
| `DESKCONN_ACCOUNT_PRIVATE_KEY` | Service CryptoSign private key; its public key must match the Hub configuration |
| `X_DEBUG` | When true, prints email contents including verification codes instead of sending them |
| `RESEND_API_KEY` | Required for email delivery when debug mode is disabled |

Use deployment-specific credentials outside local development. Configure the
Hub's `DESKCONN_ACCOUNT_SERVICE_PUBLIC_KEY` to match the service key. The service
identity must have permission to register its RPCs and perform its Hub operations.

The host example defaults to a WebSocket URL; set `ROUTER_URL` explicitly to an
endpoint enabled by your Hub. The Python client also supports RawSocket with
`rs://`; `rss://` is not the spelling used by this transport.

## Database and migrations

For the local Compose database and host-run service, keep
`DESKCONN_POSTGRES_HOST=localhost`:

```sh
make db
```

For an existing database, apply migrations with:

```sh
make migrate
```

To create a migration after a model change:

```sh
make migration name=describe_the_change
```

Review generated migrations before applying them. Hub and Management must use
the same DeskConn database, with their respective database roles.

## Email

`example.env` enables `X_DEBUG=true` for local development. Verification codes
appear in service logs; no Resend API key is needed in that mode.

For actual delivery, disable debug mode and configure Resend. Email template
aliases and the sender are defined in `deskconn/helpers.py`; templates are in
`deskconn/email_templates.py`. After configuring the deployment's Resend account,
sync its templates with:

```sh
.venv/bin/python -m deskconn.email_templates
```

## Docker

The included Compose setup shares the `deskconn` Docker network with the Hub.
Initialize and migrate the database from the host first, then configure `.env`
for service-to-service addresses:

```dotenv
DESKCONN_POSTGRES_HOST=deskconn-account-service-postgres
ROUTER_URL=rs://deskconn-router:8084/rs
```

Start the service:

```sh
make run-docker
```

The Compose service runs `xconnio/deskconn-account-service:latest`; it does not
build the local checkout automatically. Override the image to test your own
build. When running migrations from the host again, restore the database host
to `localhost` or provide a host-reachable `DESKCONN_DATABASE_URL`.

For the complete local DeskConn stack, see the
[DeskConn self-hosting guide](https://github.com/xconnio/deskconn/blob/main/docs/self-hosting.md).
