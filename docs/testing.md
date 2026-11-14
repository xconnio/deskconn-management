# Testing

Install test dependencies with `make setup` for a new checkout. For an existing
virtual environment, preserve your `.env` and run:

```sh
uv pip install -e '.[test]'
```

Then run:

```sh
make lint
make test
```

`make format` applies formatting. For a read-only format check:

```sh
.venv/bin/ruff format --check .
```

The test configuration supplies an isolated database URL and enables debug email
mode. The current tests check credential compatibility, procedure registration,
request dependency handling, caller identity, and the service launcher. They do
not replace tests of real PostgreSQL transactions or a deployed account workflow.

## Real-router integration

The optional router test registers the application with a local XConn peer,
executes an RPC, and verifies event publication and subscription. Without
`XCONN_TRANSPORT_PEER`, this test is skipped.

With a Rust toolchain and XConn checkout at `../xconn`, build the fixture:

```sh
cargo build --manifest-path ../xconn/Cargo.toml --locked \
  -p xconn-binding-runtime --all-features --example transport_peer
```

Run the service tests with that fixture:

```sh
XCONN_TRANSPORT_PEER="$PWD/../xconn/target/debug/examples/transport_peer" \
  make test
```

This uses local endpoints without a production Hub or email delivery. Rust and
the XConn checkout are needed only to build this fixture, not to install or run
the Management service normally.
