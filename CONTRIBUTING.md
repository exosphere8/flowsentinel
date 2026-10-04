# Contributing to FlowSentinel

Contributions are welcome. FlowSentinel is security software, so the bar for safety and tests is high.

## Ground rules

- **Defensive scope only.** Changes that add packet injection, scanning, evasion, unauthorized
  decryption or credential extraction will be declined. See [SECURITY.md](SECURITY.md).
- **No real traffic in the repository.** Fixtures must be synthetic and reproducible from a script.
- **Report vulnerabilities privately**, as described in [SECURITY.md](SECURITY.md), never in public issues.

## Local setup

1. Install stable Rust (1.85 or newer) with `rustfmt` and `clippy`:
   `rustup component add rustfmt clippy`
2. Install Docker with Compose v2 (needed only for `make up`).
3. Copy the environment template and set real local passwords:
   `cp .env.example .env`
4. Verify everything: `make check`

On Windows without `make`, run the commands from the `check` target in the Makefile directly.
If a build fails with `os error 3`, see the Windows note in the README.

## Database tests

The storage and API integration tests need a PostgreSQL server where the test user may create
databases. Each test creates its own database, applies the migrations and drops it at the end,
even when the test fails. Without a server they print a notice and pass, so `cargo test` works
anywhere. CI runs them against a throwaway PostgreSQL 16 service and sets
`FLOWSENTINEL_REQUIRE_DB_TESTS=1`, which turns a missing server into a failure.

With the Compose services running (`make up`), run:

```bash
make test-db
```

Or point the tests at any disposable server yourself:

```bash
FLOWSENTINEL_TEST_DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:5432/postgres \
  cargo test -p storage -p api-server
```

Never point them at a database whose data you need: they create and drop databases named
`fs_test_*`.

## Quality gates

Every pull request must pass the same gate as CI:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
make test-db   # storage and API tests against PostgreSQL (CI runs these too)
```

## Coding standards

- Idiomatic, `rustfmt`-formatted Rust. `unsafe` is forbidden workspace-wide.
- Do not use `unwrap`, `expect` or unchecked indexing outside tests. Return typed errors
  (`thiserror`) with messages that tell the user what to do next.
- Treat every input as hostile: bound lengths, use checked arithmetic and never allocate from
  an untrusted size.
- Never log, print or store packet payloads, credentials or secrets.
- Add tests for every feature and every error path. Prefer deterministic tests with no network access.
- Binary fixtures come from scripts. To add a PCAP fixture, extend
  `scripts/generate_pcap_fixtures.py`, run `make fixtures`, and commit both the script and the
  output. CI fails if the committed fixtures differ from the script's output.
- Parsers of untrusted input need property tests, and should be added to the cargo-fuzz targets
  in `fuzz/` (see `fuzz/README.md`). Run a fuzz session after changing a parser.
- Keep documentation in sync: user-visible changes update the README or `docs/`.

## Branches and commits

- Branch from `main` as `feature/<short-name>` or `fix/<short-name>`.
- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
  `test:`, `refactor:`, `chore:`, `ci:`. Use the imperative mood, for example
  `feat: add safe offline PCAP ingestion`.
- Releases follow [Semantic Versioning](https://semver.org/).

## Pull requests

Before requesting review, confirm that:

- [ ] The quality gate passes locally.
- [ ] New behavior and error paths are tested.
- [ ] Docs are updated.
- [ ] No payloads, secrets or real captures were added.
- [ ] The change stays within the defensive scope.
