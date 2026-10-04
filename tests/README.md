# Cross-crate tests

Unit and integration tests live next to the code they cover:

| Location | What it covers |
| --- | --- |
| `crates/api-server/src/lib.rs` | Configuration parsing |
| `crates/api-server/tests/health.rs` | `GET /health` in-process and over a real TCP socket |
| `crates/cli/src/main.rs` | Argument definitions |
| `crates/cli/tests/cli.rs` | The compiled `flowsentinel` binary end to end |

This directory is reserved for end-to-end tests that span several services,
such as the API with PostgreSQL. Those arrive with persistence in Milestone 5.
