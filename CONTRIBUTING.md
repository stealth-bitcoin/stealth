# Contributing to Stealth

Contributions are welcome. This document explains how to set up the project, submit changes, and what we expect during code review.

## Before you start

- **Open an issue first** for non-trivial changes so we can discuss the approach before you invest time writing code.
- **Keep PRs focused** — one concern per pull request.
- **Stay aligned with the project's philosophy** — Stealth is a local-first, privacy-preserving analysis engine. Changes that introduce external service dependencies or move away from this model are generally not a good fit.

See [GOVERNANCE.md](GOVERNANCE.md) for how decisions are made.

## Setup

### Requirements

- [Rust](https://rustup.rs/) (stable, >= 1.93.1)
- [Bitcoin Core](https://bitcoincore.org/) (>= 29.0) — needed for integration tests

### Building

```bash
cargo build --workspace
```

### Running tests

```bash
cargo test --workspace
```

Integration tests start a local `bitcoind` in regtest mode automatically via `corepc-node`.

### Code formatting and linting

CI enforces both. Run these before pushing:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

Formatting rules are defined in `rustfmt.toml` (100-char line width, 4-space indentation).

## Submitting a pull request

1. Fork the repository and create a branch from `main`.
2. Write your code, add tests if applicable.
3. Make sure `cargo fmt`, `cargo clippy`, and `cargo test` pass.
4. Open a pull request against `main`.

### Commit messages

Use [conventional commits](https://www.conventionalcommits.org/) format:

```
feat(engine): add peeling chain detector
fix(bitcoincore): handle missing address in listunspent
refactor(model): extract WalletHistory builder
test(engine): add CIOH edge case
docs: update README with CLI usage
```

### During review

Once your PR is open and under review:

- **Do not rebase or force-push.** If you need to make changes, add new commits. Force-pushing destroys the review context — reviewers lose track of what changed between rounds and have to start over.
- **Do not squash commits during review.** Keep fixup commits separate so reviewers can see exactly what changed in response to each comment.

This follows the same approach used by [Envoy](https://github.com/envoyproxy/envoy/blob/main/CONTRIBUTING.md), [LLVM](https://llvm.org/docs/GitHub.html), and [Miri](https://github.com/rust-lang/miri/blob/master/CONTRIBUTING.md).

## Project structure

```
stealth/
  model/          # Shared types, traits, configuration (stealth-model)
  engine/         # Detection engine, heuristics, TxGraph (stealth-engine)
  bitcoincore/    # Bitcoin Core RPC gateway (stealth-bitcoincore)
```

## What we look for in code

- Use `bitcoin` crate types (`Txid`, `Address`, `Amount`) instead of raw strings and floats.
- Prefer borrowing (`&`) over `.clone()` when you only need to read.
- Prefer generics over `dyn` trait objects when the concrete type is known at compile time.
- Keep thresholds and constants configurable via `DetectorThresholds`, not hardcoded.
- All detectors should be covered by integration tests.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
