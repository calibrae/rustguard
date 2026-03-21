# Contributing to RustGuard

## Getting Started

1. Fork the repo
2. Clone your fork
3. Create a branch: `git checkout -b my-thing`
4. Make your changes
5. Run tests: `cargo test --workspace`
6. Push and open a PR

## Building

```bash
cargo build --release
```

Cross-compile for Linux (from macOS):
```bash
cargo build --release --target x86_64-unknown-linux-musl
```

## Testing

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p rustguard-core
cargo test -p rustguard-crypto
```

The crypto and protocol tests are the ones that matter most. Don't skip them.

## Code Style

- `cargo fmt` before committing
- `cargo clippy` should be clean
- No `unsafe` unless absolutely necessary — if you need it, wrap it in a safe API and explain why
- Keep dependencies minimal. If you're adding a crate, justify it

## Project Structure

```
rustguard-crypto/     Crypto primitives (don't touch unless you know what you're doing)
rustguard-core/       Protocol state machine, handshake, replay protection
rustguard-tun/        Platform-specific TUN/network I/O
rustguard-daemon/     Config parsing, tunnel management
rustguard-enroll/     Zero-config enrollment protocol
rustguard-cli/        CLI entry point
```

## What We're Looking For

- Bug fixes with tests
- Platform support (Windows/Wintun would be huge)
- Performance improvements with benchmarks proving the win
- Documentation fixes

## What We're Not Looking For

- Massive refactors without prior discussion
- New dependencies for things we can do in 20 lines
- AI-generated PRs with no understanding of the code

## License

By contributing, you agree that your contributions will be licensed under MIT OR Apache-2.0.
