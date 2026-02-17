# CC-TSA Project Rules

This is a documentation-focused design specification and PoC implementation
for a quantum-safe, hardware-attested Timestamp Authority built on AMD SEV-SNP
confidential VMs.

## Build and Validation Commands

- Markdown linting: `markdownlint '**/*.md' --config .markdownlint.json`
- Rust tests: `cargo test` (if Cargo.toml exists)
- Rust formatting: `cargo fmt --check` (if Cargo.toml exists)
- Rust linting: `cargo clippy -- -D warnings` (if Cargo.toml exists)

## Key References

- System architecture: `docs/01-architecture-overview.md`
- Confidential computing: `docs/02-confidential-computing-and-time.md`
- Threshold cryptography: `docs/03-quantum-safe-threshold-crypto.md`
- Failure modes: `docs/04-failure-modes-and-recovery.md`
- Operations: `docs/05-operations-and-deployment.md`
- RFC 3161 compliance: `docs/06-rfc3161-compliance.md`
- Threat model: `docs/07-threat-model.md`
- Scaling: `docs/08-throughput-and-scaling.md`
- Enclave interface: `docs/09-enclave-interface.md`

## Git Rules

- Never use `git push --no-verify`
- Before pushing: rebase with `git pull --rebase origin <branch>`
