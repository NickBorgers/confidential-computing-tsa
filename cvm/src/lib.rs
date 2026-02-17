// Many public items in submodules are part of the future API surface
// (attestation, TSC calibration, threshold signing) but not yet wired up.
#![allow(dead_code)]

/// CVM Core: Minimal signing oracle for CC-TSA.
///
/// This is the security-critical code that runs inside the AMD SEV-SNP
/// confidential VM. It is measured at boot and its hash is bound to the
/// TSA certificate. Any change triggers a new DKG ceremony.
pub mod attestation;
pub mod protocol;
pub mod signed_attrs;
pub mod signing;
pub mod time;
pub mod tstinfo;
