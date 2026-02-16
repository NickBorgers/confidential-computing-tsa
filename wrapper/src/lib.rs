// Many public items are part of the future API surface (vsock config,
// env-based config, policy handling) but not yet wired up in the MVP.
#![allow(dead_code)]

/// TSA Wrapper: RFC 3161 HTTP server and CMS assembly.
///
/// This runs OUTSIDE the CVM and is updatable without triggering key rotation.
pub mod cms;
pub mod config;
pub mod response;
pub mod rfc3161;
pub mod vsock_client;
