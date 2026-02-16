// Many public items in submodules are part of the future API surface
// (attestation, TSC calibration, threshold signing) but not yet wired up.
#![allow(dead_code)]

/// CVM Core: Minimal signing oracle for CC-TSA.
///
/// This is the security-critical code that runs inside the AMD SEV-SNP
/// confidential VM. It is measured at boot and its hash is bound to the
/// TSA certificate. Any change triggers a new DKG ceremony.
///
/// State machine:
///   Booting -> TimeSync -> Ready -> Signing
///                                    |
///                                (on error) -> Degraded
mod attestation;
mod protocol;
mod signed_attrs;
mod signing;
mod time;
mod tstinfo;

use protocol::{
    parse_request, serialize_error_response, serialize_response, ResponseStatus, SignResponse,
};
use signed_attrs::build_signed_attrs;
use signing::SigningContext;
use time::{current_time_ms, format_generalized_time, NtsState};
use tstinfo::{build_tstinfo, TstInfoParams};

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};

/// Vsock port the CVM listens on for signing requests.
const VSOCK_PORT: u32 = 5000;

/// Maximum request size (with safety margin).
const MAX_REQUEST_BYTES: usize = 128;

/// Monotonic serial number counter.
static SERIAL_COUNTER: AtomicU64 = AtomicU64::new(1);

/// CVM operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CvmState {
    Booting,
    TimeSync,
    Ready,
    Signing,
    Degraded,
}

impl std::fmt::Display for CvmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Booting => write!(f, "BOOTING"),
            Self::TimeSync => write!(f, "TIME_SYNC"),
            Self::Ready => write!(f, "READY"),
            Self::Signing => write!(f, "SIGNING"),
            Self::Degraded => write!(f, "DEGRADED"),
        }
    }
}

fn next_serial_number() -> u64 {
    SERIAL_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Process a single signing request.
fn handle_request(
    request_bytes: &[u8],
    signing_ctx: &SigningContext,
    nts_state: &NtsState,
) -> Vec<u8> {
    // Parse the binary request
    let request = match parse_request(request_bytes) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("request parse error: {}", e);
            return serialize_error_response(ResponseStatus::InvalidRequest);
        }
    };

    // Check time availability
    if !nts_state.is_valid() {
        eprintln!("time source not validated");
        return serialize_error_response(ResponseStatus::TimeUnavailable);
    }

    // Get trusted time
    let unix_ms = current_time_ms();
    let gen_time = format_generalized_time(unix_ms);

    // Generate serial number
    let serial = next_serial_number();

    // Build TSTInfo
    let tstinfo_der = build_tstinfo(&TstInfoParams {
        hash_algorithm: request.hash_algorithm,
        digest: &request.digest,
        serial_number: serial,
        gen_time,
        nonce: request.nonce.as_deref(),
    });

    // Build signedAttrs
    let signed_attrs_der = build_signed_attrs(&tstinfo_der, &signing_ctx.cert_hash);

    // Sign the signedAttrs
    let signature = match signing_ctx.sign(&signed_attrs_der) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("signing error: {}", e);
            return serialize_error_response(ResponseStatus::InternalError);
        }
    };

    // Build response
    serialize_response(&SignResponse {
        status: ResponseStatus::Success,
        tstinfo_der,
        signed_attrs_der,
        signature,
    })
}

/// Handle a single connection: read request, process, write response.
fn handle_connection<S: Read + Write>(
    mut stream: S,
    signing_ctx: &SigningContext,
    nts_state: &NtsState,
) {
    // Read request with size limit
    let mut buf = [0u8; MAX_REQUEST_BYTES];
    let n = match stream.read(&mut buf) {
        Ok(0) => return, // connection closed
        Ok(n) => n,
        Err(e) => {
            eprintln!("read error: {}", e);
            return;
        }
    };

    let response = handle_request(&buf[..n], signing_ctx, nts_state);

    if let Err(e) = stream.write_all(&response) {
        eprintln!("write error: {}", e);
    }
}

fn main() {
    eprintln!("CVM Core v0.1.0 starting");

    let mut state = CvmState::Booting;
    eprintln!("state: {}", state);

    // Phase 1: Load or generate signing key
    // In production, the key is generated via DKG ceremony.
    // For MVP, generate a random key at startup.
    let signing_ctx = SigningContext::generate();
    eprintln!("signing key loaded");

    // Phase 2: Time synchronization
    state = CvmState::TimeSync;
    eprintln!("state: {}", state);

    // In production, establish NTS sessions with 4 time sources.
    // For MVP, trust the system clock.
    let mut nts_state = NtsState::new(100); // 100ms tolerance
    nts_state.validated = true; // MVP: assume valid
    eprintln!("time sync complete (MVP: system clock)");

    // Phase 3: Ready
    state = CvmState::Ready;
    eprintln!("state: {}", state);

    // In production, bind to vsock. For development, use TCP on localhost.
    // vsock listener: VsockListener::bind(VSOCK_CID_ANY, VSOCK_PORT)
    eprintln!(
        "listening on vsock port {} (or TCP fallback for development)",
        VSOCK_PORT
    );

    // Development mode: TCP listener for testing without vsock
    let listener = match std::net::TcpListener::bind("127.0.0.1:5000") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind TCP listener: {}", e);
            state = CvmState::Degraded;
            eprintln!("state: {}", state);
            return;
        }
    };

    eprintln!("CVM Core ready, accepting connections");
    state = CvmState::Signing;
    eprintln!("state: {}", state);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_connection(stream, &signing_ctx, &nts_state);
            }
            Err(e) => {
                eprintln!("accept error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_signing_ctx() -> SigningContext {
        SigningContext::generate()
    }

    fn test_nts_state() -> NtsState {
        let mut s = NtsState::new(100);
        s.validated = true;
        s
    }

    #[test]
    fn handle_valid_sha256_request() {
        let ctx = test_signing_ctx();
        let nts = test_nts_state();

        let mut req = vec![0x01, 0x01, 32];
        req.extend_from_slice(&[0xAA; 32]);
        req.push(0x00);

        let resp = handle_request(&req, &ctx, &nts);
        assert_eq!(resp[0], 0x01); // version
        assert_eq!(resp[1], 0x00); // success
    }

    #[test]
    fn handle_valid_sha384_with_nonce() {
        let ctx = test_signing_ctx();
        let nts = test_nts_state();

        let mut req = vec![0x01, 0x02, 48];
        req.extend_from_slice(&[0xBB; 48]);
        req.push(0x01);
        req.push(8);
        req.extend_from_slice(&[0xCC; 8]);

        let resp = handle_request(&req, &ctx, &nts);
        assert_eq!(resp[1], 0x00); // success

        // Parse response to verify non-empty payloads
        let tstinfo_len = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
        assert!(tstinfo_len > 0);
    }

    #[test]
    fn handle_invalid_request() {
        let ctx = test_signing_ctx();
        let nts = test_nts_state();

        let req = vec![0x02, 0x01, 32]; // wrong version
        let resp = handle_request(&req, &ctx, &nts);
        assert_eq!(resp[1], ResponseStatus::InvalidRequest as u8);
    }

    #[test]
    fn handle_time_unavailable() {
        let ctx = test_signing_ctx();
        let nts = NtsState::new(100); // not validated

        let mut req = vec![0x01, 0x01, 32];
        req.extend_from_slice(&[0x00; 32]);
        req.push(0x00);

        let resp = handle_request(&req, &ctx, &nts);
        assert_eq!(resp[1], ResponseStatus::TimeUnavailable as u8);
    }

    #[test]
    fn serial_numbers_are_monotonic() {
        let s1 = next_serial_number();
        let s2 = next_serial_number();
        let s3 = next_serial_number();
        assert!(s2 > s1);
        assert!(s3 > s2);
    }

    #[test]
    fn response_signature_is_verifiable() {
        use ecdsa::signature::Verifier;
        use p384::ecdsa::Signature;

        let ctx = test_signing_ctx();
        let nts = test_nts_state();

        let mut req = vec![0x01, 0x02, 48];
        req.extend_from_slice(&[0xDD; 48]);
        req.push(0x00);

        let resp = handle_request(&req, &ctx, &nts);
        assert_eq!(resp[1], 0x00);

        // Extract signed_attrs and signature from response
        let tstinfo_len = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
        let sa_offset = 6 + tstinfo_len;
        let sa_len = u32::from_be_bytes([
            resp[sa_offset],
            resp[sa_offset + 1],
            resp[sa_offset + 2],
            resp[sa_offset + 3],
        ]) as usize;
        let sa_data = &resp[sa_offset + 4..sa_offset + 4 + sa_len];

        let sig_offset = sa_offset + 4 + sa_len;
        let sig_len = u32::from_be_bytes([
            resp[sig_offset],
            resp[sig_offset + 1],
            resp[sig_offset + 2],
            resp[sig_offset + 3],
        ]) as usize;
        let sig_data = &resp[sig_offset + 4..sig_offset + 4 + sig_len];

        let signature = Signature::from_der(sig_data).unwrap();
        ctx.verifying_key().verify(sa_data, &signature).unwrap();
    }
}
