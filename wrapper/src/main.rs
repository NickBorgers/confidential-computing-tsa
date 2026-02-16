// Many public items are part of the future API surface (vsock config,
// env-based config, policy handling) but not yet wired up in the MVP.
#![allow(dead_code)]

/// TSA Wrapper: RFC 3161 HTTP server and CMS assembly.
///
/// This runs OUTSIDE the CVM and is updatable without triggering key rotation.
/// It handles:
/// - HTTP listener for RFC 3161 requests
/// - TimeStampReq ASN.1 parsing and validation
/// - Forwarding to CVM via vsock binary protocol
/// - CMS SignedData assembly from CVM response
/// - TimeStampResp construction and delivery
mod cms;
mod config;
mod response;
mod rfc3161;
mod vsock_client;

use cms::{build_signed_data, CmsConfig, CvmComponents};
use config::WrapperConfig;
use response::{build_timestamp_resp_rejection, build_timestamp_resp_success};
use rfc3161::{build_cvm_request, validate_request, HashAlgorithm, RejectReason, TimeStampReq};
use vsock_client::{parse_response_payload, parse_response_status, send_request, CvmConfig};

use std::io::{Read, Write};
use std::net::TcpListener;

/// Maximum request body size (64 KB — generous for TimeStampReq).
const MAX_REQUEST_BODY: usize = 65536;

/// Handle a single HTTP request.
///
/// For MVP, this is a minimal HTTP implementation. In production,
/// use a proper HTTP server (hyper, actix-web, etc.) with TLS.
fn handle_http_request(
    body: &[u8],
    wrapper_config: &WrapperConfig,
    cvm_config: &CvmConfig,
) -> Vec<u8> {
    // Parse TimeStampReq
    // For MVP, assume body is raw DER TimeStampReq.
    // Full implementation would use rasn to decode ASN.1.
    let tsa_req = match parse_timestamp_req_minimal(body) {
        Ok(req) => req,
        Err(reason) => {
            return build_timestamp_resp_rejection(
                reason.failure_info_bit(),
                Some(&format!("{:?}", reason)),
            );
        }
    };

    // Validate
    if let Err(reason) = validate_request(&tsa_req) {
        return build_timestamp_resp_rejection(
            reason.failure_info_bit(),
            Some(&format!("{:?}", reason)),
        );
    }

    // Build CVM binary request
    let cvm_req = build_cvm_request(&tsa_req);

    // Send to CVM
    let cvm_resp = match send_request(cvm_config, &cvm_req) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("CVM error: {}", e);
            return build_timestamp_resp_rejection(
                RejectReason::BadRequest.failure_info_bit(),
                Some("internal error: CVM unavailable"),
            );
        }
    };

    // Check CVM response status
    let status = match parse_response_status(&cvm_resp) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("CVM response error: {}", e);
            return build_timestamp_resp_rejection(
                RejectReason::BadRequest.failure_info_bit(),
                Some("internal error: invalid CVM response"),
            );
        }
    };

    if status != 0x00 {
        let reason = match status {
            0x03 => RejectReason::TimeNotAvailable,
            _ => RejectReason::BadRequest,
        };
        return build_timestamp_resp_rejection(
            reason.failure_info_bit(),
            Some("CVM signing failed"),
        );
    }

    // Parse CVM response payload
    let payload = match parse_response_payload(&cvm_resp) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("CVM payload error: {}", e);
            return build_timestamp_resp_rejection(
                RejectReason::BadRequest.failure_info_bit(),
                Some("internal error: invalid CVM payload"),
            );
        }
    };

    // Build CMS SignedData
    let cms_config = CmsConfig {
        ecdsa_cert_der: wrapper_config.ecdsa_cert_der.clone(),
        ca_chain_der: wrapper_config.ca_chain_der.clone(),
        issuer_der: wrapper_config.issuer_der.clone(),
        serial_number_der: wrapper_config.serial_number_der.clone(),
    };
    let components = CvmComponents {
        tstinfo_der: payload.tstinfo_der,
        signed_attrs_der: payload.signed_attrs_der,
        signature: payload.signature,
    };
    let signed_data = build_signed_data(&cms_config, &components);

    // Build TimeStampResp
    build_timestamp_resp_success(&signed_data)
}

/// Minimal TimeStampReq parser for MVP.
///
/// In production, use rasn or another ASN.1 library for full parsing.
/// This extracts the hash algorithm OID and digest from the messageImprint.
fn parse_timestamp_req_minimal(der: &[u8]) -> Result<TimeStampReq, RejectReason> {
    if der.len() < 10 {
        return Err(RejectReason::BadDataFormat);
    }

    // Outer SEQUENCE
    if der[0] != 0x30 {
        return Err(RejectReason::BadDataFormat);
    }

    // Skip outer SEQUENCE tag+length
    let (_, outer_header) = read_der_length(&der[1..]).ok_or(RejectReason::BadDataFormat)?;
    let content = &der[1 + outer_header..];

    // version INTEGER
    if content.len() < 3 || content[0] != 0x02 {
        return Err(RejectReason::BadDataFormat);
    }
    let ver_len = content[1] as usize;
    if ver_len != 1 || content[2] != 1 {
        return Err(RejectReason::BadRequest);
    }
    let after_version = &content[3..];

    // messageImprint SEQUENCE
    if after_version.is_empty() || after_version[0] != 0x30 {
        return Err(RejectReason::BadDataFormat);
    }
    let (mi_len, mi_header) =
        read_der_length(&after_version[1..]).ok_or(RejectReason::BadDataFormat)?;
    let mi_content = &after_version[1 + mi_header..1 + mi_header + mi_len];

    // hashAlgorithm AlgorithmIdentifier SEQUENCE
    if mi_content.is_empty() || mi_content[0] != 0x30 {
        return Err(RejectReason::BadDataFormat);
    }
    let (algo_len, algo_header) =
        read_der_length(&mi_content[1..]).ok_or(RejectReason::BadDataFormat)?;
    let algo_content = &mi_content[1 + algo_header..1 + algo_header + algo_len];

    // Extract OID from AlgorithmIdentifier
    if algo_content.is_empty() || algo_content[0] != 0x06 {
        return Err(RejectReason::BadDataFormat);
    }
    let oid_len = algo_content[1] as usize;
    if algo_content.len() < 2 + oid_len {
        return Err(RejectReason::BadDataFormat);
    }
    let oid_bytes = &algo_content[2..2 + oid_len];

    let hash_algorithm = HashAlgorithm::from_oid(oid_bytes).ok_or(RejectReason::BadAlg)?;

    // hashedMessage OCTET STRING
    let digest_start = 1 + algo_header + algo_len;
    if digest_start >= mi_content.len() || mi_content[digest_start] != 0x04 {
        return Err(RejectReason::BadDataFormat);
    }
    let (digest_len, digest_header) =
        read_der_length(&mi_content[digest_start + 1..]).ok_or(RejectReason::BadDataFormat)?;
    let digest_offset = digest_start + 1 + digest_header;
    if digest_offset + digest_len > mi_content.len() {
        return Err(RejectReason::BadDataFormat);
    }
    let message_digest = mi_content[digest_offset..digest_offset + digest_len].to_vec();

    // Remaining fields after messageImprint are optional (reqPolicy, nonce, certReq)
    // For MVP, we don't parse nonce from the ASN.1 — it will be added when full
    // ASN.1 parsing is implemented.

    Ok(TimeStampReq {
        hash_algorithm,
        message_digest,
        nonce: None,
        policy_oid: None,
        cert_req: true,
    })
}

/// Read a DER length encoding, returning (length, bytes_consumed).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some((data[0] as usize, 1))
    } else if data[0] == 0x81 {
        if data.len() < 2 {
            return None;
        }
        Some((data[1] as usize, 2))
    } else if data[0] == 0x82 {
        if data.len() < 3 {
            return None;
        }
        Some((((data[1] as usize) << 8) | data[2] as usize, 3))
    } else {
        None // lengths > 65535 not expected for TimeStampReq
    }
}

fn main() {
    eprintln!("TSA Wrapper v0.1.0 starting");

    let wrapper_config = WrapperConfig::default();
    let cvm_config = CvmConfig::default();

    let listen_addr = &wrapper_config.listen_addr;
    eprintln!("listening on {}", listen_addr);

    let listener = match TcpListener::bind(listen_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind: {}", e);
            std::process::exit(1);
        }
    };

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // Minimal HTTP request parsing for MVP
                let mut buf = vec![0u8; MAX_REQUEST_BODY + 4096]; // headers + body
                let n = match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("read error: {}", e);
                        continue;
                    }
                };
                let data = &buf[..n];

                // Find body (after \r\n\r\n)
                let body_start = data
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(0);
                let body = &data[body_start..];

                if body.is_empty() {
                    // Health check or invalid request
                    let health = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"healthy\"}";
                    let _ = stream.write_all(health);
                    continue;
                }

                let resp_body = handle_http_request(body, &wrapper_config, &cvm_config);

                let mut http_resp = Vec::new();
                http_resp.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
                http_resp.extend_from_slice(b"Content-Type: application/timestamp-reply\r\n");
                http_resp.extend_from_slice(
                    format!("Content-Length: {}\r\n\r\n", resp_body.len()).as_bytes(),
                );
                http_resp.extend_from_slice(&resp_body);

                if let Err(e) = stream.write_all(&http_resp) {
                    eprintln!("write error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("accept error: {}", e);
            }
        }
    }
}
