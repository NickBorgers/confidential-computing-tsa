/// Vsock client for communicating with the CVM core.
///
/// Connects to the CVM over vsock (or TCP for development),
/// sends binary signing requests, and receives responses.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// CVM connection configuration.
pub struct CvmConfig {
    /// For vsock: the CID of the CVM guest.
    /// For TCP development: ignored (connects to localhost).
    pub vsock_cid: u32,
    /// Port the CVM listens on.
    pub port: u32,
    /// Connection timeout.
    pub timeout: Duration,
}

impl Default for CvmConfig {
    fn default() -> Self {
        Self {
            vsock_cid: 3, // typical guest CID
            port: 5000,
            timeout: Duration::from_secs(5),
        }
    }
}

/// Send a signing request to the CVM and receive the response.
///
/// In production, this uses vsock. For development, falls back to TCP.
pub fn send_request(config: &CvmConfig, request: &[u8]) -> Result<Vec<u8>, CvmError> {
    // Development mode: TCP connection to localhost
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", config.port))
        .map_err(|e| CvmError::ConnectionFailed(e.to_string()))?;

    stream.set_read_timeout(Some(config.timeout))
        .map_err(|e| CvmError::ConnectionFailed(e.to_string()))?;
    stream.set_write_timeout(Some(config.timeout))
        .map_err(|e| CvmError::ConnectionFailed(e.to_string()))?;

    // Send request
    stream.write_all(request)
        .map_err(|e| CvmError::SendFailed(e.to_string()))?;

    // Shutdown write half to signal end of request
    stream.shutdown(std::net::Shutdown::Write)
        .map_err(|e| CvmError::SendFailed(e.to_string()))?;

    // Read response (max 16KB — generous for TSTInfo + signedAttrs + signature)
    let mut response = Vec::with_capacity(4096);
    stream.take(16384).read_to_end(&mut response)
        .map_err(|e| CvmError::ReceiveFailed(e.to_string()))?;

    if response.len() < 2 {
        return Err(CvmError::InvalidResponse("response too short".into()));
    }

    Ok(response)
}

/// Parse the status byte from a CVM response.
pub fn parse_response_status(response: &[u8]) -> Result<u8, CvmError> {
    if response.len() < 2 {
        return Err(CvmError::InvalidResponse("response too short".into()));
    }
    if response[0] != 0x01 {
        return Err(CvmError::InvalidResponse(
            format!("unexpected protocol version: {:#04x}", response[0])
        ));
    }
    Ok(response[1])
}

/// Extract the TSTInfo, signedAttrs, and signature from a successful CVM response.
pub fn parse_response_payload(response: &[u8]) -> Result<CvmPayload, CvmError> {
    if response.len() < 14 {
        return Err(CvmError::InvalidResponse("response too short for payload".into()));
    }

    let mut offset = 2; // skip version + status

    // TSTInfo
    let tstinfo_len = u32::from_be_bytes([
        response[offset], response[offset + 1], response[offset + 2], response[offset + 3],
    ]) as usize;
    offset += 4;
    if offset + tstinfo_len > response.len() {
        return Err(CvmError::InvalidResponse("tstinfo truncated".into()));
    }
    let tstinfo_der = response[offset..offset + tstinfo_len].to_vec();
    offset += tstinfo_len;

    // signedAttrs
    if offset + 4 > response.len() {
        return Err(CvmError::InvalidResponse("missing signed_attrs length".into()));
    }
    let sa_len = u32::from_be_bytes([
        response[offset], response[offset + 1], response[offset + 2], response[offset + 3],
    ]) as usize;
    offset += 4;
    if offset + sa_len > response.len() {
        return Err(CvmError::InvalidResponse("signed_attrs truncated".into()));
    }
    let signed_attrs_der = response[offset..offset + sa_len].to_vec();
    offset += sa_len;

    // Signature
    if offset + 4 > response.len() {
        return Err(CvmError::InvalidResponse("missing signature length".into()));
    }
    let sig_len = u32::from_be_bytes([
        response[offset], response[offset + 1], response[offset + 2], response[offset + 3],
    ]) as usize;
    offset += 4;
    if offset + sig_len > response.len() {
        return Err(CvmError::InvalidResponse("signature truncated".into()));
    }
    let signature = response[offset..offset + sig_len].to_vec();

    Ok(CvmPayload {
        tstinfo_der,
        signed_attrs_der,
        signature,
    })
}

/// Parsed payload from a successful CVM response.
pub struct CvmPayload {
    pub tstinfo_der: Vec<u8>,
    pub signed_attrs_der: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub enum CvmError {
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    InvalidResponse(String),
}

impl std::fmt::Display for CvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(e) => write!(f, "CVM connection failed: {}", e),
            Self::SendFailed(e) => write!(f, "CVM send failed: {}", e),
            Self::ReceiveFailed(e) => write!(f, "CVM receive failed: {}", e),
            Self::InvalidResponse(e) => write!(f, "CVM invalid response: {}", e),
        }
    }
}
