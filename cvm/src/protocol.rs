//! Binary protocol for CVM <-> Wrapper communication over vsock.
//!
//! Request (Wrapper -> CVM):
//!   [version:1][hash_algorithm:1][digest_length:1][digest:N][has_nonce:1][nonce_length:1][nonce:M]
//!
//! Response (CVM -> Wrapper):
//!   [version:1][status:1][tstinfo_length:4][tstinfo:T][signed_attrs_length:4][signed_attrs:A][signature_length:4][signature:S]

const PROTOCOL_VERSION: u8 = 0x01;

/// Maximum total request size: version(1) + algo(1) + digest_len(1) + digest(64) + has_nonce(1) + nonce_len(1) + nonce(32) = 101
const MAX_REQUEST_SIZE: usize = 101;
const MAX_NONCE_LENGTH: u8 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlgorithm {
    Sha256 = 0x01,
    Sha384 = 0x02,
    Sha512 = 0x03,
}

impl HashAlgorithm {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Sha256),
            0x02 => Some(Self::Sha384),
            0x03 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn digest_length(self) -> u8 {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub hash_algorithm: HashAlgorithm,
    pub digest: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Success = 0x00,
    InvalidRequest = 0x01,
    InternalError = 0x02,
    TimeUnavailable = 0x03,
}

#[derive(Debug, Clone)]
pub struct SignResponse {
    pub status: ResponseStatus,
    pub tstinfo_der: Vec<u8>,
    pub signed_attrs_der: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    TooLong,
    InvalidVersion(u8),
    InvalidHashAlgorithm(u8),
    DigestLengthMismatch { declared: u8, expected: u8 },
    DigestTruncated,
    InvalidNonceFlag(u8),
    NonceTooLong(u8),
    NonceTruncated,
    TrailingData,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "request too short"),
            Self::TooLong => write!(f, "request exceeds maximum size"),
            Self::InvalidVersion(v) => write!(f, "invalid protocol version: {:#04x}", v),
            Self::InvalidHashAlgorithm(a) => write!(f, "invalid hash algorithm: {:#04x}", a),
            Self::DigestLengthMismatch { declared, expected } => {
                write!(
                    f,
                    "digest length {} does not match algorithm (expected {})",
                    declared, expected
                )
            }
            Self::DigestTruncated => write!(f, "digest truncated"),
            Self::InvalidNonceFlag(v) => write!(f, "invalid nonce flag: {:#04x}", v),
            Self::NonceTooLong(n) => {
                write!(f, "nonce too long: {} bytes (max {})", n, MAX_NONCE_LENGTH)
            }
            Self::NonceTruncated => write!(f, "nonce truncated"),
            Self::TrailingData => write!(f, "trailing data after request"),
        }
    }
}

/// Parse a binary sign request from the wrapper.
pub fn parse_request(data: &[u8]) -> Result<SignRequest, ParseError> {
    if data.len() < 3 {
        return Err(ParseError::TooShort);
    }
    if data.len() > MAX_REQUEST_SIZE {
        return Err(ParseError::TooLong);
    }

    let version = data[0];
    if version != PROTOCOL_VERSION {
        return Err(ParseError::InvalidVersion(version));
    }

    let algo =
        HashAlgorithm::from_byte(data[1]).ok_or(ParseError::InvalidHashAlgorithm(data[1]))?;

    let digest_length = data[2];
    let expected_length = algo.digest_length();
    if digest_length != expected_length {
        return Err(ParseError::DigestLengthMismatch {
            declared: digest_length,
            expected: expected_length,
        });
    }

    let digest_end = 3 + digest_length as usize;
    if data.len() < digest_end {
        return Err(ParseError::DigestTruncated);
    }
    let digest = data[3..digest_end].to_vec();

    if data.len() < digest_end + 1 {
        return Err(ParseError::TooShort);
    }

    let has_nonce = data[digest_end];
    let nonce = match has_nonce {
        0x00 => {
            if data.len() != digest_end + 1 {
                return Err(ParseError::TrailingData);
            }
            None
        }
        0x01 => {
            if data.len() < digest_end + 2 {
                return Err(ParseError::TooShort);
            }
            let nonce_length = data[digest_end + 1];
            if nonce_length > MAX_NONCE_LENGTH {
                return Err(ParseError::NonceTooLong(nonce_length));
            }
            let nonce_end = digest_end + 2 + nonce_length as usize;
            if data.len() < nonce_end {
                return Err(ParseError::NonceTruncated);
            }
            if data.len() != nonce_end {
                return Err(ParseError::TrailingData);
            }
            Some(data[digest_end + 2..nonce_end].to_vec())
        }
        other => return Err(ParseError::InvalidNonceFlag(other)),
    };

    Ok(SignRequest {
        hash_algorithm: algo,
        digest,
        nonce,
    })
}

/// Serialize a sign response to send back to the wrapper.
pub fn serialize_response(resp: &SignResponse) -> Vec<u8> {
    let total = 1
        + 1
        + 4
        + resp.tstinfo_der.len()
        + 4
        + resp.signed_attrs_der.len()
        + 4
        + resp.signature.len();
    let mut buf = Vec::with_capacity(total);

    buf.push(PROTOCOL_VERSION);
    buf.push(resp.status as u8);

    buf.extend_from_slice(&(resp.tstinfo_der.len() as u32).to_be_bytes());
    buf.extend_from_slice(&resp.tstinfo_der);

    buf.extend_from_slice(&(resp.signed_attrs_der.len() as u32).to_be_bytes());
    buf.extend_from_slice(&resp.signed_attrs_der);

    buf.extend_from_slice(&(resp.signature.len() as u32).to_be_bytes());
    buf.extend_from_slice(&resp.signature);

    buf
}

/// Serialize an error response (no payload).
pub fn serialize_error_response(status: ResponseStatus) -> Vec<u8> {
    serialize_response(&SignResponse {
        status,
        tstinfo_der: Vec::new(),
        signed_attrs_der: Vec::new(),
        signature: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_sha256_no_nonce() {
        let mut req = vec![0x01, 0x01, 32];
        req.extend_from_slice(&[0xAA; 32]);
        req.push(0x00); // no nonce

        let parsed = parse_request(&req).unwrap();
        assert_eq!(parsed.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(parsed.digest.len(), 32);
        assert!(parsed.nonce.is_none());
    }

    #[test]
    fn parse_valid_sha384_with_nonce() {
        let mut req = vec![0x01, 0x02, 48];
        req.extend_from_slice(&[0xBB; 48]);
        req.push(0x01); // has nonce
        req.push(16); // nonce length
        req.extend_from_slice(&[0xCC; 16]);

        let parsed = parse_request(&req).unwrap();
        assert_eq!(parsed.hash_algorithm, HashAlgorithm::Sha384);
        assert_eq!(parsed.digest.len(), 48);
        assert_eq!(parsed.nonce.as_ref().unwrap().len(), 16);
    }

    #[test]
    fn parse_valid_sha512_no_nonce() {
        let mut req = vec![0x01, 0x03, 64];
        req.extend_from_slice(&[0xDD; 64]);
        req.push(0x00);

        let parsed = parse_request(&req).unwrap();
        assert_eq!(parsed.hash_algorithm, HashAlgorithm::Sha512);
        assert_eq!(parsed.digest.len(), 64);
    }

    #[test]
    fn reject_invalid_version() {
        let mut req = vec![0x02, 0x01, 32];
        req.extend_from_slice(&[0x00; 32]);
        req.push(0x00);
        assert_eq!(parse_request(&req), Err(ParseError::InvalidVersion(0x02)));
    }

    #[test]
    fn reject_invalid_algorithm() {
        let req = vec![0x01, 0x04, 32];
        assert_eq!(
            parse_request(&req),
            Err(ParseError::InvalidHashAlgorithm(0x04))
        );
    }

    #[test]
    fn reject_digest_length_mismatch() {
        let req = vec![0x01, 0x01, 48]; // SHA-256 but length=48
        assert_eq!(
            parse_request(&req),
            Err(ParseError::DigestLengthMismatch {
                declared: 48,
                expected: 32
            })
        );
    }

    #[test]
    fn reject_truncated() {
        let req = vec![0x01, 0x01, 32, 0x00, 0x00]; // only 2 digest bytes
        assert_eq!(parse_request(&req), Err(ParseError::DigestTruncated));
    }

    #[test]
    fn reject_nonce_too_long() {
        let mut req = vec![0x01, 0x01, 32];
        req.extend_from_slice(&[0x00; 32]);
        req.push(0x01);
        req.push(33); // exceeds MAX_NONCE_LENGTH
        assert_eq!(parse_request(&req), Err(ParseError::NonceTooLong(33)));
    }

    #[test]
    fn reject_trailing_data() {
        let mut req = vec![0x01, 0x01, 32];
        req.extend_from_slice(&[0x00; 32]);
        req.push(0x00);
        req.push(0xFF); // trailing byte
        assert_eq!(parse_request(&req), Err(ParseError::TrailingData));
    }

    #[test]
    fn roundtrip_response() {
        let resp = SignResponse {
            status: ResponseStatus::Success,
            tstinfo_der: vec![1, 2, 3],
            signed_attrs_der: vec![4, 5],
            signature: vec![6, 7, 8, 9],
        };
        let bytes = serialize_response(&resp);
        assert_eq!(bytes[0], 0x01); // version
        assert_eq!(bytes[1], 0x00); // success
        assert_eq!(
            u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            3
        ); // tstinfo len
        assert_eq!(&bytes[6..9], &[1, 2, 3]); // tstinfo
    }

    #[test]
    fn error_response_has_empty_payloads() {
        let bytes = serialize_error_response(ResponseStatus::InvalidRequest);
        assert_eq!(bytes[1], 0x01); // invalid request status
                                    // All three length fields should be zero
        assert_eq!(
            u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            0
        );
        assert_eq!(
            u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
            0
        );
        assert_eq!(
            u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
            0
        );
    }
}
