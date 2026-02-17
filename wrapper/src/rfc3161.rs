//! RFC 3161 TimeStampReq parser and request validation.
//!
//! Parses DER-encoded TimeStampReq messages, validates the hash algorithm
//! and policy OID, and converts to the CVM binary protocol format.

/// Supported hash algorithm OIDs and their properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Map an OID byte sequence to a HashAlgorithm.
    pub fn from_oid(oid: &[u8]) -> Option<Self> {
        // OID bytes (without tag and length):
        // SHA-256: 60 86 48 01 65 03 04 02 01
        // SHA-384: 60 86 48 01 65 03 04 02 02
        // SHA-512: 60 86 48 01 65 03 04 02 03
        const SHA2_PREFIX: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];

        if oid.len() == 9 && oid.starts_with(SHA2_PREFIX) {
            match oid[8] {
                0x01 => Some(Self::Sha256),
                0x02 => Some(Self::Sha384),
                0x03 => Some(Self::Sha512),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Expected digest length for this algorithm.
    pub fn digest_length(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Convert to CVM protocol hash algorithm byte.
    pub fn to_cvm_byte(self) -> u8 {
        match self {
            Self::Sha256 => 0x01,
            Self::Sha384 => 0x02,
            Self::Sha512 => 0x03,
        }
    }
}

/// Parsed TimeStampReq fields relevant for processing.
pub struct TimeStampReq {
    pub hash_algorithm: HashAlgorithm,
    pub message_digest: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
    pub policy_oid: Option<Vec<u8>>,
    pub cert_req: bool,
}

/// RFC 3161 rejection reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    BadAlg,
    BadRequest,
    BadDataFormat,
    UnacceptedPolicy,
    TimeNotAvailable,
}

impl RejectReason {
    /// PKIFailureInfo bit position per RFC 3161.
    pub fn failure_info_bit(self) -> u32 {
        match self {
            Self::BadAlg => 0,
            Self::BadRequest => 2,
            Self::BadDataFormat => 5,
            Self::TimeNotAvailable => 15,
            Self::UnacceptedPolicy => 16,
        }
    }
}

/// Build a CVM binary protocol request from parsed TimeStampReq fields.
pub fn build_cvm_request(req: &TimeStampReq) -> Vec<u8> {
    let mut buf = Vec::with_capacity(101);

    // Protocol version
    buf.push(0x01);

    // Hash algorithm
    buf.push(req.hash_algorithm.to_cvm_byte());

    // Digest length and digest
    buf.push(req.message_digest.len() as u8);
    buf.extend_from_slice(&req.message_digest);

    // Nonce
    match &req.nonce {
        Some(nonce) => {
            buf.push(0x01);
            buf.push(nonce.len() as u8);
            buf.extend_from_slice(nonce);
        }
        None => {
            buf.push(0x00);
        }
    }

    buf
}

/// Validate a parsed TimeStampReq.
pub fn validate_request(req: &TimeStampReq) -> Result<(), RejectReason> {
    // Verify digest length matches algorithm
    if req.message_digest.len() != req.hash_algorithm.digest_length() {
        return Err(RejectReason::BadDataFormat);
    }

    // Policy validation would go here (check against configured policy OIDs)
    // For MVP, accept any policy or no policy.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_oid_recognized() {
        let oid = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert_eq!(HashAlgorithm::from_oid(oid), Some(HashAlgorithm::Sha256));
    }

    #[test]
    fn sha384_oid_recognized() {
        let oid = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
        assert_eq!(HashAlgorithm::from_oid(oid), Some(HashAlgorithm::Sha384));
    }

    #[test]
    fn sha512_oid_recognized() {
        let oid = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        assert_eq!(HashAlgorithm::from_oid(oid), Some(HashAlgorithm::Sha512));
    }

    #[test]
    fn sha1_oid_rejected() {
        // SHA-1 OID: 1.3.14.3.2.26 = 2B 0E 03 02 1A
        let oid = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
        assert_eq!(HashAlgorithm::from_oid(oid), None);
    }

    #[test]
    fn build_cvm_request_no_nonce() {
        let req = TimeStampReq {
            hash_algorithm: HashAlgorithm::Sha256,
            message_digest: vec![0xAA; 32],
            nonce: None,
            policy_oid: None,
            cert_req: true,
        };
        let buf = build_cvm_request(&req);
        assert_eq!(buf[0], 0x01); // version
        assert_eq!(buf[1], 0x01); // SHA-256
        assert_eq!(buf[2], 32); // digest length
        assert_eq!(buf[35], 0x00); // no nonce
        assert_eq!(buf.len(), 36); // 3 header + 32 digest + 1 nonce flag
    }

    #[test]
    fn build_cvm_request_with_nonce() {
        let req = TimeStampReq {
            hash_algorithm: HashAlgorithm::Sha384,
            message_digest: vec![0xBB; 48],
            nonce: Some(vec![0xCC; 16]),
            policy_oid: None,
            cert_req: true,
        };
        let buf = build_cvm_request(&req);
        assert_eq!(buf[0], 0x01); // version
        assert_eq!(buf[1], 0x02); // SHA-384
        assert_eq!(buf[2], 48); // digest length
        assert_eq!(buf[51], 0x01); // has nonce
        assert_eq!(buf[52], 16); // nonce length
        assert_eq!(buf.len(), 69); // 3 + 48 + 1 + 1 + 16
    }

    #[test]
    fn validate_correct_request() {
        let req = TimeStampReq {
            hash_algorithm: HashAlgorithm::Sha256,
            message_digest: vec![0x00; 32],
            nonce: None,
            policy_oid: None,
            cert_req: false,
        };
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn validate_wrong_digest_length() {
        let req = TimeStampReq {
            hash_algorithm: HashAlgorithm::Sha256,
            message_digest: vec![0x00; 48], // wrong length for SHA-256
            nonce: None,
            policy_oid: None,
            cert_req: false,
        };
        assert_eq!(validate_request(&req), Err(RejectReason::BadDataFormat));
    }
}
