/// Template-based DER encoder for RFC 3161 TSTInfo structures.
///
/// Constructs TSTInfo without an ASN.1 library by filling variable fields
/// into a known DER structure. All fixed fields are pre-computed constants.

use crate::protocol::HashAlgorithm;

// ASN.1 tags
const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_CONTEXT_0: u8 = 0xA0; // [0] EXPLICIT for tsa GeneralName

// TSTInfo.version = 1
const VERSION_V1: &[u8] = &[TAG_INTEGER, 0x01, 0x01];

// CC-TSA policy OID: 1.3.6.1.4.1.0.1 (placeholder — to be assigned)
// Encoded: 06 07 2B 06 01 04 01 00 01
const POLICY_OID: &[u8] = &[TAG_OID, 0x07, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x00, 0x01];

// Accuracy: SEQUENCE { INTEGER 1 } => {seconds: 1}
// 30 03 02 01 01
const ACCURACY: &[u8] = &[TAG_SEQUENCE, 0x03, TAG_INTEGER, 0x01, 0x01];

// TSA GeneralName (placeholder directoryName)
// [0] EXPLICIT SEQUENCE { SET { SEQUENCE { OID(commonName), UTF8String "CC-TSA" } } }
// This is a simplified placeholder — real deployment would use the certificate's subject DN.
const TSA_NAME: &[u8] = &[
    TAG_CONTEXT_0, 0x15, // [0] EXPLICIT, length 21
    TAG_SEQUENCE, 0x13, // SEQUENCE
    0x31, 0x11, // SET
    TAG_SEQUENCE, 0x0F, // SEQUENCE
    TAG_OID, 0x03, 0x55, 0x04, 0x03, // OID: commonName (2.5.4.3)
    0x0C, 0x06, // UTF8String, length 6
    b'C', b'C', b'-', b'T', b'S', b'A',
];

/// AlgorithmIdentifier DER bytes for each supported hash algorithm.
impl HashAlgorithm {
    /// Returns the DER-encoded AlgorithmIdentifier for the MessageImprint.
    /// SEQUENCE { OID, NULL }
    pub fn algorithm_identifier_der(self) -> &'static [u8] {
        match self {
            // SHA-256: 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00
            HashAlgorithm::Sha256 => &[
                TAG_SEQUENCE, 0x0D,
                TAG_OID, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                0x05, 0x00, // NULL
            ],
            // SHA-384: 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00
            HashAlgorithm::Sha384 => &[
                TAG_SEQUENCE, 0x0D,
                TAG_OID, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
                0x05, 0x00,
            ],
            // SHA-512: 30 0D 06 09 60 86 48 01 65 03 04 02 03 05 00
            HashAlgorithm::Sha512 => &[
                TAG_SEQUENCE, 0x0D,
                TAG_OID, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                0x05, 0x00,
            ],
        }
    }
}

/// Encode a DER length field into the buffer.
/// Returns the number of bytes written.
pub fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        // TSTInfo will never exceed 64KB
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Encode a u64 as an ASN.1 INTEGER.
/// Handles leading zero byte for positive integers whose MSB is set.
pub fn encode_der_integer_u64(buf: &mut Vec<u8>, value: u64) {
    buf.push(TAG_INTEGER);

    if value == 0 {
        buf.push(0x01);
        buf.push(0x00);
        return;
    }

    // Find the minimal encoding
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7 && bytes[start] == 0 {
        start += 1;
    }

    // Need leading zero if MSB of first significant byte is set
    let needs_leading_zero = bytes[start] & 0x80 != 0;
    let len = 8 - start + if needs_leading_zero { 1 } else { 0 };

    buf.push(len as u8);
    if needs_leading_zero {
        buf.push(0x00);
    }
    buf.extend_from_slice(&bytes[start..]);
}

/// Encode raw bytes as an ASN.1 INTEGER (for nonce values).
/// Ensures proper leading-zero handling.
pub fn encode_der_integer_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    buf.push(TAG_INTEGER);

    if value.is_empty() {
        buf.push(0x01);
        buf.push(0x00);
        return;
    }

    // Skip leading zeros
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }

    let needs_leading_zero = value[start] & 0x80 != 0;
    let len = value.len() - start + if needs_leading_zero { 1 } else { 0 };

    encode_der_length(buf, len);
    if needs_leading_zero {
        buf.push(0x00);
    }
    buf.extend_from_slice(&value[start..]);
}

/// Build a DER-encoded MessageImprint SEQUENCE.
fn encode_message_imprint(buf: &mut Vec<u8>, algo: HashAlgorithm, digest: &[u8]) {
    let algo_der = algo.algorithm_identifier_der();
    // OCTET STRING header: tag + length + digest
    let octet_string_len = 1 + 1 + digest.len(); // tag + length-byte + content
    let inner_len = algo_der.len() + octet_string_len;

    buf.push(TAG_SEQUENCE);
    encode_der_length(buf, inner_len);
    buf.extend_from_slice(algo_der);
    buf.push(TAG_OCTET_STRING);
    buf.push(digest.len() as u8);
    buf.extend_from_slice(digest);
}

/// Encode a GeneralizedTime value.
/// Format: "YYYYMMDDHHMMSS.mmmZ" (19 bytes).
fn encode_generalized_time(buf: &mut Vec<u8>, time_str: &[u8; 19]) {
    buf.push(TAG_GENERALIZED_TIME);
    buf.push(19);
    buf.extend_from_slice(time_str);
}

/// Parameters for building a TSTInfo.
pub struct TstInfoParams<'a> {
    pub hash_algorithm: HashAlgorithm,
    pub digest: &'a [u8],
    pub serial_number: u64,
    /// GeneralizedTime as "YYYYMMDDHHMMSS.mmmZ" (exactly 19 bytes).
    pub gen_time: [u8; 19],
    /// Optional nonce bytes (from client request).
    pub nonce: Option<&'a [u8]>,
}

/// Build a DER-encoded TSTInfo structure.
///
/// TSTInfo ::= SEQUENCE {
///     version         INTEGER { v1(1) },
///     policy          OBJECT IDENTIFIER,
///     messageImprint  MessageImprint,
///     serialNumber    INTEGER,
///     genTime         GeneralizedTime,
///     accuracy        Accuracy        OPTIONAL,
///     ordering        BOOLEAN         DEFAULT FALSE,  -- omitted per DER
///     nonce           INTEGER         OPTIONAL,
///     tsa             [0] GeneralName OPTIONAL,
/// }
pub fn build_tstinfo(params: &TstInfoParams) -> Vec<u8> {
    // First, build all the inner content to compute the outer SEQUENCE length.
    let mut inner = Vec::with_capacity(256);

    // version
    inner.extend_from_slice(VERSION_V1);

    // policy OID
    inner.extend_from_slice(POLICY_OID);

    // messageImprint
    encode_message_imprint(&mut inner, params.hash_algorithm, params.digest);

    // serialNumber
    encode_der_integer_u64(&mut inner, params.serial_number);

    // genTime
    encode_generalized_time(&mut inner, &params.gen_time);

    // accuracy
    inner.extend_from_slice(ACCURACY);

    // ordering: DEFAULT FALSE — omitted per DER

    // nonce (optional)
    if let Some(nonce_bytes) = params.nonce {
        encode_der_integer_bytes(&mut inner, nonce_bytes);
    }

    // tsa GeneralName
    inner.extend_from_slice(TSA_NAME);

    // Wrap in outer SEQUENCE
    let mut result = Vec::with_capacity(inner.len() + 4);
    result.push(TAG_SEQUENCE);
    encode_der_length(&mut result, inner.len());
    result.extend_from_slice(&inner);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_length_short() {
        let mut buf = Vec::new();
        encode_der_length(&mut buf, 50);
        assert_eq!(buf, vec![50]);
    }

    #[test]
    fn encode_length_medium() {
        let mut buf = Vec::new();
        encode_der_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);
    }

    #[test]
    fn encode_length_long() {
        let mut buf = Vec::new();
        encode_der_length(&mut buf, 300);
        assert_eq!(buf, vec![0x82, 0x01, 0x2C]);
    }

    #[test]
    fn encode_integer_zero() {
        let mut buf = Vec::new();
        encode_der_integer_u64(&mut buf, 0);
        assert_eq!(buf, vec![TAG_INTEGER, 0x01, 0x00]);
    }

    #[test]
    fn encode_integer_small() {
        let mut buf = Vec::new();
        encode_der_integer_u64(&mut buf, 42);
        assert_eq!(buf, vec![TAG_INTEGER, 0x01, 42]);
    }

    #[test]
    fn encode_integer_needs_leading_zero() {
        let mut buf = Vec::new();
        encode_der_integer_u64(&mut buf, 128); // 0x80 — needs leading zero
        assert_eq!(buf, vec![TAG_INTEGER, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn encode_integer_max_u64() {
        let mut buf = Vec::new();
        encode_der_integer_u64(&mut buf, u64::MAX);
        // u64::MAX = 0xFFFFFFFFFFFFFFFF, needs leading zero
        assert_eq!(buf.len(), 2 + 9); // tag + length + 9 value bytes
        assert_eq!(buf[0], TAG_INTEGER);
        assert_eq!(buf[1], 9);
        assert_eq!(buf[2], 0x00); // leading zero
    }

    #[test]
    fn encode_integer_bytes_with_leading_zero() {
        let mut buf = Vec::new();
        encode_der_integer_bytes(&mut buf, &[0x80, 0x01]);
        assert_eq!(buf[0], TAG_INTEGER);
        assert_eq!(buf[1], 3); // length: leading zero + 2 bytes
        assert_eq!(buf[2], 0x00); // leading zero
        assert_eq!(&buf[3..5], &[0x80, 0x01]);
    }

    #[test]
    fn build_tstinfo_without_nonce() {
        let params = TstInfoParams {
            hash_algorithm: HashAlgorithm::Sha256,
            digest: &[0xAA; 32],
            serial_number: 1,
            gen_time: *b"20260215120000.000Z",
            nonce: None,
        };
        let der = build_tstinfo(&params);
        // Verify it starts with SEQUENCE tag
        assert_eq!(der[0], TAG_SEQUENCE);
        // Verify version INTEGER 1 is present
        assert_eq!(&der[2..5], VERSION_V1);
    }

    #[test]
    fn build_tstinfo_with_nonce() {
        let params = TstInfoParams {
            hash_algorithm: HashAlgorithm::Sha384,
            digest: &[0xBB; 48],
            serial_number: 1000,
            gen_time: *b"20260215153045.123Z",
            nonce: Some(&[0x01, 0x02, 0x03, 0x04]),
        };
        let der = build_tstinfo(&params);
        assert_eq!(der[0], TAG_SEQUENCE);
        // Nonce should be present — the DER output should be longer than without nonce
        let params_no_nonce = TstInfoParams {
            nonce: None,
            ..TstInfoParams {
                hash_algorithm: HashAlgorithm::Sha384,
                digest: &[0xBB; 48],
                serial_number: 1000,
                gen_time: *b"20260215153045.123Z",
                nonce: None,
            }
        };
        let der_no_nonce = build_tstinfo(&params_no_nonce);
        assert!(der.len() > der_no_nonce.len());
    }

    #[test]
    fn tstinfo_starts_with_valid_sequence() {
        let params = TstInfoParams {
            hash_algorithm: HashAlgorithm::Sha256,
            digest: &[0x00; 32],
            serial_number: 0,
            gen_time: *b"20260101000000.000Z",
            nonce: None,
        };
        let der = build_tstinfo(&params);

        // Verify outer SEQUENCE tag and that declared length matches actual content
        assert_eq!(der[0], TAG_SEQUENCE);
        let (content_len, header_len) = if der[1] < 0x80 {
            (der[1] as usize, 2)
        } else if der[1] == 0x81 {
            (der[2] as usize, 3)
        } else {
            (((der[2] as usize) << 8) | der[3] as usize, 4)
        };
        assert_eq!(der.len(), header_len + content_len);
    }
}
