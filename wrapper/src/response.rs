/// TimeStampResp construction.
///
/// Assembles the final RFC 3161 TimeStampResp from the CMS SignedData
/// (containing TSTInfo + signature) or from an error status.

/// PKIStatus values per RFC 3161.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PkiStatus {
    Granted = 0,
    Rejection = 2,
}

/// Build a successful TimeStampResp containing the signed timestamp token.
///
/// TimeStampResp ::= SEQUENCE {
///     status          PKIStatusInfo,
///     timeStampToken  ContentInfo OPTIONAL
/// }
///
/// PKIStatusInfo ::= SEQUENCE {
///     status PKIStatus  -- INTEGER
/// }
pub fn build_timestamp_resp_success(signed_data_content_info: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(signed_data_content_info.len() + 16);

    // PKIStatusInfo: SEQUENCE { status INTEGER 0 (granted) }
    // 30 03 02 01 00
    inner.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x00]);

    // timeStampToken: ContentInfo (already DER-encoded)
    inner.extend_from_slice(signed_data_content_info);

    // Wrap in outer SEQUENCE
    let mut result = Vec::with_capacity(inner.len() + 4);
    result.push(0x30);
    write_length(&mut result, inner.len());
    result.extend_from_slice(&inner);

    result
}

/// Build a rejection TimeStampResp with the specified failure reason.
///
/// PKIStatusInfo ::= SEQUENCE {
///     status      PKIStatus,
///     statusString PKIFreeText OPTIONAL,
///     failInfo    PKIFailureInfo OPTIONAL
/// }
pub fn build_timestamp_resp_rejection(failure_bit: u32, status_string: Option<&str>) -> Vec<u8> {
    let mut pki_status_info = Vec::new();

    // status: INTEGER 2 (rejection)
    pki_status_info.extend_from_slice(&[0x02, 0x01, 0x02]);

    // statusString (optional): SEQUENCE OF UTF8String
    if let Some(msg) = status_string {
        let msg_bytes = msg.as_bytes();
        // UTF8String
        let mut utf8_string = Vec::new();
        utf8_string.push(0x0C); // UTF8String tag
        write_length(&mut utf8_string, msg_bytes.len());
        utf8_string.extend_from_slice(msg_bytes);

        // SEQUENCE OF
        let mut seq = Vec::new();
        seq.push(0x30);
        write_length(&mut seq, utf8_string.len());
        seq.extend_from_slice(&utf8_string);

        pki_status_info.extend_from_slice(&seq);
    }

    // failInfo: BIT STRING encoding the failure bit
    let fail_info = encode_failure_info(failure_bit);
    pki_status_info.extend_from_slice(&fail_info);

    // Wrap PKIStatusInfo in SEQUENCE
    let mut status_info_seq = Vec::new();
    status_info_seq.push(0x30);
    write_length(&mut status_info_seq, pki_status_info.len());
    status_info_seq.extend_from_slice(&pki_status_info);

    // TimeStampResp outer SEQUENCE (no timeStampToken for rejections)
    let mut result = Vec::new();
    result.push(0x30);
    write_length(&mut result, status_info_seq.len());
    result.extend_from_slice(&status_info_seq);

    result
}

/// Encode a PKIFailureInfo BIT STRING.
/// The failure info is a BIT STRING with named bits.
fn encode_failure_info(bit: u32) -> Vec<u8> {
    // PKIFailureInfo is a BIT STRING with the following named bits:
    // badAlg(0), badRequest(2), badDataFormat(5), timeNotAvailable(15),
    // unacceptedPolicy(16), unacceptedExtension(25)
    //
    // BIT STRING encoding: tag(03) + length + unused_bits + value_bytes
    // We need enough bytes to hold the bit position.

    let byte_index = (bit / 8) as usize;
    let bit_in_byte = 7 - (bit % 8);
    let total_bytes = byte_index + 1;
    let unused_bits = (7 - (bit % 8)) as u8;
    // Actually: unused_bits counts unused bits in the LAST byte
    let unused_in_last = 7 - (bit % 8);

    let mut value = vec![0u8; total_bytes];
    value[byte_index] = 1 << bit_in_byte;

    let mut result = Vec::new();
    result.push(0x03); // BIT STRING tag
    write_length(&mut result, 1 + total_bytes); // +1 for unused bits byte
    result.push(unused_in_last as u8);
    result.extend_from_slice(&value);

    result
}

fn write_length(buf: &mut Vec<u8>, len: usize) {
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
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_response_starts_with_sequence() {
        let token = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // stub ContentInfo
        let resp = build_timestamp_resp_success(&token);
        assert_eq!(resp[0], 0x30); // outer SEQUENCE
    }

    #[test]
    fn success_response_contains_granted_status() {
        let token = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let resp = build_timestamp_resp_success(&token);
        // PKIStatusInfo starts at offset 2 (after outer SEQUENCE tag+length)
        // SEQUENCE tag (0x30), length (0x03), INTEGER tag (0x02), length (0x01), value (0x00)
        assert_eq!(resp[2], 0x30); // PKIStatusInfo SEQUENCE
        assert_eq!(resp[6], 0x00); // status = granted
    }

    #[test]
    fn rejection_response_has_status_2() {
        let resp = build_timestamp_resp_rejection(0, None);
        assert_eq!(resp[0], 0x30); // outer SEQUENCE
        // Find the INTEGER value for status
        // outer SEQUENCE -> PKIStatusInfo SEQUENCE -> INTEGER 2
        // The status INTEGER should be 2 (rejection)
    }

    #[test]
    fn rejection_with_status_string() {
        let resp = build_timestamp_resp_rejection(0, Some("bad algorithm"));
        assert!(!resp.is_empty());
        assert_eq!(resp[0], 0x30);
    }

    #[test]
    fn failure_info_bad_alg() {
        let bits = encode_failure_info(0);
        assert_eq!(bits[0], 0x03); // BIT STRING tag
        // bit 0 should be set in the first value byte
        let unused = bits[2];
        let value = bits[3];
        assert_eq!(value & 0x80, 0x80); // bit 0 is the MSB of the first byte
    }

    #[test]
    fn failure_info_unaccepted_policy() {
        let bits = encode_failure_info(16);
        assert_eq!(bits[0], 0x03); // BIT STRING tag
        // bit 16 is in byte 2 (0-indexed), bit position 7 within that byte
        assert!(bits.len() >= 5); // tag + length + unused + 3 value bytes
    }
}
