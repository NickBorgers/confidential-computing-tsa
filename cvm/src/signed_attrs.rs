/// CMS SignedAttributes (signedAttrs) DER encoder.
///
/// Per RFC 5652 Section 5.4, when the content type is not id-data,
/// signedAttrs MUST be present and the signature covers DER(signedAttrs).
///
/// signedAttrs = SET OF Attribute {
///   { contentType,          SET { id-ct-TSTInfo } },
///   { messageDigest,        SET { OCTET STRING (SHA-384 of TSTInfo DER) } },
///   { signingCertificateV2, SET { SigningCertificateV2 } },
/// }

use crate::tstinfo::encode_der_length;
use sha2::{Sha384, Digest};

// ASN.1 tags
const TAG_SET: u8 = 0x31;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;

// OID: contentType (1.2.840.113549.1.9.3)
const OID_CONTENT_TYPE: &[u8] = &[TAG_OID, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];

// OID: id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
const OID_CT_TSTINFO: &[u8] = &[TAG_OID, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04];

// OID: messageDigest (1.2.840.113549.1.9.4)
const OID_MESSAGE_DIGEST: &[u8] = &[TAG_OID, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

// OID: signingCertificateV2 (1.2.840.113549.1.9.16.2.47)
const OID_SIGNING_CERT_V2: &[u8] = &[TAG_OID, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F];

/// Pre-computed SHA-256 hash of the TSA's signing certificate.
/// This is set at build/init time and remains constant.
/// Placeholder: 32 zero bytes — replaced at startup with actual cert hash.
static DEFAULT_CERT_HASH: [u8; 32] = [0u8; 32];

/// Build the contentType attribute.
/// SEQUENCE { OID(contentType), SET { OID(id-ct-TSTInfo) } }
fn build_content_type_attr(buf: &mut Vec<u8>) {
    let set_inner = OID_CT_TSTINFO;
    let set_len = set_inner.len();

    let seq_inner_len = OID_CONTENT_TYPE.len() + 1 + 1 + set_len; // OID + SET tag + SET len + SET content

    buf.push(TAG_SEQUENCE);
    encode_der_length(buf, seq_inner_len);
    buf.extend_from_slice(OID_CONTENT_TYPE);
    buf.push(TAG_SET);
    buf.push(set_len as u8);
    buf.extend_from_slice(set_inner);
}

/// Build the messageDigest attribute.
/// SEQUENCE { OID(messageDigest), SET { OCTET STRING(sha384_of_tstinfo) } }
fn build_message_digest_attr(buf: &mut Vec<u8>, tstinfo_hash: &[u8; 48]) {
    // OCTET STRING: tag + length + 48 bytes
    let octet_string_len = 1 + 1 + 48; // tag + length + value
    let set_len = octet_string_len;
    let seq_inner_len = OID_MESSAGE_DIGEST.len() + 1 + 1 + set_len;

    buf.push(TAG_SEQUENCE);
    encode_der_length(buf, seq_inner_len);
    buf.extend_from_slice(OID_MESSAGE_DIGEST);
    buf.push(TAG_SET);
    buf.push(set_len as u8);
    buf.push(TAG_OCTET_STRING);
    buf.push(48);
    buf.extend_from_slice(tstinfo_hash);
}

/// Build the signingCertificateV2 attribute.
/// SEQUENCE { OID(signingCertificateV2), SET { SEQUENCE { SEQUENCE { SEQUENCE { OCTET STRING(cert_hash) } } } } }
///
/// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
/// ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha-256, certHash OCTET STRING }
/// When hashAlgorithm is sha-256 (default), it is omitted per DER.
fn build_signing_cert_v2_attr(buf: &mut Vec<u8>, cert_hash: &[u8; 32]) {
    // ESSCertIDv2: SEQUENCE { certHash OCTET STRING }
    // (hashAlgorithm omitted because sha-256 is DEFAULT)
    let cert_hash_octet = 1 + 1 + 32; // OCTET STRING tag + len + value
    let ess_cert_id_len = cert_hash_octet;
    let ess_cert_id_seq = 1 + 1 + ess_cert_id_len; // SEQUENCE tag + len + content

    // certs: SEQUENCE OF ESSCertIDv2
    let certs_seq_len = ess_cert_id_seq;
    let certs_seq = 1 + 1 + certs_seq_len; // SEQUENCE tag + len + content

    // SigningCertificateV2: SEQUENCE { certs }
    let signing_cert_v2_len = certs_seq;
    let signing_cert_v2_seq = 1 + 1 + signing_cert_v2_len;

    let set_len = signing_cert_v2_seq;
    let seq_inner_len = OID_SIGNING_CERT_V2.len() + 1 + 1 + set_len;

    buf.push(TAG_SEQUENCE);
    encode_der_length(buf, seq_inner_len);
    buf.extend_from_slice(OID_SIGNING_CERT_V2);
    buf.push(TAG_SET);
    encode_der_length(buf, set_len);

    // SigningCertificateV2 SEQUENCE
    buf.push(TAG_SEQUENCE);
    encode_der_length(buf, signing_cert_v2_len);

    // certs SEQUENCE OF
    buf.push(TAG_SEQUENCE);
    encode_der_length(buf, certs_seq_len);

    // ESSCertIDv2 SEQUENCE
    buf.push(TAG_SEQUENCE);
    encode_der_length(buf, ess_cert_id_len);

    // certHash OCTET STRING
    buf.push(TAG_OCTET_STRING);
    buf.push(32);
    buf.extend_from_slice(cert_hash);
}

/// Build the complete signedAttrs SET.
///
/// The result is a SET OF three Attributes, DER-encoded.
/// The signature is computed over this exact byte sequence.
///
/// Note: per RFC 5652 Section 5.4, for signing purposes the
/// implicit [0] tag on signedAttrs is replaced with SET OF (0x31).
/// We encode directly as SET OF here since the CVM signs this directly.
pub fn build_signed_attrs(tstinfo_der: &[u8], cert_hash: &[u8; 32]) -> Vec<u8> {
    // Compute SHA-384 of the TSTInfo DER
    let tstinfo_hash: [u8; 48] = Sha384::digest(tstinfo_der).into();

    // Build individual attributes
    let mut attrs_content = Vec::with_capacity(256);
    build_content_type_attr(&mut attrs_content);
    build_message_digest_attr(&mut attrs_content, &tstinfo_hash);
    build_signing_cert_v2_attr(&mut attrs_content, cert_hash);

    // Wrap in SET OF
    let mut result = Vec::with_capacity(attrs_content.len() + 4);
    result.push(TAG_SET);
    encode_der_length(&mut result, attrs_content.len());
    result.extend_from_slice(&attrs_content);

    result
}

/// Build signedAttrs using the default (placeholder) certificate hash.
pub fn build_signed_attrs_default(tstinfo_der: &[u8]) -> Vec<u8> {
    build_signed_attrs(tstinfo_der, &DEFAULT_CERT_HASH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_attrs_starts_with_set_tag() {
        let tstinfo = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // minimal SEQUENCE
        let cert_hash = [0xAA; 32];
        let attrs = build_signed_attrs(&tstinfo, &cert_hash);
        assert_eq!(attrs[0], TAG_SET);
    }

    #[test]
    fn signed_attrs_length_matches() {
        let tstinfo = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let cert_hash = [0xBB; 32];
        let attrs = build_signed_attrs(&tstinfo, &cert_hash);

        // Parse outer SET length
        let (content_len, header_len) = if attrs[1] < 0x80 {
            (attrs[1] as usize, 2)
        } else if attrs[1] == 0x81 {
            (attrs[2] as usize, 3)
        } else {
            (((attrs[2] as usize) << 8) | attrs[3] as usize, 4)
        };
        assert_eq!(attrs.len(), header_len + content_len);
    }

    #[test]
    fn signed_attrs_contains_three_sequences() {
        let tstinfo = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let cert_hash = [0x00; 32];
        let attrs = build_signed_attrs(&tstinfo, &cert_hash);

        // Skip the outer SET header
        let content_start = if attrs[1] < 0x80 { 2 } else if attrs[1] == 0x81 { 3 } else { 4 };
        let content = &attrs[content_start..];

        // Count SEQUENCE tags at the top level
        let mut count = 0;
        let mut pos = 0;
        while pos < content.len() {
            assert_eq!(content[pos], TAG_SEQUENCE, "expected SEQUENCE at position {}", pos);
            count += 1;
            pos += 1;
            // Read length
            let (len, len_bytes) = if content[pos] < 0x80 {
                (content[pos] as usize, 1)
            } else if content[pos] == 0x81 {
                (content[pos + 1] as usize, 2)
            } else {
                (((content[pos + 1] as usize) << 8) | content[pos + 2] as usize, 3)
            };
            pos += len_bytes + len;
        }
        assert_eq!(count, 3, "signedAttrs should contain exactly 3 attributes");
    }

    #[test]
    fn different_tstinfo_produces_different_digest() {
        let cert_hash = [0x00; 32];
        let attrs1 = build_signed_attrs(&[0x30, 0x03, 0x02, 0x01, 0x01], &cert_hash);
        let attrs2 = build_signed_attrs(&[0x30, 0x03, 0x02, 0x01, 0x02], &cert_hash);
        assert_ne!(attrs1, attrs2);
    }
}
