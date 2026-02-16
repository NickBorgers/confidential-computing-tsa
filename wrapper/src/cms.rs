/// CMS SignedData assembly from CVM response.
///
/// Takes the TSTInfo DER, signedAttrs DER, and ECDSA signature from the CVM,
/// combines them with certificates, and produces a complete CMS SignedData
/// structure suitable for wrapping in a TimeStampResp.
///
/// This module uses a proper ASN.1 library (rasn) since it runs outside the CVM
/// and can be updated independently.

use sha2::{Sha384, Digest};

// CMS OIDs
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]; // 1.2.840.113549.1.7.2
const OID_CT_TSTINFO: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04]; // 1.2.840.113549.1.9.16.1.4
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]; // 1.2.840.10045.4.3.3
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]; // 2.16.840.1.101.3.4.2.2

/// Configuration for CMS assembly.
pub struct CmsConfig {
    /// DER-encoded TSA signing certificate (ECDSA P-384).
    pub ecdsa_cert_der: Vec<u8>,
    /// DER-encoded CA certificate chain.
    pub ca_chain_der: Vec<Vec<u8>>,
    /// Issuer and serial number from the ECDSA certificate (for SignerInfo.sid).
    pub issuer_der: Vec<u8>,
    pub serial_number_der: Vec<u8>,
}

/// Components from the CVM response needed for CMS assembly.
pub struct CvmComponents {
    pub tstinfo_der: Vec<u8>,
    pub signed_attrs_der: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Build a CMS SignedData structure from CVM components.
///
/// The output is the complete ContentInfo wrapping SignedData,
/// ready to be placed in a TimeStampResp.timeStampToken.
///
/// Structure:
/// ContentInfo {
///   contentType: id-signedData,
///   content: SignedData {
///     version: 3,
///     digestAlgorithms: { SHA-384 },
///     encapContentInfo: { id-ct-TSTInfo, TSTInfo },
///     certificates: [0] { ecdsa_cert, ca_chain... },
///     signerInfos: { SignerInfo { ... ECDSA P-384 ... } }
///   }
/// }
pub fn build_signed_data(config: &CmsConfig, components: &CvmComponents) -> Vec<u8> {
    let mut signed_data_content = Vec::with_capacity(4096);

    // version: 3 (because eContentType is not id-data)
    // INTEGER 3: 02 01 03
    signed_data_content.extend_from_slice(&[0x02, 0x01, 0x03]);

    // digestAlgorithms: SET OF { AlgorithmIdentifier SHA-384 }
    // SET { SEQUENCE { OID SHA-384, NULL } }
    let sha384_algo_id = build_algorithm_identifier(OID_SHA384);
    let mut digest_algos = Vec::new();
    write_tag_length_value(&mut digest_algos, 0x31, &sha384_algo_id);
    signed_data_content.extend_from_slice(&digest_algos);

    // encapContentInfo: SEQUENCE { eContentType, eContent }
    let encap = build_encap_content_info(&components.tstinfo_der);
    signed_data_content.extend_from_slice(&encap);

    // certificates [0] IMPLICIT SET OF Certificate
    let mut all_certs = Vec::new();
    all_certs.extend_from_slice(&config.ecdsa_cert_der);
    for ca_cert in &config.ca_chain_der {
        all_certs.extend_from_slice(ca_cert);
    }
    let mut certs_tagged = Vec::new();
    write_tag_length_value(&mut certs_tagged, 0xA0, &all_certs);
    signed_data_content.extend_from_slice(&certs_tagged);

    // signerInfos: SET OF SignerInfo
    let signer_info = build_signer_info(
        &config.issuer_der,
        &config.serial_number_der,
        &components.signed_attrs_der,
        &components.signature,
    );
    let mut signer_infos = Vec::new();
    write_tag_length_value(&mut signer_infos, 0x31, &signer_info);
    signed_data_content.extend_from_slice(&signer_infos);

    // Wrap in SignedData SEQUENCE
    let mut signed_data = Vec::new();
    write_tag_length_value(&mut signed_data, 0x30, &signed_data_content);

    // Wrap in ContentInfo
    let mut content_info_content = Vec::new();
    // contentType: id-signedData
    write_tag_length_value(&mut content_info_content, 0x06, OID_SIGNED_DATA);
    // content [0] EXPLICIT SignedData
    write_tag_length_value(&mut content_info_content, 0xA0, &signed_data);

    let mut result = Vec::new();
    write_tag_length_value(&mut result, 0x30, &content_info_content);

    result
}

fn build_algorithm_identifier(oid_bytes: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    write_tag_length_value(&mut inner, 0x06, oid_bytes);
    inner.extend_from_slice(&[0x05, 0x00]); // NULL parameters
    let mut result = Vec::new();
    write_tag_length_value(&mut result, 0x30, &inner);
    result
}

fn build_encap_content_info(tstinfo_der: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    // eContentType: id-ct-TSTInfo
    write_tag_length_value(&mut inner, 0x06, OID_CT_TSTINFO);
    // eContent [0] EXPLICIT OCTET STRING
    let mut octet_string = Vec::new();
    write_tag_length_value(&mut octet_string, 0x04, tstinfo_der);
    write_tag_length_value(&mut inner, 0xA0, &octet_string);

    let mut result = Vec::new();
    write_tag_length_value(&mut result, 0x30, &inner);
    result
}

fn build_signer_info(
    issuer_der: &[u8],
    serial_number_der: &[u8],
    signed_attrs_der: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut inner = Vec::new();

    // version: 1
    inner.extend_from_slice(&[0x02, 0x01, 0x01]);

    // sid: IssuerAndSerialNumber SEQUENCE
    let mut sid = Vec::new();
    sid.extend_from_slice(issuer_der);
    sid.extend_from_slice(serial_number_der);
    write_tag_length_value(&mut inner, 0x30, &sid);

    // digestAlgorithm: SHA-384
    let digest_algo = build_algorithm_identifier(OID_SHA384);
    inner.extend_from_slice(&digest_algo);

    // signedAttrs [0] IMPLICIT SET OF
    // The CVM provides signedAttrs with SET tag (0x31).
    // For SignerInfo, we need to re-tag as [0] IMPLICIT (0xA0).
    if !signed_attrs_der.is_empty() {
        let mut retagged = signed_attrs_der.to_vec();
        if retagged[0] == 0x31 {
            retagged[0] = 0xA0; // re-tag from SET to [0] IMPLICIT
        }
        inner.extend_from_slice(&retagged);
    }

    // signatureAlgorithm: ecdsa-with-SHA384
    let sig_algo = build_algorithm_identifier(OID_ECDSA_SHA384);
    inner.extend_from_slice(&sig_algo);

    // signature: OCTET STRING
    write_tag_length_value(&mut inner, 0x04, signature);

    let mut result = Vec::new();
    write_tag_length_value(&mut result, 0x30, &inner);
    result
}

/// Write a DER TLV (tag-length-value) to a buffer.
fn write_tag_length_value(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    buf.push(tag);
    let len = value.len();
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
    buf.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_identifier_structure() {
        let algo_id = build_algorithm_identifier(OID_SHA384);
        assert_eq!(algo_id[0], 0x30); // SEQUENCE
        // Should contain OID + NULL
    }

    #[test]
    fn encap_content_info_structure() {
        let tstinfo = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // minimal SEQUENCE
        let encap = build_encap_content_info(&tstinfo);
        assert_eq!(encap[0], 0x30); // outer SEQUENCE
    }

    #[test]
    fn build_signed_data_produces_content_info() {
        let config = CmsConfig {
            ecdsa_cert_der: vec![0x30, 0x03, 0x02, 0x01, 0x01], // stub cert
            ca_chain_der: vec![],
            issuer_der: vec![0x30, 0x03, 0x0C, 0x01, 0x41], // stub issuer
            serial_number_der: vec![0x02, 0x01, 0x01], // serial 1
        };
        let components = CvmComponents {
            tstinfo_der: vec![0x30, 0x03, 0x02, 0x01, 0x01],
            signed_attrs_der: vec![0x31, 0x03, 0x02, 0x01, 0x01],
            signature: vec![0x00; 96],
        };
        let result = build_signed_data(&config, &components);
        assert_eq!(result[0], 0x30); // outer ContentInfo SEQUENCE
    }

    #[test]
    fn write_tlv_short_length() {
        let mut buf = Vec::new();
        write_tag_length_value(&mut buf, 0x04, &[0x01, 0x02, 0x03]);
        assert_eq!(buf, vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn write_tlv_long_length() {
        let mut buf = Vec::new();
        let data = vec![0x00; 200];
        write_tag_length_value(&mut buf, 0x04, &data);
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf[1], 0x81);
        assert_eq!(buf[2], 200);
    }
}
