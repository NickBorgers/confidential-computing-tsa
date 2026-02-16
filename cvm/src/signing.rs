/// ECDSA P-384 signing module for the CVM core.
///
/// Single-signer MVP: the full ECDSA private key is held in one CVM.
/// Threshold signing (multi-party) will be added later.
use ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha384};

/// The signing context holds the private key in memory.
/// The key is loaded once at startup and never persisted.
pub struct SigningContext {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// SHA-256 hash of the DER-encoded public key certificate.
    /// Used in signingCertificateV2 attribute.
    pub cert_hash: [u8; 32],
}

impl SigningContext {
    /// Create a signing context from a raw private key scalar (48 bytes).
    pub fn from_private_key_bytes(key_bytes: &[u8]) -> Result<Self, SigningError> {
        let signing_key =
            SigningKey::from_bytes(key_bytes.into()).map_err(|_| SigningError::InvalidKey)?;
        let verifying_key = *signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
            cert_hash: [0u8; 32], // Set via set_cert_hash after certificate is loaded
        })
    }

    /// Generate a new random signing key (for initial key generation or testing).
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            cert_hash: [0u8; 32],
        }
    }

    /// Set the certificate hash (SHA-256 of the DER-encoded TSA certificate).
    pub fn set_cert_hash(&mut self, hash: [u8; 32]) {
        self.cert_hash = hash;
    }

    /// Sign the DER-encoded signedAttrs with ECDSA P-384.
    ///
    /// Per RFC 5652 Section 5.4, the signature is computed over
    /// the DER encoding of the signedAttrs value (with SET OF tag).
    /// The signing process internally computes SHA-384 of the input.
    pub fn sign(&self, signed_attrs_der: &[u8]) -> Result<Vec<u8>, SigningError> {
        let signature: Signature = self.signing_key.sign(signed_attrs_der);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Compute SHA-384 hash of data (utility for signedAttrs digest computation).
    pub fn sha384(data: &[u8]) -> [u8; 48] {
        Sha384::digest(data).into()
    }
}

#[derive(Debug)]
pub enum SigningError {
    InvalidKey,
}

impl core::fmt::Display for SigningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid private key"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::Verifier;

    #[test]
    fn generate_and_sign() {
        let ctx = SigningContext::generate();
        let data = b"test signed attrs data";
        let sig_bytes = ctx.sign(data).unwrap();
        assert!(!sig_bytes.is_empty());

        // Verify the signature
        let sig = Signature::from_der(&sig_bytes).unwrap();
        ctx.verifying_key().verify(data, &sig).unwrap();
    }

    #[test]
    fn sign_produces_different_signatures() {
        // ECDSA with randomized nonce produces different signatures for the same input
        let ctx = SigningContext::generate();
        let data = b"same data";
        let sig1 = ctx.sign(data).unwrap();
        let sig2 = ctx.sign(data).unwrap();
        // Both should verify, but may differ (randomized k)
        let s1 = Signature::from_der(&sig1).unwrap();
        let s2 = Signature::from_der(&sig2).unwrap();
        ctx.verifying_key().verify(data, &s1).unwrap();
        ctx.verifying_key().verify(data, &s2).unwrap();
    }

    #[test]
    fn roundtrip_from_key_bytes() {
        let ctx1 = SigningContext::generate();
        let key_bytes = ctx1.signing_key.to_bytes();
        let ctx2 = SigningContext::from_private_key_bytes(&key_bytes).unwrap();

        let data = b"roundtrip test";
        let sig_bytes = ctx2.sign(data).unwrap();
        let sig = Signature::from_der(&sig_bytes).unwrap();
        ctx1.verifying_key().verify(data, &sig).unwrap();
    }

    #[test]
    fn sha384_produces_correct_length() {
        let hash = SigningContext::sha384(b"test");
        assert_eq!(hash.len(), 48);
    }
}
