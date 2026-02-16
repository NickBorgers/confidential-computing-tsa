# Enclave Interface Specification

> **CC-TSA Design Document 09** | Audience: Engineers, Security Reviewers, Auditors

This document specifies the minimal enclave interface for the CC-TSA Confidential VM (CVM) core:
the binary vsock protocol, the TSTInfo template encoder, signedAttrs construction,
the CVM state machine, and the testing strategy.

The CVM core is designed to be the smallest possible auditable codebase (~670 LOC Rust)
that runs inside the AMD SEV-SNP confidential VM. Any change to this code triggers
a new DKG ceremony and new certificate issuance, because the code is part of the
attestation measurement bound to the TSA certificate.

For the overall system architecture and the rationale for the two-layer split,
see [Architecture Overview](01-architecture-overview.md), Section 2.6.
For RFC 3161 protocol details, see [RFC 3161 Compliance](06-rfc3161-compliance.md).
For the threat model analysis of the wrapper, see [Threat Model](07-threat-model.md), Scenario 7.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Binary Protocol Specification](#2-binary-protocol-specification)
3. [TSTInfo Template Encoder](#3-tstinfo-template-encoder)
4. [SignedAttrs Construction](#4-signedattrs-construction)
5. [CVM State Machine](#5-cvm-state-machine)
6. [Module Inventory](#6-module-inventory)
7. [Testing Strategy](#7-testing-strategy)

---

## 1. Architecture Overview

The CC-TSA uses a two-layer architecture to minimize the code inside the attested CVM:

```
┌─────────────────────────────────────────────────────┐
│  Client (internal network only)                     │
│  Sends: RFC 3161 TimeStampReq over HTTPS            │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│  WRAPPER (outside CVM — updatable)                  │
│                                                     │
│  • HTTP listener, TLS termination                   │
│  • RFC 3161 TimeStampReq ASN.1 parser               │
│  • Request validation (algorithm, policy, nonce)    │
│  • vsock client → calls CVM                         │
│  • CMS SignedData assembly from CVM response        │
│  • TimeStampResp construction                       │
│  • Monitoring, metrics, logging                     │
└──────────────────────┬──────────────────────────────┘
                       │ vsock
┌──────────────────────▼──────────────────────────────┐
│  CVM CORE (inside SEV-SNP VM — immutable, attested) │
│  ~670 LOC Rust                                      │
│                                                     │
│  • vsock listener (simple binary protocol)          │
│  • Input validation (digest length, algorithm enum) │
│  • SecureTSC time read                              │
│  • NTS time validation                              │
│  • Serial number generation (monotonic)             │
│  • TSTInfo DER construction (template-based)        │
│  • signedAttrs DER construction (template-based)    │
│  • ECDSA P-384 signing of signedAttrs               │
│  • Attestation report generation                    │
└─────────────────────────────────────────────────────┘
```

**Design principle**: The CVM core contains only the operations that must be performed
inside the attested enclave — time reading, TSTInfo construction, and signing.
Everything else (HTTP, ASN.1 parsing, CMS assembly) is in the updatable wrapper.

**Security boundary**: The wrapper holds no key material. A compromised wrapper
cannot forge timestamps. See [Threat Model](07-threat-model.md), Scenario 7.

---

## 2. Binary Protocol Specification

The CVM core communicates with the wrapper over AF_VSOCK (port 5000)
using a fixed binary protocol. One request per connection.

### 2.1 Request Format (Wrapper → CVM)

| Offset | Size | Field | Values |
|--------|------|-------|--------|
| 0 | 1 | `version` | `0x01` |
| 1 | 1 | `hash_algorithm` | `0x01`=SHA-256, `0x02`=SHA-384, `0x03`=SHA-512 |
| 2 | 1 | `digest_length` | 32, 48, or 64 (must match algorithm) |
| 3 | N | `digest` | Raw hash bytes (N = digest_length) |
| 3+N | 1 | `has_nonce` | `0x00` (no nonce) or `0x01` (nonce follows) |
| 4+N | 1 | `nonce_length` | 0–32 (only present if has_nonce=0x01) |
| 5+N | M | `nonce` | Raw nonce bytes (M = nonce_length) |

**Maximum request size**: 101 bytes.

**Validation rules** (CVM rejects requests that violate any rule):

- `version` must be `0x01`
- `hash_algorithm` must be `0x01`, `0x02`, or `0x03`
- `digest_length` must match the expected length for the declared algorithm
- `has_nonce` must be `0x00` or `0x01`
- `nonce_length` must be ≤ 32
- No trailing bytes after the last field

### 2.2 Response Format (CVM → Wrapper)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `version` | `0x01` |
| 1 | 1 | `status` | See status codes below |
| 2 | 4 | `tstinfo_length` | Big-endian u32 |
| 6 | T | `tstinfo_der` | DER-encoded TSTInfo |
| 6+T | 4 | `signed_attrs_length` | Big-endian u32 |
| 10+T | A | `signed_attrs_der` | DER-encoded signedAttrs |
| 10+T+A | 4 | `signature_length` | Big-endian u32 |
| 14+T+A | S | `signature` | ECDSA P-384 DER signature |

### 2.3 Status Codes

| Code | Name | Description |
|------|------|-------------|
| `0x00` | Success | All three payload fields are populated |
| `0x01` | InvalidRequest | Request parsing or validation failed; all lengths are zero |
| `0x02` | InternalError | Signing or processing error; all lengths are zero |
| `0x03` | TimeUnavailable | Trusted time source not validated; all lengths are zero |

### 2.4 Design Rationale

The binary protocol is intentionally minimal:

- **No ASN.1**: The CVM never parses ASN.1. All variable-length fields use explicit length bytes.
- **No strings**: All fields are integers or raw byte arrays. No encoding ambiguity.
- **Fixed maximum size**: Bounded at 101 bytes. No memory allocation decisions based on untrusted input.
- **No framing**: One request per vsock connection. No need for message delimiters or multiplexing.

---

## 3. TSTInfo Template Encoder

The CVM builds DER-encoded TSTInfo structures without an ASN.1 library.
Each field is either fixed (pre-computed constant) or variable (filled at signing time).

### 3.1 TSTInfo Field Map

```
TSTInfo ::= SEQUENCE {
    version         INTEGER { v1(1) },       -- FIXED: 02 01 01
    policy          OBJECT IDENTIFIER,       -- FIXED: CC-TSA policy OID
    messageImprint  MessageImprint,          -- VARIABLE: algo OID + digest
    serialNumber    INTEGER,                 -- VARIABLE: monotonic counter
    genTime         GeneralizedTime,         -- VARIABLE: YYYYMMDDHHMMSS.mmmZ
    accuracy        Accuracy,               -- FIXED: {seconds: 1}
    ordering        BOOLEAN DEFAULT FALSE,   -- OMITTED (DER: DEFAULT values are absent)
    nonce           INTEGER OPTIONAL,        -- VARIABLE: from client request
    tsa             [0] GeneralName,         -- FIXED: pre-computed TSA name
}
```

| Field | Type | Size | Implementation |
|-------|------|------|----------------|
| `version` (1) | Fixed | 3 bytes | Constant: `02 01 01` |
| `policy` OID | Fixed | ~9 bytes | Constant: pre-computed at build time |
| `messageImprint` | Variable | ~50-80 bytes | Hash algorithm OID (per-algo constant) + digest OCTET STRING |
| `serialNumber` | Variable | 3-11 bytes | ASN.1 INTEGER encoding of u64 |
| `genTime` | Variable | 21 bytes | GeneralizedTime: `YYYYMMDDHHMMSS.mmmZ` (19 content bytes) |
| `accuracy` | Fixed | 5 bytes | Constant: `30 03 02 01 01` |
| `ordering` | Omitted | 0 bytes | DEFAULT FALSE = absent per DER |
| `nonce` | Variable | 0-36 bytes | Optional ASN.1 INTEGER from client nonce |
| `tsa` | Fixed | ~25 bytes | Constant: pre-computed GeneralName |

### 3.2 DER Helper Functions

The encoder uses four helper functions (~60 LOC total):

- `encode_der_length(buf, len)`: Write a DER length. 1 byte if < 128, multi-byte otherwise.
- `encode_der_integer_u64(buf, value)`: Encode a u64 as ASN.1 INTEGER with leading-zero handling.
- `encode_der_integer_bytes(buf, bytes)`: Encode raw bytes as ASN.1 INTEGER (for nonce values).
- `HashAlgorithm::algorithm_identifier_der()`: Return pre-computed AlgorithmIdentifier bytes per hash algorithm.

### 3.3 Algorithm Identifier Constants

Each supported hash algorithm has a pre-computed DER AlgorithmIdentifier:

| Algorithm | AlgorithmIdentifier DER (hex) |
|-----------|-------------------------------|
| SHA-256 | `30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00` |
| SHA-384 | `30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00` |
| SHA-512 | `30 0D 06 09 60 86 48 01 65 03 04 02 03 05 00` |

---

## 4. SignedAttrs Construction

Per RFC 5652 Section 5.4, when the content type is not `id-data`, `signedAttrs`
MUST be present and the signature is computed over `DER(signedAttrs)`.
The CVM constructs the signedAttrs SET and signs it directly.

### 4.1 SignedAttrs Structure

```
signedAttrs = SET OF Attribute {
  SEQUENCE { contentType OID,          SET { id-ct-TSTInfo } },         -- fixed
  SEQUENCE { messageDigest OID,        SET { OCTET STRING(hash) } },    -- variable
  SEQUENCE { signingCertificateV2 OID, SET { SigningCertificateV2 } },  -- fixed
}
```

| Attribute | OID | Content | Type |
|-----------|-----|---------|------|
| `contentType` | 1.2.840.113549.1.9.3 | `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4) | Fixed |
| `messageDigest` | 1.2.840.113549.1.9.4 | SHA-384 hash of the TSTInfo DER bytes | Variable |
| `signingCertificateV2` | 1.2.840.113549.1.9.16.2.47 | `ESSCertIDv2` with SHA-256 hash of TSA cert | Fixed |

### 4.2 Variable Field

Only one field varies per request: the `messageDigest`, which contains the SHA-384 hash
of the DER-encoded TSTInfo. The CVM computes `SHA-384(tstinfo_der)` and places the
48-byte result in the `messageDigest` attribute.

### 4.3 Signing

The ECDSA P-384 signature is computed over the complete DER encoding of the signedAttrs SET.
Per RFC 5652, the `[0] IMPLICIT` tag used for signedAttrs in the SignerInfo is replaced
with a SET tag (`0x31`) for signing purposes. The CVM encodes signedAttrs with the SET tag
directly, since it produces the bytes that will be signed.

---

## 5. CVM State Machine

```
                    ┌──────────┐
                    │ Booting  │
                    └────┬─────┘
                         │ Load signing key
                    ┌────▼─────┐
                    │ TimeSync │
                    └────┬─────┘
                         │ NTS validation complete
                    ┌────▼─────┐
              ┌─────│  Ready   │
              │     └────┬─────┘
              │          │ Accept vsock connections
              │     ┌────▼─────┐
              │     │ Signing  │◄──── normal operation
              │     └────┬─────┘
              │          │ on error
              │     ┌────▼──────┐
              └────►│ Degraded  │
                    └───────────┘
```

### 5.1 States

| State | Description | Accepts Requests? |
|-------|-------------|-------------------|
| **Booting** | Loading ECDSA private key. In production, key is from DKG ceremony. For MVP, generated randomly at startup. | No |
| **TimeSync** | Establishing NTS sessions with time sources, calibrating against SecureTSC. | No |
| **Ready** | Time validated, key loaded. Starts vsock listener. | Yes (transitions to Signing) |
| **Signing** | Actively processing signing requests. Normal operating state. | Yes |
| **Degraded** | Error condition: time drift exceeded tolerance, NTS sources unreachable, or signing failure. | No |

### 5.2 Transitions

- **Booting → TimeSync**: Key loaded successfully.
- **TimeSync → Ready**: NTS validation completed, time source confirmed within tolerance.
- **Ready → Signing**: First connection accepted.
- **Signing → Degraded**: Time drift exceeds tolerance, all NTS sources fail, or repeated signing errors.
- **Degraded → TimeSync**: Operator-initiated recovery, or automatic retry after backoff.

### 5.3 Periodic Tasks

| Task | Interval | Action |
|------|----------|--------|
| NTS refresh | 60 seconds | Query all NTS time sources, update drift estimate |
| SecureTSC validation | 60 seconds | Compare SecureTSC against NTS consensus |
| Serial number checkpoint | On each request | Atomic increment of monotonic counter |

---

## 6. Module Inventory

| Module | File | LOC | Dependencies | Purpose |
|--------|------|-----|-------------|---------|
| Protocol | `protocol.rs` | ~80 | None | Binary request/response parsing and serialization |
| TSTInfo | `tstinfo.rs` | ~200 | `protocol` (for `HashAlgorithm`) | Template-based DER encoder for RFC 3161 TSTInfo |
| SignedAttrs | `signed_attrs.rs` | ~60 | `tstinfo` (for `encode_der_length`), `sha2` | CMS signedAttrs SET construction |
| Time | `time.rs` | ~150 | `std::time`, `std::sync::atomic` | SecureTSC, NTS validation, monotonic clock, GeneralizedTime |
| Signing | `signing.rs` | ~40 | `p384`, `ecdsa`, `sha2` | ECDSA P-384 signing |
| Attestation | `attestation.rs` | ~40 | `std::fs`, `std::os::unix` (Linux only) | SEV-SNP attestation report generation |
| Main | `main.rs` | ~100 | All above | State machine, vsock listener, request handling loop |
| **Total** | | **~670** | | |

### External Dependencies

| Crate | Version | Purpose | Audit Notes |
|-------|---------|---------|-------------|
| `p384` | 0.13 | ECDSA P-384 signing and verification | RustCrypto project, widely audited |
| `ecdsa` | 0.16 | ECDSA signature types and traits | RustCrypto project |
| `sha2` | 0.10 | SHA-384 for messageDigest computation | RustCrypto project |
| `rand_core` | 0.6 | Cryptographic RNG for key generation | RustCrypto project |

---

## 7. Testing Strategy

### 7.1 Unit Tests (run outside CVM)

| Test Category | Module | Test Cases |
|---------------|--------|------------|
| **Protocol parsing** | `protocol.rs` | Valid SHA-256/384/512 requests; with and without nonce; reject invalid version, algorithm, digest length mismatch, truncated data, trailing data, nonce too long |
| **TSTInfo encoding** | `tstinfo.rs` | Known inputs produce valid DER; outer SEQUENCE length matches content; edge cases (serial 0, max u64, empty nonce); GeneralizedTime format |
| **SignedAttrs encoding** | `signed_attrs.rs` | Outer SET tag present; length matches content; contains exactly 3 attributes; different TSTInfo produces different digest |
| **DER helpers** | `tstinfo.rs` | Short/medium/long DER lengths; INTEGER encoding with leading zeros; u64 edge cases |
| **GeneralizedTime** | `time.rs` | Unix epoch; known dates; leap years; end-of-year boundaries; millisecond precision |
| **Monotonic clock** | `time.rs` | Successive calls never decrease; concurrent access safety |
| **Signing** | `signing.rs` | Generate key and sign; verify signature; roundtrip from key bytes; different signatures verify |
| **Response serialization** | `protocol.rs` | Roundtrip encode/decode; error responses have zero-length payloads |

### 7.2 Integration Tests

| Test | Setup | Verification |
|------|-------|--------------|
| **End-to-end signing** | Start CVM core (TCP mode), send binary request, receive response | Parse response; verify ECDSA signature against CVM's public key |
| **Full RFC 3161 flow** | Start CVM + wrapper, send TimeStampReq via HTTP | Verify TimeStampResp with `openssl ts -verify` |
| **Interoperability** | Generate timestamp tokens, verify with multiple libraries | OpenSSL, Bouncy Castle, Go `crypto/pkcs7` |
| **Error handling** | Send malformed requests, check error responses | Correct status codes; no panics; no information leakage |

### 7.3 Fuzz Testing

The binary protocol parser (`parse_request`) should be fuzz-tested to ensure
it never panics on arbitrary input. Target: 1 million iterations minimum.

```rust
// Fuzz target for protocol parser
#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    let _ = parse_request(data);
    // Must not panic for any input
});
```

### 7.4 Security Audit Scope

The security audit focuses on the ~670 LOC of Rust in the CVM core:

| Focus Area | Concern | Verification Method |
|------------|---------|---------------------|
| DER encoding correctness | Malformed TSTInfo could cause verification failures or security issues | Compare output against reference ASN.1 parsers (OpenSSL, `asn1parse`) |
| Input validation | Malformed requests could cause panics or buffer overflows | Fuzz testing + code review |
| Timing side channels | Signing time could leak information about the private key | Use constant-time ECDSA implementation (`p384` crate) |
| Memory safety | Key material must not leak through stack/heap | Review `SigningContext` for proper key handling; no `Debug` on key types |
| Monotonic enforcement | Serial numbers and timestamps must never go backward | Atomic operations; test under concurrent load |
| Integer overflow | Serial number counter overflow after 2^64 operations | Review atomic increment; practically unreachable but documented |

---

## Cross-Reference Index

| Topic | Document |
|---|---|
| System architecture, two-layer split, deployment topology | [Architecture Overview](01-architecture-overview.md) |
| AMD SEV-SNP, SecureTSC, trusted time chain | [Confidential Computing & Time](02-confidential-computing-and-time.md) |
| RFC 3161 token format, CMS SignedData, CVM/wrapper split | [RFC 3161 Compliance](06-rfc3161-compliance.md) |
| Threat model, wrapper security analysis | [Threat Model](07-threat-model.md) |

---

*This document is part of the CC-TSA documentation suite. For the complete list of documents, see the [Document Map](../README.md#document-map) in the project README.*
