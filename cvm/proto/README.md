# CVM Binary Protocol Specification

The CVM core communicates with the wrapper over vsock using a fixed binary protocol.
This design eliminates ASN.1 parsing from the CVM's attack surface.

## Transport

- **Production**: AF_VSOCK, port 5000
- **Development**: TCP 127.0.0.1:5000

One request per connection. The wrapper opens a connection, sends the request,
shuts down the write half, reads the response, and closes the connection.

## Request Format (Wrapper -> CVM)

| Offset | Size | Field | Values |
|--------|------|-------|--------|
| 0 | 1 | version | `0x01` |
| 1 | 1 | hash_algorithm | `0x01`=SHA-256, `0x02`=SHA-384, `0x03`=SHA-512 |
| 2 | 1 | digest_length | 32, 48, or 64 |
| 3 | N | digest | Raw hash bytes (N = digest_length) |
| 3+N | 1 | has_nonce | `0x00` (no nonce) or `0x01` (nonce follows) |
| 4+N | 1 | nonce_length | 0-32 (only if has_nonce=0x01) |
| 5+N | M | nonce | Raw nonce bytes (M = nonce_length, absent if has_nonce=0x00) |

**Maximum request size**: 101 bytes (SHA-512 digest + 32-byte nonce).

### Validation Rules

- `version` must be `0x01`. Any other value is rejected.
- `hash_algorithm` must be `0x01`, `0x02`, or `0x03`.
- `digest_length` must match the algorithm: SHA-256=32, SHA-384=48, SHA-512=64.
- `has_nonce` must be `0x00` or `0x01`.
- `nonce_length` must be <= 32.
- No trailing data is permitted after the last field.

## Response Format (CVM -> Wrapper)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | version | `0x01` |
| 1 | 1 | status | `0x00`=success, `0x01`=invalid request, `0x02`=internal error, `0x03`=time unavailable |
| 2 | 4 | tstinfo_length | DER-encoded TSTInfo length (big-endian u32) |
| 6 | T | tstinfo_der | TSTInfo DER bytes |
| 6+T | 4 | signed_attrs_length | signedAttrs DER length (big-endian u32) |
| 10+T | A | signed_attrs_der | signedAttrs DER bytes |
| 10+T+A | 4 | signature_length | ECDSA P-384 DER signature length (big-endian u32) |
| 14+T+A | S | signature | ECDSA P-384 signature over signed_attrs_der |

### Error Responses

When status is non-zero, all three length fields are zero and no payload follows.

### Status Codes

| Code | Name | Meaning |
|------|------|---------|
| `0x00` | Success | TSTInfo, signedAttrs, and signature are present |
| `0x01` | InvalidRequest | Request parsing or validation failed |
| `0x02` | InternalError | Signing or internal processing failed |
| `0x03` | TimeUnavailable | Trusted time source not validated |

## Why signedAttrs?

Per RFC 5652 Section 5.4, when the content type is not `id-data`
(TSTInfo uses `id-ct-TSTInfo`), `signedAttrs` MUST be present and the
signature covers `DER(signedAttrs)`, not the TSTInfo directly.

The CVM constructs signedAttrs containing:
1. `contentType`: `id-ct-TSTInfo`
2. `messageDigest`: SHA-384 hash of the TSTInfo DER
3. `signingCertificateV2`: SHA-256 hash of the TSA certificate

The ECDSA signature is computed over the complete DER-encoded signedAttrs.

## Security Properties

- **No ASN.1 parsing in CVM**: The binary format is fixed-layout with explicit lengths.
- **Strict validation**: Any deviation from the expected format is rejected.
- **Maximum size bounded**: Requests cannot exceed 101 bytes.
- **No strings**: All fields are integers or raw byte arrays.
