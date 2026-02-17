# Quantum-Safe Threshold Cryptography & Key Management

This document describes the cryptographic algorithms, threshold signing protocol, distributed key generation ceremony, and key lifecycle management
used by the Confidential Computing Timestamp Authority (CC-TSA). For system architecture and deployment topology,
see [Architecture Overview](01-architecture-overview.md). For the hardware-attested execution environment that protects key shares at runtime,
see [Confidential Computing and Time](02-confidential-computing-and-time.md).

> **Implementation status**: The PoC implements single-signer ECDSA P-384 signing inside the CVM core.
> The threshold ML-DSA-65 protocol, DKG ceremony, hybrid dual-signature tokens, and key lifecycle
> management described in this document are design targets not yet implemented.

---

## Table of Contents

1. [Algorithm Selection](#1-algorithm-selection)
2. [Hybrid Token Structure](#2-hybrid-token-structure)
3. [Threshold ML-DSA](#3-threshold-ml-dsa)
4. [Distributed Key Generation (DKG)](#4-distributed-key-generation-dkg)
5. [Key Share Storage](#5-key-share-storage)
6. [Key Lifecycle State Diagram](#6-key-lifecycle-state-diagram)

---

## 1. Algorithm Selection

CC-TSA uses a deliberate three-algorithm strategy: a primary post-quantum signature, a classical companion for backward compatibility,
and a conservative hash-based backup for catastrophic lattice breaks. Every timestamp token carries the first two signatures simultaneously;
the third is held in reserve.

### Primary: ML-DSA-65 (FIPS 204)

ML-DSA-65 is the NIST post-quantum digital signature standard, formerly known as CRYSTALS-Dilithium.
It provides Security Level 3 (~143-bit classical security, ~128-bit quantum security) based on the hardness of the Module Learning With Errors (Module-LWE) problem.

Key characteristics:

- **Signature size**: ~3,309 bytes
- **Public key size**: ~1,952 bytes
- **Signing performance**: ~100,000 signatures/sec on modern hardware — more than sufficient for TSA workloads
- **Verification performance**: ~100,000 verifications/sec

**Why ML-DSA-65 and not ML-DSA-44 or ML-DSA-87?** Security Level 3 strikes the right balance between security margin and operational efficiency.
ML-DSA-44 (Level 2) provides ~107-bit classical / ~99-bit quantum security, which falls below conservative recommendations for timestamps
that may need to remain valid for decades. ML-DSA-87 (Level 5) roughly doubles the signature size to ~4,627 bytes with diminishing security returns —
the jump from 128-bit to 192-bit quantum security does not justify the bandwidth and storage cost for every timestamp token.

### Classical Companion: ECDSA P-384

ECDSA over the NIST P-384 curve provides backward compatibility with existing timestamp verifiers that do not yet support post-quantum algorithms. P-384 offers 192-bit classical security.

Key characteristics:

- **Signature size**: ~96 bytes
- **Public key size**: ~97 bytes
- **Signing performance**: ~50,000 signatures/sec
- **Verification performance**: ~20,000 verifications/sec

Every CC-TSA timestamp token carries **both** an ECDSA P-384 signature and an ML-DSA-65 signature.
Classical verifiers process the ECDSA signature and ignore the ML-DSA `SignerInfo`; quantum-aware verifiers can validate both.
This hybrid approach ensures that tokens are verifiable today and remain secure against future quantum attacks.
See [RFC 3161 Compliance](06-rfc3161-compliance.md) for details on the dual-`SignerInfo` CMS structure.

### Conservative Backup: SLH-DSA-128f (FIPS 205)

SLH-DSA-128f (formerly SPHINCS+) is a stateless hash-based signature scheme. Its security relies exclusively on the collision resistance
of the underlying hash function — it would survive even a complete break of lattice-based cryptography.

Key characteristics:

- **Signature size**: ~17,088 bytes (much larger than ML-DSA-65)
- **Public key size**: ~64 bytes
- **Signing performance**: ~100 signatures/sec (much slower than ML-DSA-65)
- **Verification performance**: ~1,000 verifications/sec

SLH-DSA-128f is **not used in normal operation**. It serves as an emergency fallback: if ML-DSA is cryptanalytically broken,
CC-TSA can perform a new DKG ceremony using SLH-DSA and resume signing with a new certificate — at reduced throughput, but with uncompromised security.
See [Failure Modes and Recovery](04-failure-modes-and-recovery.md) for the activation procedure.

### Algorithm Comparison Table

| Property | ML-DSA-65 | ECDSA P-384 | SLH-DSA-128f |
|---|---|---|---|
| **Security basis** | Lattice (Module-LWE) | Elliptic curve DLP | Hash functions |
| **Quantum safe** | Yes | No | Yes |
| **Signature size** | 3,309 B | 96 B | 17,088 B |
| **Public key size** | 1,952 B | 97 B | 64 B |
| **Sign performance** | ~100K/sec | ~50K/sec | ~100/sec |
| **Verify performance** | ~100K/sec | ~20K/sec | ~1K/sec |
| **Threshold friendly** | Yes (recent research) | Yes (well-studied) | No (stateless = hard to threshold) |
| **FIPS standard** | FIPS 204 | FIPS 186-5 | FIPS 205 |
| **Role in CC-TSA** | **Primary PQC** | **Classical companion** | **Emergency backup** |

---

## 2. Hybrid Token Structure

Each CC-TSA timestamp token is a standard CMS `SignedData` structure (RFC 5652) containing RFC 3161 `TSTInfo` content,
signed by **two** `SignerInfo` entries — one classical (ECDSA P-384) and one post-quantum (ML-DSA-65).
Both signatures cover the identical `TSTInfo` payload.

```mermaid
graph TD
    CI["<b>CMS ContentInfo</b>"]
    SD["<b>SignedData</b> (version 3)"]
    DA["digestAlgorithms:<br/>{SHA-384, SHA-384}"]
    ECI["<b>encapContentInfo</b>"]
    ECT["eContentType:<br/>id-ct-TSTInfo<br/>(1.2.840.113549.1.9.16.1.4)"]
    EC["<b>eContent: TSTInfo</b> (DER-encoded)"]
    TST_V["version: 1"]
    TST_P["policy: CC-TSA policy OID"]
    TST_MI["messageImprint:<br/>{hashAlgorithm, hashedMessage}"]
    TST_SN["serialNumber: unique"]
    TST_GT["genTime: GeneralizedTime (UTC)"]
    TST_ACC["accuracy: {seconds: 1, millis: 0}"]
    TST_N["nonce: (from request)"]
    TST_TSA["tsa: CC-TSA GeneralName"]
    CERTS["<b>certificates</b><br/>{TSA cert (ECDSA),<br/>TSA cert (ML-DSA),<br/>CA chain}"]

    subgraph SignerInfos
        SI1["<b>SignerInfo #1 — Classical</b>"]
        SI1_ALG["signatureAlgorithm:<br/>ecdsa-with-SHA384"]
        SI1_SIG["signature:<br/>ECDSA P-384 signature<br/>(~96 bytes)"]

        SI2["<b>SignerInfo #2 — Post-Quantum</b>"]
        SI2_ALG["signatureAlgorithm:<br/>id-ml-dsa-65"]
        SI2_SIG["signature:<br/>ML-DSA-65 signature<br/>(~3,309 bytes)"]
    end

    CI --> SD
    SD --> DA
    SD --> ECI
    ECI --> ECT
    ECI --> EC
    EC --> TST_V
    EC --> TST_P
    EC --> TST_MI
    EC --> TST_SN
    EC --> TST_GT
    EC --> TST_ACC
    EC --> TST_N
    EC --> TST_TSA
    SD --> CERTS
    SD --> SI1
    SI1 --> SI1_ALG
    SI1 --> SI1_SIG
    SD --> SI2
    SI2 --> SI2_ALG
    SI2 --> SI2_SIG

    SI1 -. "signs TSTInfo" .-> EC
    SI2 -. "signs TSTInfo" .-> EC
```

**Verification modes:**

- **Classical-only verifier**: Validates `SignerInfo #1` (ECDSA P-384), ignores `SignerInfo #2`. Uses the ECDSA TSA certificate from the `certificates` field.
This is the standard RFC 3161 verification path and works with all existing tooling.
- **Quantum-aware verifier**: Validates `SignerInfo #2` (ML-DSA-65), optionally also validates `SignerInfo #1`. Uses the ML-DSA TSA certificate. Provides quantum-safe assurance.
- **Belt-and-suspenders verifier**: Validates both `SignerInfo` entries and requires both to pass. Highest assurance — detects compromise of either algorithm.

For full details on the CMS encoding, OID assignments, and backward compatibility considerations, see [RFC 3161 Compliance](06-rfc3161-compliance.md).

---

## 3. Threshold ML-DSA

### Background

Traditional threshold signatures split a signing key into **shares** distributed across multiple parties.
Any subset of **t** shares (from a total of **n**) can collaborate to produce a valid signature,
but fewer than **t** shares reveal nothing about the key. The resulting signature is **indistinguishable** from a single-signer signature —
verifiers do not need to know that a threshold scheme was used.

For ML-DSA, threshold protocols are based on recent cryptographic research. The CC-TSA design draws on the framework described in
Cozzo & Smart ("Sharing the LUOV and ML-DSA", USENIX Security '26 research track), which adapts Shamir-style secret sharing
and verifiable secret sharing to the lattice-based structure of ML-DSA. The key insight is that ML-DSA's signing operation —
which involves sampling a masking vector, computing a commitment, and then a response — can be distributed across parties
such that the masking and response are computed in shares, while the final combination yields a valid single-signer signature.

### Protocol Overview

CC-TSA uses a **3-of-5** threshold scheme:

- **5 enclave nodes** each hold a distinct key share
- **Any 3 nodes** can collaborate to produce a valid ML-DSA-65 signature
- The signing key is **never reconstructed** at any point — not during DKG, not during signing
- The output signature is a standard ML-DSA-65 signature; verifiers cannot distinguish it from a single-signer signature

### Threshold Signing Protocol (2 Rounds)

The following diagram illustrates the two-round threshold signing protocol. The **Coordinator** is the enclave node that received
the incoming timestamp request (via the load balancer); it also serves as one of the three signing participants.

```mermaid
sequenceDiagram
    autonumber
    participant C as Coordinator<br/>(Node C)
    participant P1 as Participant 1<br/>(Node P1)
    participant P2 as Participant 2<br/>(Node P2)

    Note over C: Receives RFC 3161<br/>timestamp request
    Note over C: Constructs TSTInfo,<br/>computes digest d = SHA-384(TSTInfo)

    rect rgb(230, 240, 255)
        Note over C,P2: Round 1 — Commitment
        C->>P1: SignRequest(d, session_id, selected_signers)
        C->>P2: SignRequest(d, session_id, selected_signers)
        Note over C: Generate masking vector y_C,<br/>compute commitment w_C = A * y_C
        Note over P1: Generate masking vector y_P1,<br/>compute commitment w_P1 = A * y_P1
        Note over P2: Generate masking vector y_P2,<br/>compute commitment w_P2 = A * y_P2
        P1->>C: Commitment(w_P1)
        P2->>C: Commitment(w_P2)
        Note over C: Has all 3 commitments:<br/>w_C, w_P1, w_P2
    end

    rect rgb(230, 255, 230)
        Note over C,P2: Round 2 — Signature Share
        C->>P1: AllCommitments(w_C, w_P1, w_P2)
        C->>P2: AllCommitments(w_C, w_P1, w_P2)
        Note over C: Compute challenge c = H(w_C + w_P1 + w_P2, d)
        Note over P1: Compute challenge c = H(w_C + w_P1 + w_P2, d)
        Note over P2: Compute challenge c = H(w_C + w_P1 + w_P2, d)
        Note over C: Compute partial signature<br/>z_C = y_C + c * s_C<br/>(rejection sampling)
        Note over P1: Compute partial signature<br/>z_P1 = y_P1 + c * s_P1<br/>(rejection sampling)
        Note over P2: Compute partial signature<br/>z_P2 = y_P2 + c * s_P2<br/>(rejection sampling)
        P1->>C: PartialSignature(z_P1)
        P2->>C: PartialSignature(z_P2)
    end

    rect rgb(255, 245, 230)
        Note over C: Signature Assembly
        Note over C: Combine: z = z_C + z_P1 + z_P2<br/>(Lagrange interpolation applied)
        Note over C: Final signature sigma = (c, z)
        Note over C: Verify sigma against public key PK
        alt Signature valid
            Note over C: Embed sigma in CMS SignedData<br/>(SignerInfo #2, id-ml-dsa-65)
        else Signature invalid (rejection sampling abort)
            Note over C: Retry from Round 1<br/>(expected ~1 in 7 attempts)
        end
    end
```

**Performance characteristics:**

- The 2-round protocol requires two network round-trips between the coordinator and participants. Latency is dominated by network distance, not cryptographic computation.
- The ECDSA threshold signing (for `SignerInfo #1`) runs in parallel using a similar 2-round protocol, well-studied for elliptic curves.
- Rejection sampling in ML-DSA means that approximately 1 in 7 attempts will abort and require a retry from Round 1.
This is inherent to the ML-DSA design and does not indicate an error. The expected number of rounds to produce a valid signature
is approximately 7/6 (~1.17 attempts), contributing negligible overhead.
- The overall signing latency is well within the 1-second end-to-end round-trip budget for all deployment topologies, including multi-provider configurations.

**Security properties:**

- **No key reconstruction**: The signing key `s` is never assembled in any single location. Each node only ever holds its share `s_i`.
- **Abort security**: If any participant sends an invalid partial signature, the coordinator detects this during final verification and aborts — no partial information about honest shares is leaked.
- **Replay protection**: Each signing session uses a fresh `session_id` and fresh randomness; replayed messages from previous sessions are rejected.

For the full failure-mode analysis of threshold signing (e.g., a participant going offline mid-protocol), see [Failure Modes and Recovery](04-failure-modes-and-recovery.md).

---

## 4. Distributed Key Generation (DKG)

### Overview

Distributed Key Generation (DKG) is the cryptographic ceremony that creates the 3-of-5 threshold key shares without any single party —
or any coalition of fewer than 3 parties — ever seeing the full private key. DKG runs on first boot when no key material exists,
and again whenever the cluster must be reconstituted (e.g., after quorum loss or a software update requiring new key material).
The protocol is based on Pedersen/Feldman verifiable secret sharing, adapted for the algebraic structure of ML-DSA over module lattices.

**DKG outputs:**

- Each of the 5 enclave nodes receives a unique **key share** `s_i`
- All nodes agree on a common **public key** `PK`
- The public key is embedded in an X.509 certificate issued by the Certificate Authority

**DKG requirements:**

- All 5 nodes must participate (the ceremony cannot proceed with fewer)
- All nodes must pass mutual attestation before any key material is generated
- The ceremony is deterministic once randomness is committed — no node can bias the outcome

### DKG Ceremony Protocol

```mermaid
sequenceDiagram
    autonumber
    participant N1 as Node 1<br/>(Azure)
    participant N2 as Node 2<br/>(Azure)
    participant N3 as Node 3<br/>(GCP)
    participant N4 as Node 4<br/>(GCP)
    participant N5 as Node 5<br/>(Third Provider)
    participant CA as Certificate<br/>Authority

    rect rgb(255, 235, 235)
        Note over N1,N5: Phase 1 — Mutual Attestation
        Note over N1: Request attestation<br/>report from AMD-SP
        Note over N2: Request attestation<br/>report from AMD-SP
        Note over N3: Request attestation<br/>report from AMD-SP
        Note over N4: Request attestation<br/>report from AMD-SP
        Note over N5: Request attestation<br/>report from AMD-SP
        N1->>N2: AttestationReport(N1)
        N1->>N3: AttestationReport(N1)
        N1->>N4: AttestationReport(N1)
        N1->>N5: AttestationReport(N1)
        N2->>N1: AttestationReport(N2)
        N3->>N1: AttestationReport(N3)
        N4->>N1: AttestationReport(N4)
        N5->>N1: AttestationReport(N5)
        Note over N1,N5: (All pairs exchange attestation reports — shown for N1 only for brevity)
        Note over N1,N5: Each node verifies all 4 received reports<br/>against AMD certificate chain (ARK → ASK → VCEK)
        Note over N1,N5: All 5 nodes confirm: all peers are<br/>genuine enclaves running expected code measurement
    end

    rect rgb(230, 240, 255)
        Note over N1,N5: Phase 2 — DKG Protocol (Pedersen/Feldman for ML-DSA)
        Note over N1: Generate random polynomial<br/>f_1(x) of degree t-1 = 2
        Note over N2: Generate random polynomial<br/>f_2(x) of degree t-1 = 2
        Note over N3: Generate random polynomial<br/>f_3(x) of degree t-1 = 2
        Note over N4: Generate random polynomial<br/>f_4(x) of degree t-1 = 2
        Note over N5: Generate random polynomial<br/>f_5(x) of degree t-1 = 2
        Note over N1: Evaluate f_1 at points 1..5<br/>creating 5 sub-shares
        N1->>N2: SubShare(f_1(2)) [encrypted, attested TLS]
        N1->>N3: SubShare(f_1(3)) [encrypted, attested TLS]
        N1->>N4: SubShare(f_1(4)) [encrypted, attested TLS]
        N1->>N5: SubShare(f_1(5)) [encrypted, attested TLS]
        Note over N1,N5: (All 5 nodes send sub-shares to all others — shown for N1 only)
        Note over N1: Combine received sub-shares:<br/>s_1 = f_1(1) + f_2(1) + f_3(1) + f_4(1) + f_5(1)
        Note over N2: Combine received sub-shares:<br/>s_2 = f_1(2) + f_2(2) + f_3(2) + f_4(2) + f_5(2)
        Note over N1,N5: Each node broadcasts commitment<br/>to its polynomial coefficients (Feldman VSS)
        Note over N1,N5: All nodes verify commitments<br/>against received sub-shares — ensures no node cheated
    end

    rect rgb(230, 255, 230)
        Note over N1,N5: Phase 3 — Public Key Derivation
        Note over N1,N5: All nodes compute the same public key PK<br/>from the broadcast commitments:<br/>PK = A * (f_1(0) + f_2(0) + ... + f_5(0))
        Note over N1,N5: All nodes verify they derived the same PK
        N1->>CA: CSR (Certificate Signing Request)<br/>containing PK
        CA->>N1: X.509 Certificate for CC-TSA<br/>(subject: TSA, key: ML-DSA-65 PK)
        N1->>N2: Distribute TSA certificate
        N1->>N3: Distribute TSA certificate
        N1->>N4: Distribute TSA certificate
        N1->>N5: Distribute TSA certificate
    end

    rect rgb(255, 245, 230)
        Note over N1,N5: Phase 4 — Key Shares Active in Memory
        Note over N1,N5: Key shares s_1..s_5 remain in enclave memory only.<br/>No persistence to durable storage.<br/>Shares are lost if nodes reboot.
        Note over N1,N5: Archive DKG ceremony materials:<br/>commitments, verification data, attestation reports,<br/>attestation measurement bound to issued certificate
        Note over N1,N5: DKG complete — system ready for signing
    end
```

**Security properties of DKG:**

- **Verifiability**: Feldman's VSS commitments allow every node to verify that the sub-shares it received are consistent
with the committed polynomial. A cheating node is detected and the ceremony aborts.
- **No trusted dealer**: There is no single party that generates and distributes shares. Each of the 5 nodes contributes equally to the key generation.
- **Confidentiality**: Sub-shares are transmitted over attested TLS channels — encrypted point-to-point between mutually verified enclaves.
No party outside the enclave cluster can observe the sub-shares.
- **Robustness**: If any node fails during DKG (crash, attestation failure, commitment mismatch), the entire ceremony aborts
and must be restarted from scratch. This is acceptable because the ceremony is automated and can be retried immediately.

A parallel DKG ceremony is run for the ECDSA P-384 threshold key, using the well-established Gennaro et al. protocol
for elliptic curve threshold signatures. The same mutual attestation phase is shared between both ceremonies.

For the operational procedures surrounding the DKG ceremony (scheduling, personnel, audit trail), see [Operations and Deployment](05-operations-and-deployment.md).

---

## 5. Key Share Storage

Key shares exist **only in enclave memory**. They are not persisted to durable storage in any form — no disk encryption, no KMS wrapping, no sealed blobs.

### Design Properties

- **No at-rest key material**: Key shares are never written to disk, cloud storage, or any medium outside the enclave's hardware-encrypted memory.
If a node shuts down, reboots, or crashes, its key share is irrecoverably lost. This is by design.
- **Eliminated attack surface**: There is no sealed key share to steal, no wrapping key to compromise, and no KMS policy to subvert.
The only way to obtain a key share is to read it from a running enclave's memory — which AMD SEV-SNP is specifically designed to prevent.
- **Simplified trust model**: The trust model does not depend on cloud KMS services or their attestation policy configurations.
Trust is rooted entirely in the hardware attestation of the running enclave and the software measurement bound to the TSA certificate.
- **Recovery by reconstitution**: If the cluster loses quorum (fewer than 3 nodes remain running), a new DKG ceremony is required.
This produces new key shares, a new public key, and requires a new TSA certificate.
Old timestamps signed under the previous certificate remain valid.

### Trade-offs

The ephemeral key model trades persistence for simplicity and security:

| Property | Ephemeral (memory-only) | Persistent (at-rest encryption) |
|---|---|---|
| **Survives node reboot** | No — share is lost | Yes — share can be unsealed |
| **Attack surface** | Memory only (hardware-protected) | Memory + disk + KMS + attestation policy |
| **Operator influence** | Cannot change running software without new DKG | Can update KMS attestation policy to accept new measurements |
| **Recovery from quorum loss** | New DKG + new certificate | Unseal existing shares from storage |
| **Trust dependencies** | AMD SEV-SNP hardware only | AMD SEV-SNP + cloud KMS + attestation policy management |

The ephemeral model is preferred because it eliminates the trust contradiction inherent in operator-managed KMS attestation policies.
See [Architecture Overview](01-architecture-overview.md) Section 8 for the full rationale.

---

## 6. Key Lifecycle State Diagram

The threshold signing key progresses through a well-defined set of states from initial generation to eventual retirement. The following state diagram captures all valid states and transitions.

```mermaid
stateDiagram-v2
    [*] --> Uninitialized

    Uninitialized --> DKG_In_Progress : Initiate DKG ceremony

    DKG_In_Progress --> Active : Ceremony complete,<br/>all 5 shares in memory

    Active --> Degraded : 1-2 nodes go offline<br/>(3-4 nodes remain)

    Degraded --> Active : Offline nodes recovered<br/>(all 5 nodes online)

    Degraded --> Suspended : 3+ nodes offline<br/>(fewer than 3 remain)

    Suspended --> Degraded : Some nodes recovered<br/>(3-4 nodes online)

    Active --> Compromised : Compromise detected
    Degraded --> Compromised : Compromise detected
    Suspended --> Compromised : Compromise detected

    Compromised --> Retired : Emergency revocation,<br/>certificate revoked

    Active --> Retired : Planned key rotation,<br/>software update, or decommission

    Retired --> Uninitialized : New DKG for replacement key

    Retired --> [*]
```

### State Descriptions

| State | Description | Signing Capability |
|---|---|---|
| **Uninitialized** | No key material exists. The system is awaiting a DKG ceremony. This is the initial state and also the state after key retirement when new key material is needed. | None |
| **DKG In Progress** | The distributed key generation ceremony is running. All 5 nodes must be online and mutually attested. This occurs on initial setup and whenever the cluster is reconstituted (e.g., after quorum loss or software update). | None (ceremony in progress) |
| **Active** | All 5 key shares are distributed and held in enclave memory. The system is fully operational. | Full — any 3 of 5 nodes can sign |
| **Degraded** | 1-2 nodes are offline (3-4 nodes remain). Signing continues but fault tolerance is reduced. Lost shares cannot be recovered — if quorum is lost, a new DKG is required. | Reduced margin — still operational |
| **Suspended** | Fewer than 3 nodes are online. Signing is halted because the threshold cannot be met. Recovery requires a new DKG ceremony and new certificate. | None — halted |
| **Compromised** | A key compromise has been detected (e.g., a share leaked, anomalous signing behavior). Emergency procedures are activated. | Halted immediately |
| **Retired** | The key has been decommissioned. The corresponding certificate is revoked or expired. Existing timestamps signed by this key remain valid (certificate was valid at signing time). | None — permanently decommissioned |

### Monitoring and Alerts

State transitions generate alerts through the monitoring infrastructure described in [Operations and Deployment](05-operations-and-deployment.md):

- **Active to Degraded**: Warning — reduced fault tolerance. Operations team investigates and recovers the offline node(s).
- **Degraded to Suspended**: Critical — signing halted. Immediate response required.
- **Any state to Compromised**: Critical — emergency revocation procedure initiated. See [Failure Modes and Recovery](04-failure-modes-and-recovery.md) for the compromise response playbook.

---

## References

1. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
2. NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA)
3. NIST FIPS 186-5 — Digital Signature Standard (DSS), including ECDSA
4. RFC 3161 — Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)
5. RFC 5652 — Cryptographic Message Syntax (CMS)
6. Cozzo, D. & Smart, N.P. — "Sharing the LUOV and ML-DSA" (USENIX Security '26 Research Track)
7. Pedersen, T.P. — "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing" (CRYPTO '91)
8. Feldman, P. — "A Practical Scheme for Non-Interactive Verifiable Secret Sharing" (FOCS '87)
9. AMD SEV-SNP — Strengthening VM Isolation with Integrity Protection and More (AMD White Paper)
