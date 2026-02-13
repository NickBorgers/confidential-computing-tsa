# Quantum-Safe Threshold Cryptography & Key Management

This document describes the cryptographic algorithms, threshold signing protocol, distributed key generation ceremony, and key lifecycle management used by the Confidential Computing Timestamp Authority (CC-TSA). For system architecture and deployment topology, see [Architecture Overview](01-architecture-overview.md). For the hardware-attested execution environment that protects key shares at runtime, see [Confidential Computing and Time](02-confidential-computing-and-time.md).

---

## Table of Contents

1. [Algorithm Selection](#1-algorithm-selection)
2. [Hybrid Token Structure](#2-hybrid-token-structure)
3. [Threshold ML-DSA](#3-threshold-ml-dsa)
4. [Distributed Key Generation (DKG)](#4-distributed-key-generation-dkg)
5. [Key Share Persistence — Double-Envelope Encryption](#5-key-share-persistence--double-envelope-encryption)
6. [Key Lifecycle State Diagram](#6-key-lifecycle-state-diagram)
7. [Proactive Secret Sharing](#7-proactive-secret-sharing)

---

## 1. Algorithm Selection

CC-TSA uses a deliberate three-algorithm strategy: a primary post-quantum signature, a classical companion for backward compatibility, and a conservative hash-based backup for catastrophic lattice breaks. Every timestamp token carries the first two signatures simultaneously; the third is held in reserve.

### Primary: ML-DSA-65 (FIPS 204)

ML-DSA-65 is the NIST post-quantum digital signature standard, formerly known as CRYSTALS-Dilithium. It provides Security Level 3 (~143-bit classical security, ~128-bit quantum security) based on the hardness of the Module Learning With Errors (Module-LWE) problem.

Key characteristics:

- **Signature size**: ~3,309 bytes
- **Public key size**: ~1,952 bytes
- **Signing performance**: ~100,000 signatures/sec on modern hardware — more than sufficient for TSA workloads
- **Verification performance**: ~100,000 verifications/sec

**Why ML-DSA-65 and not ML-DSA-44 or ML-DSA-87?** Security Level 3 strikes the right balance between security margin and operational efficiency. ML-DSA-44 (Level 2) provides ~107-bit classical / ~99-bit quantum security, which falls below conservative recommendations for timestamps that may need to remain valid for decades. ML-DSA-87 (Level 5) roughly doubles the signature size to ~4,627 bytes with diminishing security returns — the jump from 128-bit to 192-bit quantum security does not justify the bandwidth and storage cost for every timestamp token.

### Classical Companion: ECDSA P-384

ECDSA over the NIST P-384 curve provides backward compatibility with existing timestamp verifiers that do not yet support post-quantum algorithms. P-384 offers 192-bit classical security.

Key characteristics:

- **Signature size**: ~96 bytes
- **Public key size**: ~97 bytes
- **Signing performance**: ~50,000 signatures/sec
- **Verification performance**: ~20,000 verifications/sec

Every CC-TSA timestamp token carries **both** an ECDSA P-384 signature and an ML-DSA-65 signature. Classical verifiers process the ECDSA signature and ignore the ML-DSA `SignerInfo`; quantum-aware verifiers can validate both. This hybrid approach ensures that tokens are verifiable today and remain secure against future quantum attacks. See [RFC 3161 Compliance](06-rfc3161-compliance.md) for details on the dual-`SignerInfo` CMS structure.

### Conservative Backup: SLH-DSA-128f (FIPS 205)

SLH-DSA-128f (formerly SPHINCS+) is a stateless hash-based signature scheme. Its security relies exclusively on the collision resistance of the underlying hash function — it would survive even a complete break of lattice-based cryptography.

Key characteristics:

- **Signature size**: ~17,088 bytes (much larger than ML-DSA-65)
- **Public key size**: ~64 bytes
- **Signing performance**: ~100 signatures/sec (much slower than ML-DSA-65)
- **Verification performance**: ~1,000 verifications/sec

SLH-DSA-128f is **not used in normal operation**. It serves as an emergency fallback: a pre-generated SLH-DSA backup key is stored, certified by the CA, and held in sealed storage. If ML-DSA is cryptanalytically broken, CC-TSA can activate the SLH-DSA key and resume signing within minutes — at reduced throughput, but with uncompromised security. See [Failure Modes and Recovery](04-failure-modes-and-recovery.md) for the activation procedure.

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

Each CC-TSA timestamp token is a standard CMS `SignedData` structure (RFC 5652) containing RFC 3161 `TSTInfo` content, signed by **two** `SignerInfo` entries — one classical (ECDSA P-384) and one post-quantum (ML-DSA-65). Both signatures cover the identical `TSTInfo` payload.

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
    TST_ACC["accuracy: {seconds: 0, millis: 50}"]
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

- **Classical-only verifier**: Validates `SignerInfo #1` (ECDSA P-384), ignores `SignerInfo #2`. Uses the ECDSA TSA certificate from the `certificates` field. This is the standard RFC 3161 verification path and works with all existing tooling.
- **Quantum-aware verifier**: Validates `SignerInfo #2` (ML-DSA-65), optionally also validates `SignerInfo #1`. Uses the ML-DSA TSA certificate. Provides quantum-safe assurance.
- **Belt-and-suspenders verifier**: Validates both `SignerInfo` entries and requires both to pass. Highest assurance — detects compromise of either algorithm.

For full details on the CMS encoding, OID assignments, and backward compatibility considerations, see [RFC 3161 Compliance](06-rfc3161-compliance.md).

---

## 3. Threshold ML-DSA

### Background

Traditional threshold signatures split a signing key into **shares** distributed across multiple parties. Any subset of **t** shares (from a total of **n**) can collaborate to produce a valid signature, but fewer than **t** shares reveal nothing about the key. The resulting signature is **indistinguishable** from a single-signer signature — verifiers do not need to know that a threshold scheme was used.

For ML-DSA, threshold protocols are based on recent cryptographic research. The CC-TSA design draws on the framework described in Cozzo & Smart ("Sharing the LUOV and ML-DSA", USENIX Security '26 research track), which adapts Shamir-style secret sharing and verifiable secret sharing to the lattice-based structure of ML-DSA. The key insight is that ML-DSA's signing operation — which involves sampling a masking vector, computing a commitment, and then a response — can be distributed across parties such that the masking and response are computed in shares, while the final combination yields a valid single-signer signature.

### Protocol Overview

CC-TSA uses a **3-of-5** threshold scheme:

- **5 enclave nodes** each hold a distinct key share
- **Any 3 nodes** can collaborate to produce a valid ML-DSA-65 signature
- The signing key is **never reconstructed** at any point — not during DKG, not during signing, not during key share refresh
- The output signature is a standard ML-DSA-65 signature; verifiers cannot distinguish it from a single-signer signature

### Threshold Signing Protocol (2 Rounds)

The following diagram illustrates the two-round threshold signing protocol. The **Coordinator** is the enclave node that received the incoming timestamp request (via the load balancer); it also serves as one of the three signing participants.

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

- The 2-round protocol adds approximately **1-2ms latency** over single-signer ML-DSA signing.
- With intra-region networking (< 1ms RTT between enclave nodes), total threshold signing completes in **< 5ms**.
- The ECDSA threshold signing (for `SignerInfo #1`) runs in parallel using a similar 2-round protocol, well-studied for elliptic curves.
- Rejection sampling in ML-DSA means that approximately 1 in 7 attempts will abort and require a retry from Round 1. This is inherent to the ML-DSA design and does not indicate an error. The expected number of rounds to produce a valid signature is approximately 7/6 (~1.17 attempts), contributing negligible overhead.

**Security properties:**

- **No key reconstruction**: The signing key `s` is never assembled in any single location. Each node only ever holds its share `s_i`.
- **Abort security**: If any participant sends an invalid partial signature, the coordinator detects this during final verification and aborts — no partial information about honest shares is leaked.
- **Replay protection**: Each signing session uses a fresh `session_id` and fresh randomness; replayed messages from previous sessions are rejected.

For the full failure-mode analysis of threshold signing (e.g., a participant going offline mid-protocol), see [Failure Modes and Recovery](04-failure-modes-and-recovery.md).

---

## 4. Distributed Key Generation (DKG)

### Overview

Distributed Key Generation is a one-time cryptographic ceremony that creates the 3-of-5 threshold key shares without any single party — or any coalition of fewer than 3 parties — ever seeing the full private key. The protocol is based on Pedersen/Feldman verifiable secret sharing, adapted for the algebraic structure of ML-DSA over module lattices.

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
        Note over N1,N5: Phase 4 — Key Share Persistence
        Note over N1: Seal s_1 with double-envelope encryption<br/>(see Section 5)
        Note over N2: Seal s_2 with double-envelope encryption
        Note over N3: Seal s_3 with double-envelope encryption
        Note over N4: Seal s_4 with double-envelope encryption
        Note over N5: Seal s_5 with double-envelope encryption
        Note over N1,N5: Archive DKG ceremony materials:<br/>commitments, verification data, attestation reports
        Note over N1,N5: DKG complete — system ready for signing
    end
```

**Security properties of DKG:**

- **Verifiability**: Feldman's VSS commitments allow every node to verify that the sub-shares it received are consistent with the committed polynomial. A cheating node is detected and the ceremony aborts.
- **No trusted dealer**: There is no single party that generates and distributes shares. Each of the 5 nodes contributes equally to the key generation.
- **Confidentiality**: Sub-shares are transmitted over attested TLS channels — encrypted point-to-point between mutually verified enclaves. No party outside the enclave cluster can observe the sub-shares.
- **Robustness**: If any node fails during DKG (crash, attestation failure, commitment mismatch), the entire ceremony aborts and must be restarted from scratch. This is acceptable because DKG is a one-time event.

A parallel DKG ceremony is run for the ECDSA P-384 threshold key, using the well-established Gennaro et al. protocol for elliptic curve threshold signatures. The same mutual attestation phase is shared between both ceremonies.

For the operational procedures surrounding the DKG ceremony (scheduling, personnel, audit trail), see [Operations and Deployment](05-operations-and-deployment.md).

---

## 5. Key Share Persistence — Double-Envelope Encryption

### Problem

Key shares must survive node restarts, VM migrations, and enclave reboots. However, persisting cryptographic key material to disk introduces a critical risk: the sealed key share must only be recoverable inside a genuine, attested enclave running the correct CC-TSA code. A compromised host OS, a modified VM image, or a rogue operator must not be able to decrypt the key share.

### Solution: Double-Envelope Encryption

CC-TSA protects each key share with two independent layers of encryption. Both layers must be unwrapped to recover the plaintext key share, and each layer is bound to a different trust anchor.

```mermaid
graph TD
    subgraph Encryption ["Sealing (at rest)"]
        direction TB
        KS["Key Share<br/>(plaintext, in enclave memory)"]
        ESK["Encrypt with<br/><b>Enclave Sealing Key</b><br/>(derived from AMD-SP,<br/>tied to VM measurement)"]
        SKS["Sealed Key Share<br/>(encrypted blob)"]
        EKMS["Encrypt / Wrap with<br/><b>KMS Wrapping Key</b><br/>(Azure Key Vault or<br/>GCP Cloud KMS)"]
        DEKS["Double-Encrypted Key Share<br/>(stored on persistent disk)"]

        KS --> ESK
        ESK --> SKS
        SKS --> EKMS
        EKMS --> DEKS
    end

    subgraph Decryption ["Unsealing (on restart)"]
        direction TB
        BOOT["VM boots<br/>AMD-SP establishes<br/>encrypted memory"]
        APP["TSA application starts<br/>requests attestation report"]
        ATT["Present attestation report<br/>to KMS (Secure Key Release)"]
        VER["KMS verifies attestation<br/>(correct measurement,<br/>correct policy)"]
        REL["KMS releases wrapping key<br/>(or unwraps outer envelope)"]
        UNSEAL["Application uses<br/>enclave sealing key<br/>to decrypt inner envelope"]
        READY["Key share in enclave memory<br/>ready for signing"]

        BOOT --> APP
        APP --> ATT
        ATT --> VER
        VER --> REL
        REL --> UNSEAL
        UNSEAL --> READY
    end

    DEKS -. "read from disk" .-> ATT
```

### Unsealing Procedure (on restart)

1. **VM boots**: AMD SEV-SNP Secure Processor establishes encrypted memory for the confidential VM. The host OS and hypervisor cannot read guest memory.
2. **Application starts**: The CC-TSA application initializes inside the enclave and requests an attestation report from the AMD Secure Processor. This report binds the VM's launch measurement, guest policy, and platform identity.
3. **Attestation to KMS**: The application presents the attestation report to the cloud KMS (Azure Key Vault with Managed HSM or GCP Cloud KMS) via a Secure Key Release / Confidential Key Release API.
4. **KMS verification**: The KMS verifies the attestation report against a pre-configured policy — checking that the launch measurement matches the expected CC-TSA build, that the guest policy enforces the required security settings, and that the platform certificate chains to AMD's root of trust.
5. **Wrapping key release**: Upon successful verification, the KMS releases the wrapping key (or directly unwraps the outer encryption layer of the sealed blob).
6. **Inner envelope decryption**: The application uses the enclave sealing key (derived from AMD-SP hardware, tied to the specific VM measurement) to decrypt the inner envelope.
7. **Key share ready**: The plaintext key share is now in encrypted enclave memory — accessible only to the CC-TSA process, protected by hardware-enforced memory encryption.

### Why Double Envelope?

| Approach | Weakness | Risk |
|---|---|---|
| **Sealing key alone** | Tied to hardware and VM measurement. If the VM image is updated (e.g., security patch), the sealing key changes and old sealed blobs cannot be decrypted. Additionally, AMD VCEK may rotate during platform maintenance. | Key share becomes permanently inaccessible after routine updates. |
| **KMS alone** | The KMS cannot independently verify that the requesting process runs inside a genuine enclave. A compromised host OS could impersonate the application. Additionally, the cloud provider has theoretical access to KMS-managed keys. | Key share exposed to compromised host or rogue cloud operator. |
| **Both together** | Neither weakness applies in isolation. KMS verifies attestation before releasing the wrapping key (ensures genuine enclave). Sealing key ensures only the correct enclave measurement can decrypt the inner layer (ensures correct code). | Defense in depth — both layers must be defeated simultaneously. |

This double-envelope design is essential for the multi-cloud deployment model described in [Architecture Overview](01-architecture-overview.md). Azure nodes use Azure Key Vault with Managed HSM; GCP nodes use GCP Cloud KMS with Confidential Key Release. The inner sealing layer is cloud-agnostic (AMD SEV-SNP on both platforms). See [Confidential Computing and Time](02-confidential-computing-and-time.md) for details on the AMD SEV-SNP attestation model.

---

## 6. Key Lifecycle State Diagram

The threshold signing key progresses through a well-defined set of states from initial generation to eventual retirement. The following state diagram captures all valid states and transitions.

```mermaid
stateDiagram-v2
    [*] --> Uninitialized

    Uninitialized --> DKG_In_Progress : Initiate DKG ceremony

    DKG_In_Progress --> Active : Ceremony complete,<br/>all 5 shares sealed

    Active --> Degraded : 1-2 nodes go offline<br/>(3-4 nodes remain)

    Degraded --> Active : Offline nodes recovered<br/>(all 5 nodes online)

    Degraded --> Suspended : 3+ nodes offline<br/>(fewer than 3 remain)

    Suspended --> Degraded : Some nodes recovered<br/>(3-4 nodes online)

    Active --> Rotating : Scheduled share refresh<br/>(proactive secret sharing)

    Rotating --> Active : Refresh complete,<br/>old shares securely deleted

    Active --> Compromised : Compromise detected
    Degraded --> Compromised : Compromise detected
    Suspended --> Compromised : Compromise detected

    Compromised --> Retired : Emergency revocation,<br/>certificate revoked

    Active --> Retired : Planned key rotation<br/>or decommission

    Retired --> Uninitialized : New DKG for replacement key

    Retired --> [*]
```

### State Descriptions

| State | Description | Signing Capability |
|---|---|---|
| **Uninitialized** | No key material exists. The system is awaiting a DKG ceremony. | None |
| **DKG In Progress** | The distributed key generation ceremony is running. All 5 nodes must be online and mutually attested. | None (ceremony in progress) |
| **Active** | All 5 key shares are distributed and sealed. The system is fully operational. | Full — any 3 of 5 nodes can sign |
| **Degraded** | 1-2 nodes are offline (3-4 nodes remain). Signing continues but fault tolerance is reduced. | Reduced margin — still operational |
| **Suspended** | Fewer than 3 nodes are online. Signing is halted because the threshold cannot be met. | None — halted |
| **Rotating** | Proactive share refresh is in progress (see Section 7). The public key does not change. Signing may be briefly paused during the refresh. | Paused during refresh (~seconds) |
| **Compromised** | A key compromise has been detected (e.g., a share leaked, anomalous signing behavior). Emergency procedures are activated. | Halted immediately |
| **Retired** | The key has been decommissioned. The corresponding certificate is revoked or expired. Existing timestamps signed by this key remain valid (certificate was valid at signing time). | None — permanently decommissioned |

### Monitoring and Alerts

State transitions generate alerts through the monitoring infrastructure described in [Operations and Deployment](05-operations-and-deployment.md):

- **Active to Degraded**: Warning — reduced fault tolerance. Operations team investigates and recovers the offline node(s).
- **Degraded to Suspended**: Critical — signing halted. Immediate response required.
- **Any state to Compromised**: Critical — emergency revocation procedure initiated. See [Failure Modes and Recovery](04-failure-modes-and-recovery.md) for the compromise response playbook.

---

## 7. Proactive Secret Sharing

### Why Refresh Shares?

Even without a confirmed compromise, periodic share refresh (proactive secret sharing) limits the window during which a stolen share is useful. Consider the following attack scenario:

1. An attacker exfiltrates a single key share `s_i` at time T.
2. The attacker now needs to steal 2 more shares to meet the 3-of-5 threshold.
3. If shares are refreshed at time T + 30 days, the stolen share `s_i` becomes mathematically unrelated to the new share `s_i'` held by node `i`.
4. The attacker must start over — their stolen share is worthless.

Share refresh also enables **node replacement**: when a node is decommissioned and replaced, the new node receives a fresh share during the refresh, and the old node's share is invalidated. No trust in the decommissioned node is required after the refresh.

### Protocol

The share refresh protocol uses the same communication pattern as DKG, with one critical difference: the random polynomials have a **zero constant term**, ensuring that the public key does not change.

```mermaid
sequenceDiagram
    autonumber
    participant N1 as Node 1
    participant N2 as Node 2
    participant N3 as Node 3
    participant N4 as Node 4
    participant N5 as Node 5

    Note over N1,N5: All 5 nodes participate<br/>(or all available nodes, minimum t=3)

    rect rgb(230, 240, 255)
        Note over N1,N5: Phase 1 — Generate Refresh Polynomials
        Note over N1: Generate random polynomial g_1(x)<br/>of degree t-1 = 2, with g_1(0) = 0
        Note over N2: Generate random polynomial g_2(x)<br/>of degree t-1 = 2, with g_2(0) = 0
        Note over N3: Generate random polynomial g_3(x)<br/>of degree t-1 = 2, with g_3(0) = 0
        Note over N4: Generate random polynomial g_4(x)<br/>of degree t-1 = 2, with g_4(0) = 0
        Note over N5: Generate random polynomial g_5(x)<br/>of degree t-1 = 2, with g_5(0) = 0
    end

    rect rgb(230, 255, 230)
        Note over N1,N5: Phase 2 — Exchange Refresh Sub-Shares
        N1->>N2: g_1(2) [attested TLS]
        N1->>N3: g_1(3) [attested TLS]
        N1->>N4: g_1(4) [attested TLS]
        N1->>N5: g_1(5) [attested TLS]
        Note over N1,N5: (All 5 nodes send refresh sub-shares to all others)
    end

    rect rgb(255, 245, 230)
        Note over N1,N5: Phase 3 — Compute New Shares
        Note over N1: s_1' = s_1 + g_1(1) + g_2(1) + g_3(1) + g_4(1) + g_5(1)
        Note over N2: s_2' = s_2 + g_1(2) + g_2(2) + g_3(2) + g_4(2) + g_5(2)
        Note over N3: s_3' = s_3 + g_1(3) + g_2(3) + g_3(3) + g_4(3) + g_5(3)
        Note over N4: s_4' = s_4 + g_1(4) + g_2(4) + g_3(4) + g_4(4) + g_5(4)
        Note over N5: s_5' = s_5 + g_1(5) + g_2(5) + g_3(5) + g_4(5) + g_5(5)
    end

    rect rgb(255, 235, 235)
        Note over N1,N5: Phase 4 — Verification & Cleanup
        Note over N1,N5: All nodes verify new shares via<br/>commitment verification (Feldman VSS)
        Note over N1,N5: Public key unchanged:<br/>sum of g_i(0) = 0 ∴ PK' = PK
        Note over N1: Securely delete old s_1<br/>(overwrite in enclave memory)
        Note over N2: Securely delete old s_2
        Note over N3: Securely delete old s_3
        Note over N4: Securely delete old s_4
        Note over N5: Securely delete old s_5
        Note over N1,N5: Re-seal new shares with<br/>double-envelope encryption (Section 5)
        Note over N1,N5: Delete old sealed blobs from disk
    end
```

### Key Properties of Share Refresh

- **Public key invariance**: Because all refresh polynomials have a zero constant term, `g_i(0) = 0` for all `i`. The sum of all `g_i(0)` values is zero, so the secret (the sum of all `f_i(0)` values from the original DKG) is unchanged. Since the public key is derived from the secret, it does not change. The X.509 certificate remains valid.
- **Forward security**: After the refresh, old shares are securely deleted. An attacker who steals a share before the refresh cannot combine it with shares stolen after the refresh — the mathematical relationship between old and new shares is destroyed by the random refresh polynomials.
- **No downtime**: The refresh protocol can be executed while the system is operational. Signing is briefly paused (on the order of seconds) during the transition from old shares to new shares to ensure consistency.

### Schedule

| Trigger | Action |
|---|---|
| **Scheduled (every 30 days)** | Routine proactive refresh. Limits the exposure window for any potentially compromised share. |
| **Node replacement** | When a node is decommissioned and a replacement node is introduced, a share refresh ensures the new node gets a valid share and the old node's share is invalidated. |
| **Suspected share compromise** | If monitoring detects anomalous behavior suggesting a share may have been exposed (see [Threat Model](07-threat-model.md)), an immediate refresh is triggered. |
| **Policy change** | Changes to the threshold parameters (e.g., moving from 3-of-5 to 4-of-7) require a fresh DKG, not just a refresh. |

For the operational procedures surrounding share refresh (automation, monitoring, rollback), see [Operations and Deployment](05-operations-and-deployment.md).

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
9. Herzberg, A., Jarecki, S., Krawczyk, H., Yung, M. — "Proactive Secret Sharing, Or: How to Cope with Perpetual Leakage" (CRYPTO '95)
10. AMD SEV-SNP — Strengthening VM Isolation with Integrity Protection and More (AMD White Paper)
