# Adopt immutable software + ephemeral key model: Operations overhaul

## Summary

Phase 2 of 3. Updates the operations and deployment documentation to reflect the immutable software + ephemeral key model established in Phase 1.

The operations guide currently describes rolling updates (update KMS policy, deploy one node at a time, remove old measurement), proactive share refresh schedules, KMS-dependent backup/recovery, and key share sealing procedures. All of these are obsolete under the new model and must be replaced with: coordinated DKG ceremonies, software-change-as-key-rotation procedures, and simplified backup (no sealed blobs to back up).

**Depends on: Phase 1 (core model changes to README, 01-architecture-overview, 03-quantum-safe-threshold-crypto)**

## Changes required

### docs/05-operations-and-deployment.md — Major rewrite (8 sections)

1. **Section 1.2 "Key Management" (lines 43-59)** — Major rewrite
   - Current: Describes Azure Key Vault MHSM, GCP Cloud KMS, wrapping keys, double-envelope encryption
   - Change to: Key shares exist only in enclave memory. No KMS dependency for key management. No wrapping keys. No double-envelope encryption.
   - Remove or repurpose KMS infrastructure requirements if KMS is no longer needed
   - Update networking requirements (Section 1.3, line 66): remove "Node-to-KMS" connectivity requirement

2. **Section 2 "Deployment Topology Options" (lines 87-237)** — Moderate edit
   - Remove KMS nodes from topology diagrams
   - Remove text explaining KMS availability per provider as a topology consideration
   - Simplify: topology is now driven by cloud availability zones and network latency, not KMS placement

3. **Section 3 "DKG Ceremony Procedure" (lines 249-432)** — Major rewrite
   - Currently describes DKG as a one-time ceremony. Must be rewritten to reflect it runs on every cluster (re)constitution.
   - **Phase 8 "Key Share Sealing" (lines 417-418)**: Delete entirely. No sealing step. Keys remain in memory.
   - **Phase 9 "Ceremony Completion" (line 419)**: Remove reference to sealed blob archival.
   - **Section 3.1 "Prerequisites" (lines 257-264)**: Remove "KMS configured with attestation policies" prerequisite.
   - Add new subsection: "When DKG runs" — first boot, after any node reboot that breaks quorum, and after software version changes.
   - Add new subsection: "Certificate issuance as part of DKG" — every DKG produces a new key, which requires a new certificate. Describe the workflow: DKG → public key derivation → CSR → CA issuance → certificate distribution.

4. **Section 4.4 "Proactive Share Refresh" (lines 557-585)** — Delete or repurpose
   - If Section 7 of doc 03 was deleted in Phase 1: delete this operational section too.
   - If retained as membership-change protocol: rewrite to match.

5. **Section 5 "Rolling Update Procedure" (lines 589-697)** — COMPLETE SECTION REWRITE
   - **This is the most critical change.** The entire rolling update procedure is replaced with:
     - **"Software Version Change Procedure"**: a coordinated process, not a rolling one.
     - Steps: (1) Build new image, publish new measurement alongside new image hash. (2) Halt signing on current cluster. (3) Deploy new image to all 5 nodes. (4) Boot all nodes with new image. (5) Run DKG across all 5 nodes. (6) Obtain new certificate from CA for new public key. (7) Distribute certificate. (8) Resume signing. (9) Publish new measurement + certificate binding.
   - Remove "Accept both measurements during update window" concept entirely (lines 684).
   - Remove "Rollback plan" based on KMS policy (line 686). New rollback: if new image fails, redeploy old image and re-run DKG with old measurement + old certificate (if still valid) or new certificate for old key.
   - Update estimated duration: includes DKG ceremony time + certificate issuance time.
   - **Key safety rule**: the measurement published with the certificate MUST match the running binary. This is the core trust guarantee.

6. **Section 6 "Node Replacement" (lines 700-781)** — Major simplification
   - Current: Describes tiered recovery (automatic restart with unsealing, cold standby activation, new node provisioning) with share transfer via proactive refresh.
   - New model: If a node fails and the cluster still has ≥3 nodes with keys in memory, signing continues. The failed node is replaced by provisioning a new node, but it cannot participate in signing until the next DKG includes it (or a share refresh grants it a share from the running cluster, if that mechanism is retained).
   - Remove all references to "sealed share transfer" and "KMS key release for new node."

7. **Section 8 "Backup & Disaster Recovery" (lines 955-1047)** — Major rewrite
   - **What is backed up (lines 958-967)**:
     - Remove "Sealed key share blobs" row — no longer exist.
     - Remove "KMS wrapping keys" row — no longer applicable.
     - Retain: TSA certificate + chain, application image, DKG ceremony transcript, configuration.
     - Add: Published measurement-to-certificate binding records.
   - **RTO/RPO table (lines 1018-1024)**:
     - All failure scenarios now have the same recovery model: if ≥3 nodes still running → signing continues; if <3 nodes → new DKG + new cert required.
     - "Full outage" RTO changes from "5-15 min (unseal)" to "5-15 min (DKG) + certificate issuance time."
     - "Irrecoverable key loss" is no longer a special case — it's the expected outcome of any scenario where <3 nodes are available. Reframe as normal operation, not catastrophe.
   - **RPO discussion (lines 1026-1032)**: Remove "RPO is 0" claim for most scenarios. RPO for the signing key is always "key lost" on full outage — but this is by design, not a failure.
   - **DR testing (lines 1036-1047)**: Replace "KMS failover" test with "Full DKG ceremony drill." Increase DKG ceremony drill frequency from annual to quarterly (it's now a routine operation, not a rare ceremony).

8. **Section 9 "Compliance Mapping" (lines 1050-1079)** — Moderate edit
   - **Key protection (ETSI EN 319 421 Section 7.3, line 1058)**: Remove "double-envelope encryption (hardware sealing + KMS wrapping)." Replace with: "Threshold shares (3-of-5) in SEV-SNP enclaves; ephemeral key material exists only in hardware-encrypted memory; software immutability ensures measurement integrity; key rotation on any software change."
   - **Key generation (line 1057)**: Add that DKG ceremony now runs at every cluster constitution, not one-time.
   - **Disaster recovery (line 1062)**: Update to reflect DKG-based recovery instead of KMS-backed recovery.
   - **Compliance evidence (lines 1071-1078)**: Update evidence collection to reflect no sealed key blobs, add measurement-to-certificate binding records.

### docs/02-confidential-computing-and-time.md — Minor edit

1. **Attestation Boot Chain section (lines 470-482)** — Minor tweak
   - Current: Step 6 describes "KMS releases sealed key share"
   - Change to: Attestation is used for mutual verification between nodes during DKG, not for KMS key release. Remove or reframe the KMS interaction in the boot chain description.
   - The attestation model itself (AMD-SP, VCEK, measurement) is unchanged — only its purpose shifts from "gate KMS key release" to "verify node identity during DKG."

## Acceptance criteria

- [ ] No references to rolling updates, KMS policy updates, or sealed key share recovery remain
- [ ] The DKG ceremony is described as a routine operation (every cluster constitution), not a rare one-time event
- [ ] Software version changes are described as coordinated key rotation procedures
- [ ] Backup/DR documentation reflects that key material is intentionally ephemeral
- [ ] Compliance mapping is updated to justify the ephemeral model to auditors
- [ ] All operational procedures are self-consistent with the core model from Phase 1

## Context

This is Phase 2 of 3. Depends on Phase 1 (core architecture and cryptography docs). Phase 3 covers failure modes and threat model.
