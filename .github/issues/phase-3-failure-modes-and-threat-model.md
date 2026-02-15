# Adopt immutable software + ephemeral key model: Failure modes and threat model

## Summary

Phase 3 of 3. Updates the failure modes/recovery documentation and threat model to reflect the immutable software + ephemeral key model established in Phases 1 and 2.

The failure modes doc currently assumes key shares are recoverable from KMS-backed sealed storage. Under the new model, key shares are ephemeral — any node failure means that node's share is gone. Recovery is always via new DKG (if <3 nodes remain) or share redistribution (if ≥3 nodes still hold shares in memory). The threat model must be updated to remove the KMS-policy-manipulation attack surface and strengthen the trust claims around operator exclusion.

**Depends on: Phase 1 (core model) and Phase 2 (operations overhaul)**

## Changes required

### docs/04-failure-modes-and-recovery.md — Major rewrite (7 sections)

1. **Section 1 "Failure Mode Decision Tree" (lines 16-51)** — Major rewrite
   - Current tree asks "Key material safe?" with answer "YES — shares sealed in KMS-backed storage"
   - New tree: "Key material available?" depends on "How many nodes still have shares in memory?"
     - ≥3 nodes with in-memory shares → signing continues, can redistribute share to replacement node
     - <3 nodes with in-memory shares → signing halted, new DKG required when ≥5 nodes available
   - Remove all references to KMS-backed storage as a safety net

2. **Section 2 "Single Node Failure" (lines 82-129)** — Major rewrite
   - Current: 3-tier recovery based on KMS key availability (Tier 1: automatic restart + unseal, Tier 2: cold standby, Tier 3: new provisioning)
   - New model: Single node failure → 4 nodes remain with shares → signing continues at reduced fault tolerance → replacement node provisioned → share redistributed to new node via threshold protocol (if retained from Phase 1) or new DKG
   - Remove all tier layering based on KMS availability
   - Key change: recovery no longer depends on unsealing; it depends on whether threshold is maintained

3. **Section 4 "Three or More Node Failure" (lines 181-212)** — Major rewrite of recovery
   - This is now the critical boundary: <3 nodes = key is irrecoverably lost (by design)
   - Recovery: wait for nodes to be available → run new DKG → obtain new certificate → resume signing
   - Reframe: this is not a catastrophe, it's the expected cost of the ephemeral model. The tradeoff is explicit: stronger trust guarantees in exchange for key regeneration when quorum is lost.

4. **Section 5 "All-Node Failure (Complete Outage)" (lines 216-320)** — COMPLETE SECTION REWRITE
   - **Lines 222-229 "Key Material Status"**: Currently states keys survive in sealed storage. Change to: keys are lost. This is expected.
   - **9-step recovery procedure (lines 251-310)**: Replace entirely. New procedure:
     1. Boot all 5 nodes with the same immutable software image
     2. Nodes verify each other's attestation (same measurement as before)
     3. Run DKG ceremony across all 5 nodes
     4. Obtain new certificate from CA (or reuse existing if CA supports re-keying with same identity)
     5. Resume signing
   - Remove all steps involving KMS attestation, wrapping key release, and envelope decryption
   - RTO estimate: DKG ceremony time (5-15 min) + certificate issuance time (1-5 min)

5. **Section 6 "Irrecoverable Key Loss" (lines 322-401)** — Conceptual rewrite
   - "Irrecoverable key loss" is no longer a rare disaster — it's what happens whenever <3 nodes are available. Rename to something like "Key Regeneration After Quorum Loss."
   - Remove panic-inducing language. This is a designed-in property, not a failure.
   - The distinction between "key loss" and "key compromise" remains important: key loss = new DKG + new cert. Key compromise = revoke old cert + new DKG + new cert + forensic investigation.
   - **Lines 345-348**: The existing text about old timestamps remaining valid still applies and should be retained.

6. **Section 8 "Cluster Health State Machine" (lines 488-551)** — Moderate edit
   - Update state descriptions: instead of "key material safe in KMS," state "key material exists in memory of running nodes only"
   - Change messaging around degraded states: "Must recover nodes before additional failures cause quorum loss and key regeneration"

7. **Section 10 "Attestation Failure" (lines 595-658)** — MAJOR REWRITE
   - **Current recovery (lines 618-622)**: "Before deploying any update that changes measurements, update the KMS attestation policy to accept the new measurement."
   - **This entire concept is removed.** Under the immutable model:
     - Software is immutable → measurement never changes during the lifetime of a key
     - If attestation fails, it means either: (a) hardware issue (AMD-SP), (b) the wrong software image was deployed, or (c) platform firmware changed
     - Recovery for (a) and (b): replace node, ensure correct image, rejoin via DKG or share redistribution
     - Recovery for (c): platform firmware changes (AMD-SP updates by cloud provider) change the platform TCB version but not the launch measurement. The mutual attestation between nodes can be configured to pin the launch measurement while accepting a range of platform TCB versions.
   - **Remove the rolling update measurement diagram (lines 641-657)** — no longer applicable
   - **Remove "Safe Deployment Order" procedure** — software changes are now all-or-nothing key rotation events, not rolling updates

### docs/07-threat-model.md — Moderate edit (3 sections)

1. **Section 2 "Trust Assumptions" (lines 63-77)** — Moderate edit
   - **Remove or downgrade "Cloud provider KMS" trust assumption**: KMS is no longer in the critical path for key management. If KMS is retained for other purposes, note its reduced role.
   - **Strengthen "TSA application code" assumption (line 76)**: The application code is now immutable for the lifetime of a signing key. Its measurement is published and bound to the certificate. Relying parties can independently verify the measurement against the published, reproducibly-built binary. This is stronger than "must be correct, audited, and built reproducibly" — it's now cryptographically verifiable.
   - **Add new trust assumption: "Software immutability"**: Operators cannot modify the running software without triggering key rotation. This removes the operator from the trust chain for signing operations.

2. **Section 4 "STRIDE Analysis — Tampering/Information Disclosure" (lines 170-197)** — Moderate edit
   - **Line 194**: Current: "operator could redeploy a backdoored image (detected by measurement change)"
   - Change to: "operator cannot redeploy a backdoored image without triggering key rotation and new certificate issuance. The old certificate is bound to the old measurement. The backdoored image would require a new DKG, producing a new public key and new certificate — which is visible to all relying parties and would require CA cooperation."
   - This changes the threat from "detected" to "structurally prevented" — a much stronger claim.
   - **Key share extraction threat**: Update from "extract sealed blob from storage" to "extract from hardware-encrypted enclave memory during operation." The attack surface is now runtime-only, not at-rest + runtime.

3. **Section 6 "Residual Risks" (lines 278-289)** — Moderate edit
   - **R8 "KMS provider collusion" (line 288)**: Remove or downgrade. KMS is no longer in the key management path. If retained for other uses, note the reduced blast radius.
   - **Add new residual risk**: "Simultaneous loss of ≥3 nodes requires key regeneration (new DKG + new certificate). This is by design but creates a brief service interruption. Mitigated by multi-provider deployment making simultaneous loss of ≥3 nodes across 2+ providers extremely unlikely."
   - **Strengthen R7 "Supply chain compromise" (line 287)**: Note that supply chain compromise now requires CA cooperation to produce a valid certificate for the compromised binary. The measurement is bound to the certificate, so a compromised binary with a different measurement cannot reuse the existing certificate.

## Acceptance criteria

- [ ] All recovery procedures assume ephemeral keys — no references to KMS unsealing, sealed blobs, or wrapping keys
- [ ] "Irrecoverable key loss" is reframed as a designed-in property, not a failure mode
- [ ] Attestation failure recovery does not involve updating KMS policies to accept new measurements
- [ ] The threat model explicitly claims that operators cannot change running software without visible key rotation
- [ ] The operator-backdoor-via-KMS-policy attack surface (current `07-threat-model.md:194`) is eliminated, not just detected
- [ ] Residual risks are updated to reflect the new (smaller) attack surface

## Context

This is Phase 3 of 3. Depends on Phase 1 (core model) and Phase 2 (operations). After all three phases, the documentation should present a coherent, self-consistent architecture where:

1. Software is immutable for the lifetime of a signing key
2. Key shares exist only in enclave memory (no persistence)
3. The attestation measurement is bound to the TSA certificate and published
4. Software changes require coordinated key rotation (new DKG + new certificate)
5. Relying parties can cryptographically verify exactly what software produced their timestamps
6. No operator action can change the running software without triggering visible key rotation

This eliminates the trust contradiction where the design claimed "no need to trust the operator" while giving operators the ability to change KMS attestation policies to accept arbitrary software measurements.
