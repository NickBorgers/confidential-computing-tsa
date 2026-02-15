# Adopt immutable software + ephemeral key model: Core architecture and cryptography

## Summary

The current design allows rolling software updates and persists key shares across reboots using double-envelope encryption (AMD-SP sealing key + cloud KMS wrapping key). This creates a fundamental trust contradiction: the design claims relying parties can verify trust via attestation "without trusting the CC-TSA operator," but the rolling update procedure gives operators the ability to change which software measurements the KMS accepts — effectively requiring relying parties to trust that operators only deploy legitimate code.

**Decision: adopt an immutable software + ephemeral key model.** Software is fixed for the lifetime of a signing key. Key shares exist only in enclave memory and are lost on reboot. Software changes require key rotation (new DKG + new certificate). The attestation measurement becomes part of the TSA's cryptographic identity, not just an operational detail.

## Motivation

The rolling update procedure (`docs/04-failure-modes-and-recovery.md` lines 620-657) has the operator:

1. Build new application image
2. Calculate new launch measurement
3. **Update KMS policy to accept BOTH old AND new measurements**
4. Deploy to nodes one at a time
5. Remove old measurement from KMS policy

Step 3 means the operator controls which measurements the KMS accepts. A backdoored image's measurement can be added just as easily as a legitimate one. The threat model acknowledges this at `docs/07-threat-model.md:194` ("operator could redeploy a backdoored image — detected by measurement change"), but detection requires someone independently verifying measurements. The KMS won't stop it — the operator just updated the policy.

The immutable model resolves this: the measurement is fixed at DKG time, published alongside the certificate, and independently verifiable. No operator can subsequently change the running code without triggering a new DKG and new certificate issuance.

## Changes required

### README.md — Moderate edit

- **Line 94** ("KMS-backed persistence survives restarts"): Rewrite to reflect ephemeral model. Key shares exist only in memory; restarts require re-keying.
- **Line 14** ("3-of-5 threshold shares, each in a separate enclave — key never reconstructed"): Threshold claim is still valid. Add that keys are ephemeral and measurement is bound to certificate.
- Update the "Quick Answers" section to explain: keys are generated fresh via DKG, survive only while nodes run, and are discarded on shutdown.

### docs/01-architecture-overview.md — Major rewrite (5 sections)

1. **Section 2.1 "Enclave Nodes" — Key Share Storage row (line 139)**
   - Current: "At rest, it is wrapped (encrypted) by the provider's KMS under a key that can only be released to an attested enclave"
   - Change to: Key share exists only in enclave memory during operation. No at-rest persistence. If the node reboots, the key share is gone and a new DKG is required.

2. **Section 2.4 "KMS (Per-Provider)" (lines 187-204)** — Complete section removal or repurposing
   - The entire KMS section describes wrapping keys, Secure Key Release, and the 5-step key lifecycle with KMS. This is obsolete.
   - If KMS is retained for any purpose (e.g., encrypting audit logs, CA operations), keep a minimal reference. Otherwise remove entirely.
   - Remove the KMS boxes from the architecture diagram (lines 108-119).

3. **Section 2.6 "Monitoring" (line 236)** — Minor tweak
   - Remove "Key share sealed/unsealed, KMS connectivity" metric
   - Replace with "Key generation status, DKG ceremony health"

4. **Section 6.2 "Availability" (line 673)** — Moderate edit
   - Current: "allows for rolling updates, AZ failures, and individual node issues without downtime"
   - Remove "rolling updates" — software changes now require coordinated DKG, not rolling updates

5. **Add new section: "Software Immutability and Measurement Identity"**
   - Explain that the TSA software is immutable for the lifetime of a signing key
   - The attestation measurement is published alongside the TSA certificate
   - Any software change requires: retire old key → deploy new software → new DKG → new certificate
   - This ensures relying parties can cryptographically verify exactly what code produced their timestamps

### docs/03-quantum-safe-threshold-crypto.md — Major rewrite (4 sections)

1. **Section 4 "DKG" (lines 232-334)** — Moderate edit
   - DKG is no longer a one-time ceremony. It runs on first boot and whenever the cluster is reconstituted.
   - Clarify that DKG establishes the key for the lifetime of that software version.
   - Remove Phase 8 "Key Share Sealing" (lines 321-326) or replace with "keys remain in memory only."

2. **Section 5 "Key Share Persistence — Double-Envelope Encryption" (lines 337-404)** — COMPLETE DELETION
   - This entire section (problem statement, solution, Mermaid diagrams, unsealing procedure, "Why Double Envelope?" table) is obsolete.
   - Replace with a brief section explaining: "Key shares exist only in enclave memory. They are not persisted to durable storage. If a node shuts down, its key share is irrecoverably lost. This is by design — it eliminates the at-rest key material attack surface and removes the KMS dependency from the trust model."

3. **Section 6 "Key Lifecycle State Diagram" (lines 407-464)** — Major rewrite
   - Remove the `Rotating` state (no proactive share refresh needed in ephemeral model)
   - Remove transitions involving sealed/unsealed states
   - Add clarity: `Active → Retired` is the path for software changes (not updates — retirements)
   - Simplify: the key lifecycle is DKG → Active → (Degraded ↔ Active) → Retired. No persistence transitions.

4. **Section 7 "Proactive Secret Sharing" (lines 467-552)** — Major simplification or deletion
   - The primary justification for share refresh ("limits the window during which a stolen share is useful") is less relevant when shares are ephemeral and never persisted to storage.
   - Option A: Delete entirely. Share refresh is unnecessary if keys are ephemeral.
   - Option B: Retain as a mechanism for adding/removing nodes from a running cluster without full DKG. Reframe from "security refresh" to "membership change protocol."

## Acceptance criteria

- [ ] No references to double-envelope encryption, KMS wrapping keys, or Secure Key Release remain in the three core docs
- [ ] The trust model explicitly states: relying parties can verify the exact software that signed their timestamps via the published measurement bound to the certificate
- [ ] The key lifecycle is clear: DKG on first boot → keys in memory only → software change = new DKG + new cert
- [ ] The KMS section is either removed or clearly repurposed for non-key-persistence uses
- [ ] All Mermaid diagrams are updated to reflect the new model

## Context

This is Phase 1 of 3. This phase establishes the new core model. Phases 2 and 3 update the operational procedures and failure/threat documentation to match.
