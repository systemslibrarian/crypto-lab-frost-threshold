# frost-threshold Specification

## Scope
This document specifies the browser demo implementation for FROST over Ed25519 using RFC 9591 and the `frost-ed25519` crate.

## Ciphersuite
- Curve/group: Ed25519
- Signature type: Schnorr-style Ed25519 signature (64 bytes)
- FROST suite: FROST(Ed25519, SHA-512)
- Reference standard: RFC 9591
- Rust implementation: `frost-ed25519` v2

## Parameters
- Participant count `n`: 2..7 (UI range)
- Threshold `t`: 2..n
- Round 1 commitments:
  - hiding commitment: 32 bytes
  - binding commitment: 32 bytes
- Signature share:
  - scalar: 32 bytes
- Group verifying key:
  - compressed point: 32 bytes
- Final signature:
  - 64 bytes

## Protocol Flow
1. Key generation (trusted dealer)
- `frost_keygen(t, n)` calls `keys::generate_with_dealer`.
- Output includes:
  - group public key (`VerifyingKey`)
  - one secret share per participant: identifier, signing share scalar, VSS commitment vector

2. Participant selection
- Any subset of size `t` may sign.

3. Round 1
- For each selected participant, `frost_round1_commit(identifier)` produces:
  - secret nonces (hiding + binding)
  - public commitments (hiding + binding)
- Nonces are stored in memory-only session state.

4. Round 2
- For each selected participant, `frost_round2_sign(...)`:
  - validates/de-serializes share + commitments
  - builds `SigningPackage`
  - calls `round2::sign`
  - returns signature share

5. Aggregation
- `frost_aggregate(...)`:
  - validates/de-serializes signature shares + commitments
  - builds `PublicKeyPackage`
  - calls `aggregate`
  - verifies output with `VerifyingKey::verify`

## Session State Lifecycle
1. Fresh session
- Empty keys, no selections, no commitments, no signature shares.

2. After keygen
- Stores group public key and all `n` participant shares.

3. After selection
- Stores exactly `t` selected participant identifiers.

4. After Round 1
- Stores nonce material and commitments by selected identifier.
- Nonces never rendered in UI.

5. After Round 2
- Stores signature share per selected identifier.

6. After aggregation
- Stores final signature and verification result.
- History stores prior successful signature for subset comparison.

7. Reset behaviors
- Full reset clears keys and all signing artifacts.
- Subset retry keeps keys/message, clears signing artifacts.

## Serialization Format
All external values are lowercase hex strings.

- Identifier: 32-byte scalar encoding (64 hex chars)
- Signing share scalar: 32 bytes
- VSS coefficient commitment: each 32-byte point
- Nonce: 32-byte scalar
- Nonce commitment: 32-byte point
- Signature share: 32-byte scalar
- Group verifying key: 32-byte point
- Final signature: 64 bytes (128 hex chars)
- Message: arbitrary bytes represented as hex

## WASM API Contract
- `frost_keygen(threshold, num_participants)`
- `frost_round1_commit(identifier_hex)`
- `frost_round2_sign(input_json)`
- `frost_aggregate(input_json)`

## Known Test Coverage
- Keygen size/shape test (`3-of-5`)
- Round 1 freshness + distinct commitments
- End-to-end signing tests:
  - `2-of-3`
  - `3-of-5`
  - `5-of-5`
- Negative-path tests:
  - wrong commitment list in Round 2
  - under-threshold aggregation error

## RFC 9591 Vectors
RFC 9591 Appendix B vectors are normative references for future hardening.
Current test suite validates protocol invariants and end-to-end correctness with live randomized runs. Appendix B vector ingestion can be added as a deterministic fixture extension.
