# frost-threshold Threat Model

## Security Goals
- Demonstrate real threshold signing with FROST over Ed25519.
- Show that any valid subset of size `t` can produce a verifiable standard signature.
- Prevent accidental disclosure of nonces in UI rendering.

## What This Demo Proves
- The key is split and signing is share-based.
- Signature shares alone are not full signatures.
- Aggregated output verifies as standard Ed25519 signature bytes.
- Different valid subsets can produce different but valid signatures.

## What This Demo Does Not Prove
- Production readiness under hostile endpoint compromise.
- Network transport security between independent signer devices.
- Hardware-backed key isolation.
- Byzantine coordinator hardening beyond protocol-level checks.

## Trusted Dealer Limitation
This demo uses trusted dealer key generation (`generate_with_dealer`).
- Dealer sees full secret material during setup.
- Malicious dealer can bias or exfiltrate shares.

How DKG addresses this:
- Distributed key generation removes single trusted dealer.
- Participants jointly produce shares without a single party learning full signing key.

## Nonce Reuse Catastrophe
Nonce reuse in Schnorr/FROST leaks long-term key material.
- Reusing hiding/binding nonces across signatures can reveal share secrets.
- Demo mitigations:
  - Fresh nonces generated each Round 1 call with CSPRNG (`getrandom`/Web Crypto)
  - Nonces stored in-memory only
  - Nonces never displayed by UI
  - Nonces zeroized after Round 2 signing in Rust

## Browser Security Boundaries
Assumptions:
- Browser runtime and JS engine are not actively compromised.
- No malicious extension is reading memory/DOM state.

Risks:
- XSS could exfiltrate in-memory shares/nonces.
- Devtools and memory snapshots can expose secret state.
- Side-channel concerns are outside demo scope.

## Data Handling
- Secrets are kept in memory only.
- No localStorage/sessionStorage persistence.
- Secret bytes are zeroized where feasible in Rust bridge.

## Coordinator and Aggregator Risks
- Coordinator can deny service by withholding/biasing package assembly.
- Misreporting and liveness are not fully addressed by this educational UI.

## Why This Is a Demo
This project is intentionally educational and transparent.
- It prioritizes conceptual clarity and protocol traceability.
- It is not a hardened distributed signer service.

Production systems require:
- DKG and robust key ceremony
- authenticated channels and anti-replay controls
- audit logging and secure enclaves/HSMs
- key lifecycle and incident response controls
