/**
 * attacks.test.ts — the two named FROST failure modes, checked against the real
 * @noble/curves Ed25519 verifier.
 *
 * Teeth:
 *  - an honest FROST(Ed25519) aggregate verifies (the pipeline is real, not a
 *    stub) — if it didn't, every attack claim would be meaningless;
 *  - nonce reuse across three sessions recovers the EXACT group secret and the
 *    forged signature is ACCEPTED by the real verifier;
 *  - fresh nonces (control) recover the wrong key and the forgery is REJECTED;
 *  - dropping the RFC 9591 binding factor at aggregation makes the real verifier
 *    REJECT, while the correctly-bound aggregate is ACCEPTED.
 */

import { describe, expect, it } from 'vitest';
import {
  keygen,
  frostSign,
  lagrangeCoeff,
  runNonceReuse,
  runBindingOmission,
} from './attacks';
import { ed25519 } from '@noble/curves/ed25519.js';

const B = ed25519.Point.BASE;
const L = ed25519.Point.Fn.ORDER;
const mod = (x: bigint): bigint => ((x % L) + L) % L;

describe('real FROST(Ed25519) pipeline', () => {
  it('an honest t-of-n aggregate verifies under the real Ed25519 verifier', async () => {
    const group = keygen(2, 3);
    const set = group.signers.slice(0, 2);
    const nonces = new Map(
      set.map((s) => [
        s.id,
        { d: mod(BigInt(`0x${s.id}9a3f`) + 7n), e: mod(BigInt(`0x${s.id}c1d2`) + 11n) },
      ]),
    );
    const out = await frostSign(group, set, 'hello', nonces);
    expect(out.verified).toBe(true);
  });

  it('Lagrange coefficients reconstruct the group secret from any threshold subset', () => {
    const group = keygen(3, 5);
    const set = group.signers.slice(1, 4); // arbitrary 3-of-5 subset
    const ids = set.map((s) => s.id);
    let x = 0n;
    for (const s of set) x = mod(x + mod(lagrangeCoeff(s.id, ids) * s.share));
    expect(x).toBe(group.secret);
    expect(B.multiply(x).toBytes()).toEqual(group.publicKeyEnc);
  });
});

describe('Attack 1 — nonce reuse across signing attempts', () => {
  it('reuse ⇒ recovers the exact group secret and the forgery is ACCEPTED', async () => {
    const r = await runNonceReuse(true);
    expect(r.sessionsVerified).toBe(true);
    expect(r.recoveredSecretHex).toBe(r.secretHex);
    expect(r.keyRecovered).toBe(true);
    expect(r.forgeryAccepted).toBe(true);
  });

  it('fresh nonces (control) ⇒ wrong key, forgery REJECTED', async () => {
    const r = await runNonceReuse(false);
    expect(r.sessionsVerified).toBe(true);
    expect(r.keyRecovered).toBe(false);
    expect(r.forgeryAccepted).toBe(false);
  });
});

describe('Attack 2 — skipping the nonce-commitment binding factor', () => {
  it('correct binding ACCEPTS, dropped binding factor is REJECTED', async () => {
    const r = await runBindingOmission();
    expect(r.boundVerified).toBe(true);
    expect(r.unboundVerified).toBe(false);
  });
});
