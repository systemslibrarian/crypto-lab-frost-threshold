import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import quicknet from './fixtures/drand-quicknet-round1.json';
import {
  BLS_BASIC_G1_DST,
  atsCombine,
  atsHash,
  atsKeygen,
  atsSignShare,
  atsTrace,
  atsVerify,
  bytesToHex,
  decodeBitmap,
  encodeBitmap,
  hexToBytes,
  verifyBlsG1Signature,
  type AtsKeySet,
  type AtsShare,
  type AtsSignature,
} from './bls-ats';
import { runFramingAttempts } from './framing';
import { runRogueKeyAttack } from './rogue-key-demo';

const message = new TextEncoder().encode('accountability needs an encoded signer set');

function sharesFor(keys: AtsKeySet, signers: number[], value = message): AtsShare[] {
  return signers.map((signer) =>
    atsSignShare(keys.secretKeys[signer - 1]!, value, signer),
  );
}

function signatureFor(keys: AtsKeySet, signers: number[], value = message): AtsSignature {
  const combined = atsCombine(keys, value, signers, sharesFor(keys, signers, value), keys.threshold);
  if (combined.kind !== 'signature') throw new Error('honest shares unexpectedly produced blame');
  return combined.signature;
}

function combinations(values: number[], choose: number): number[][] {
  if (choose === 0) return [[]];
  return values.flatMap((value, index) =>
    combinations(values.slice(index + 1), choose - 1).map((tail) => [value, ...tail]),
  );
}

function roundMessage(round: number): Uint8Array {
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64BE(BigInt(round));
  return createHash('sha256').update(encoded).digest();
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

describe('Boneh–Shoup accountable threshold BLS', () => {
  it('verifies all 10 subsets of 3-of-5 and traces the encoded signer set', () => {
    const keys = atsKeygen(5, 3);
    const subsets = combinations([1, 2, 3, 4, 5], 3);
    expect(subsets).toHaveLength(10);
    for (const signers of subsets) {
      const signature = signatureFor(keys, signers);
      expect(atsVerify(keys, message, signature, 3)).toMatchObject({ ok: true, signers });
      expect(atsTrace(signature, 5, [5, 4, 3])).toEqual(signers);
    }
  });

  it('matches an independent direct sum of dealer scalars', () => {
    const keys = atsKeygen(5, 3);
    const signers = [1, 3, 5];
    const signature = signatureFor(keys, signers);
    const scalar = signers.reduce(
      (sum, signer) => bls.fields.Fr.add(sum, bls.fields.Fr.fromBytes(hexToBytes(keys.secretKeys[signer - 1]!))),
      0n,
    );
    const direct = atsHash(message).multiply(scalar).toHex();
    expect(signature.sigma).toBe(direct);
  });

  it('rejects every single-bit bitmap edit and a same-size signer swap', () => {
    const keys = atsKeygen(5, 3);
    const signature = signatureFor(keys, [1, 2, 3]);
    const original = Number.parseInt(signature.bitmap, 16);
    for (let bit = 0; bit < 5; bit += 1) {
      const edited = { ...signature, bitmap: (original ^ (1 << bit)).toString(16).padStart(2, '0') };
      expect(atsVerify(keys, message, edited, 3).ok, `bit ${bit}`).toBe(false);
    }
    const swapped = { ...signature, bitmap: encodeBitmap([1, 2, 4], 5) };
    expect(atsVerify(keys, message, swapped, 3)).toMatchObject({
      ok: false,
      code: 'PAIRING_MISMATCH',
    });
  });

  it('enforces t even when a smaller signer set has a valid aggregate', () => {
    const keys = atsKeygen(5, 3);
    const twoSignerShares = sharesFor(keys, [1, 2]);
    const sigma = bls.G1.Point.fromHex(twoSignerShares[0]!.sigma)
      .add(bls.G1.Point.fromHex(twoSignerShares[1]!.sigma))
      .toHex();
    const candidate = { bitmap: encodeBitmap([1, 2], 5), sigma };
    expect(atsVerify(keys, message, candidate, 3)).toMatchObject({
      ok: false,
      code: 'WRONG_THRESHOLD',
    });
  });

  it('blames exactly the signer whose share fails verification', () => {
    const keys = atsKeygen(5, 3);
    const shares = sharesFor(keys, [1, 2, 3]);
    shares[1] = { signer: 2, sigma: sharesFor(keys, [4])[0]!.sigma };
    expect(atsCombine(keys, message, [1, 2, 3], shares, 3)).toEqual({
      kind: 'blame',
      blame: [2],
      checkedSigners: [1, 2, 3],
    });
  });

  it('rejects all three framing strategies', () => {
    const keys = atsKeygen(5, 3);
    const attempts = runFramingAttempts(keys, message, 5);
    expect(attempts.map((attempt) => attempt.id)).toEqual(['own-shares', 'random-point', 'reused-share']);
    expect(attempts.every((attempt) => !attempt.verification.ok)).toBe(true);
    expect(attempts.every((attempt) => attempt.attemptedSigners.includes(5))).toBe(true);
  });

  it('rejects a rogue cancellation key without a valid proof of possession', () => {
    const attack = runRogueKeyAttack(message);
    expect(attack.rawEquationPasses).toBe(true);
    expect(attack.proofAccepted).toBe(false);
    expect(attack.protectedVerification).toMatchObject({ ok: false, code: 'BAD_PROOF' });
    expect(attack.namedHonestSigners).toEqual([1, 2]);
  });

  it('traces the bitmap rather than mutable page state', () => {
    const signature: AtsSignature = {
      bitmap: encodeBitmap([2, 4, 5], 5),
      sigma: bls.G1.Point.BASE.toHex(),
    };
    expect(atsTrace(signature, 5, [1, 2, 3])).toEqual([2, 4, 5]);
  });

  it('round-trips bitmaps and rejects duplicates, out-of-range and spare bits', () => {
    expect(decodeBitmap(encodeBitmap([2, 4, 5], 5), 5)).toEqual([2, 4, 5]);
    expect(() => encodeBitmap([1, 1, 2], 5)).toThrow(/duplicate/i);
    expect(() => encodeBitmap([1, 6], 5)).toThrow(/outside/i);
    expect(() => decodeBitmap('80', 5)).toThrow(/spare bit/i);
  });

  it('rejects a malformed/non-subgroup signature encoding before pairing', () => {
    const keys = atsKeygen(3, 2);
    const malformed = { bitmap: encodeBitmap([1, 2], 3), sigma: '00'.repeat(48) };
    expect(atsVerify(keys, message, malformed, 2)).toMatchObject({
      ok: false,
      code: 'BAD_SIGNATURE',
    });
  });
});

describe('private drand quicknet published vector (not an accountable signature)', () => {
  it('verifies round 1, recomputes randomness, and rejects two negative controls', () => {
    expect(quicknet.scheme).toBe('bls-unchained-g1-rfc9380');
    expect(quicknet.dst).toBe(BLS_BASIC_G1_DST);
    const round1Message = roundMessage(quicknet.round);

    expect(verifyBlsG1Signature(quicknet.publicKey, round1Message, quicknet.signature)).toBe(true);
    expect(sha256Hex(hexToBytes(quicknet.signature))).toBe(quicknet.randomness);

    const changed = hexToBytes(quicknet.signature);
    changed[changed.length - 1]! ^= 0x01;
    expect(verifyBlsG1Signature(quicknet.publicKey, round1Message, bytesToHex(changed))).toBe(false);
    expect(verifyBlsG1Signature(quicknet.publicKey, roundMessage(2), quicknet.signature)).toBe(false);
  });
});
