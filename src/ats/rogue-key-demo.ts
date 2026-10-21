/**
 * Deliberately broken comparison used only by the rogue-key break-it control.
 * `rawEquationPasses` omits proof-of-possession registration to expose exactly
 * why the real ATS verifier must reject this roster. It is never the default
 * verifier and lives outside bls-ats.ts so the unsafe path cannot be mistaken
 * for the construction.
 */

import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  atsHash,
  atsKeygen,
  atsPopProve,
  atsPopVerify,
  atsVerify,
  encodeBitmap,
  hexToBytes,
  type AtsSignature,
  type AtsVerifyResult,
} from './bls-ats';

export interface RogueKeyResult {
  namedHonestSigners: number[];
  rogueSigner: number;
  roguePublicKey: string;
  proofAccepted: boolean;
  rawEquationPasses: boolean;
  protectedVerification: AtsVerifyResult;
  candidate: AtsSignature;
}

export function runRogueKeyAttack(message: Uint8Array): RogueKeyResult {
  const honest = atsKeygen(2, 2);
  const attacker = atsKeygen(1, 1);
  const attackerSecret = bls.fields.Fr.fromBytes(hexToBytes(attacker.secretKeys[0]!));

  const honestSum = honest.publicKeys
    .map((key) => bls.G2.Point.fromHex(key))
    .reduce((sum, key) => sum.add(key), bls.G2.Point.ZERO);
  const attackerAggregateKey = bls.G2.Point.BASE.multiply(attackerSecret);
  const roguePoint = attackerAggregateKey.subtract(honestSum);
  roguePoint.assertValidity();
  const roguePublicKey = roguePoint.toHex();

  // This proof is valid for x*g2, not for the cancellation key above. The
  // attacker cannot make a valid proof for the rogue key without knowing its
  // discrete logarithm (which depends on both honest secret keys).
  const invalidRogueProof = atsPopProve(attacker.secretKeys[0]!);
  const roster = {
    publicKeys: [...honest.publicKeys, roguePublicKey],
    proofs: [...honest.proofs, invalidRogueProof],
  };
  const candidate: AtsSignature = {
    bitmap: encodeBitmap([1, 2, 3], 3),
    sigma: atsHash(message).multiply(attackerSecret).toHex(),
  };

  // Unsafe equation with no registration check: sum(pk_1, pk_2, pk_rogue)
  // equals x*g2, so the attacker's x*H(m) signature passes while naming the
  // two honest keys.
  const aggregate = roster.publicKeys
    .map((key) => bls.G2.Point.fromHex(key))
    .reduce((sum, key) => sum.add(key), bls.G2.Point.ZERO);
  const left = bls.pairing(bls.G1.Point.fromHex(candidate.sigma), bls.G2.Point.BASE);
  const right = bls.pairing(atsHash(message), aggregate);
  const rawEquationPasses = bls.fields.Fp12.eql(left, right);

  return {
    namedHonestSigners: [1, 2],
    rogueSigner: 3,
    roguePublicKey,
    proofAccepted: atsPopVerify(roguePublicKey, invalidRogueProof),
    rawEquationPasses,
    protectedVerification: atsVerify(roster, message, candidate, 3),
    candidate,
  };
}
