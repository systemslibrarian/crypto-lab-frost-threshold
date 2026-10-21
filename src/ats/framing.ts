import {
  atsKeygen,
  atsSignShare,
  atsVerify,
  encodeBitmap,
  sumEncodedSignatures,
  type AtsKeySet,
  type AtsSignature,
  type AtsVerifyResult,
} from './bls-ats';

export interface FramingAttempt {
  id: 'own-shares' | 'random-point' | 'reused-share';
  label: string;
  attemptedSigners: number[];
  actualInputs: number[];
  candidate: AtsSignature;
  verification: AtsVerifyResult;
}

const sorted = (values: number[]): number[] => [...values].sort((a, b) => a - b);

function signersExcept(n: number, omitted: number): number[] {
  return Array.from({ length: n }, (_, index) => index + 1).filter((signer) => signer !== omitted);
}

function share(keys: AtsKeySet, message: Uint8Array, signer: number): string {
  const secret = keys.secretKeys[signer - 1];
  if (secret === undefined) throw new Error(`missing secret for signer ${signer}`);
  return atsSignShare(secret, message, signer).sigma;
}

function candidate(bitmapSigners: number[], n: number, sigmas: string[]): AtsSignature {
  return { bitmap: encodeBitmap(bitmapSigners, n), sigma: sumEncodedSignatures(sigmas) };
}

/**
 * Attack Game 22.3: all parties except `victim` cooperate and try three things
 * available to them. None possesses the victim's current-message share.
 */
export function runFramingAttempts(
  keys: AtsKeySet,
  message: Uint8Array,
  victim: number,
): FramingAttempt[] {
  if (keys.n <= keys.threshold) throw new Error('framing fixture needs at least one non-quorum signer');
  if (!Number.isInteger(victim) || victim < 1 || victim > keys.n) {
    throw new Error(`victim must be a signer from 1 through ${keys.n}`);
  }
  const attackers = signersExcept(keys.n, victim);
  const honestNamed = attackers.slice(0, keys.threshold - 1);
  const attemptedSigners = sorted([...honestNamed, victim]);
  const substitute = attackers.find((signer) => !honestNamed.includes(signer));
  if (substitute === undefined) throw new Error('framing fixture needs a substitute signer');

  // 1. Sign with an all-attacker quorum, then lie in J by swapping the
  // substitute's index for the absent victim's index.
  const actualOwnSigners = sorted([...honestNamed, substitute]);
  const ownCandidate = candidate(
    attemptedSigners,
    keys.n,
    actualOwnSigners.map((signer) => share(keys, message, signer)),
  );

  // 2. Use an unrelated valid G1 point in the missing victim slot.
  const unrelated = atsKeygen(1, 1);
  const randomPoint = share(unrelated, message, 1);
  const randomCandidate = candidate(
    attemptedSigners,
    keys.n,
    [...honestNamed.map((signer) => share(keys, message, signer)), randomPoint],
  );

  // 3. Reuse a real victim share, but from a different message.
  const differentMessage = new Uint8Array([...message, 0x01]);
  const reusedCandidate = candidate(
    attemptedSigners,
    keys.n,
    [
      ...honestNamed.map((signer) => share(keys, message, signer)),
      share(keys, differentMessage, victim),
    ],
  );

  const finish = (
    id: FramingAttempt['id'],
    label: string,
    actualInputs: number[],
    value: AtsSignature,
  ): FramingAttempt => ({
    id,
    label,
    attemptedSigners,
    actualInputs,
    candidate: value,
    verification: atsVerify(keys, message, value, keys.threshold),
  });

  return [
    finish('own-shares', 'Sum only the cooperating parties’ current shares', actualOwnSigners, ownCandidate),
    finish('random-point', 'Substitute an unrelated G1 point for the victim', honestNamed, randomCandidate),
    finish('reused-share', 'Reuse the victim’s share from a different message', attemptedSigners, reusedCandidate),
  ];
}
