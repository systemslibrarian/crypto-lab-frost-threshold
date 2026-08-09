import { ellipsisSafe } from '../ui/display';
import type { FrostSession } from '../ui/state';

/**
 * Visualize what aggregation actually does.
 *
 * Where the Lagrange coefficient lives matters, and it is easy to draw wrong.
 * Per RFC 9591 the SIGNER applies it in Round 2:
 *
 *   Sec 5.2  z_i = d_i + (e_i * rho_i) + (lambda_i * s_i * c)
 *   Sec 5.3  z   = z_1 + z_2 + ... + z_t
 *
 * So by the time a share reaches the aggregator, lambda_i is already baked into
 * it, and aggregation is plain scalar addition — NOT a second multiplication by
 * lambda_i. This module therefore shows lambda_i as an annotation on the share
 * that already carries it, and the flow into the sum as "+".
 *
 * We recover each signer's small-integer FROST identifier from its serialized
 * scalar (little-endian; identifiers are 1..n) and compute lambda_i(0) exactly as
 * a rational, purely to DISPLAY the real coefficient. No key material touches
 * this; the secret shares are drawn routed to a locked box that does NOT feed the
 * sum.
 *
 * The "shares are summed, not concatenated" claim is not asserted here, it is
 * checked: checkShareSum() recomputes sum(z_i) mod l in the page and compares it
 * against the s half of the signature the WASM actually returned.
 */

/** Recover the small integer identifier from a little-endian serialized scalar. */
const idToInt = (identifierHex: string): number | null => {
  if (!/^[0-9a-fA-F]+$/.test(identifierHex) || identifierHex.length < 2) return null;
  // Little-endian: the integer lives in the low bytes. Ed25519 identifiers here
  // are 1..7, so the first byte carries it; verify the rest are zero.
  const bytes = identifierHex.match(/../g) ?? [];
  const low = parseInt(bytes[0] ?? '00', 16);
  const restZero = bytes.slice(1).every((b) => b === '00');
  return restZero ? low : null;
};

type Frac = { n: number; d: number };

const gcd = (a: number, b: number): number => (b === 0 ? Math.abs(a) : gcd(b, a % b));
const reduce = ({ n, d }: Frac): Frac => {
  const g = gcd(n, d) || 1;
  const s = d < 0 ? -1 : 1;
  return { n: (s * n) / g, d: (s * d) / g };
};
const mul = (a: Frac, b: Frac): Frac => reduce({ n: a.n * b.n, d: a.d * b.d });
const fracLabel = (f: Frac): string => (f.d === 1 ? `${f.n}` : `${f.n}/${f.d}`);

/**
 * Lagrange coefficient λ_i(0) = ∏_{j≠i} x_j / (x_j - x_i), exact rational.
 * Standard integer arithmetic here; over the real protocol this is done in the
 * scalar field, but the value is the same rational reduced mod the group order.
 */
const lagrangeAtZero = (ids: number[], i: number): Frac => {
  let acc: Frac = { n: 1, d: 1 };
  const xi = ids[i] ?? 0;
  ids.forEach((xj, j) => {
    if (j === i || xj === xi) return;
    acc = mul(acc, { n: xj, d: xj - xi });
  });
  return reduce(acc);
};

/** Order of the Ed25519 prime-order subgroup: l = 2^252 + 27742317777372353535851937790883648493. */
const ELL = (1n << 252n) + 27742317777372353535851937790883648493n;

/** Parse a little-endian serialized scalar (the wire format for Ed25519 scalars). */
const leHexToScalar = (hex: string): bigint | null => {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length === 0 || hex.length % 2 !== 0) return null;
  const bytes = hex.match(/../g) ?? [];
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    acc = (acc << 8n) | BigInt(Number.parseInt(bytes[i] ?? '00', 16));
  }
  return acc;
};

export interface ShareSumCheck {
  /** sum(z_i) mod l, recomputed here from the shares the signers published. */
  sum: bigint;
  /** The s scalar actually present in the aggregated signature. */
  s: bigint;
  ok: boolean;
  count: number;
}

/**
 * Recompute s = sum(z_i) mod l from the Round 2 shares and compare it with the
 * second half of the 64-byte signature the aggregator produced. This is the
 * demo's own check that aggregation is scalar addition — if the aggregator were
 * concatenating shares, or re-applying Lagrange coefficients, this would fail.
 * Returns null when there is nothing to check yet (or the hex is unparseable).
 */
export const checkShareSum = (session: FrostSession): ShareSumCheck | null => {
  const sig = session.finalSignature;
  if (!sig || sig.length !== 128) return null;
  const ids = session.selectedParticipants;
  if (ids.length === 0) return null;

  let sum = 0n;
  for (const id of ids) {
    const z = leHexToScalar(session.signatureShares[id] ?? '');
    if (z === null) return null;
    sum = (sum + z) % ELL;
  }
  const s = leHexToScalar(sig.slice(64));
  if (s === null) return null;
  return { sum, s, ok: sum === s, count: ids.length };
};

export const renderAggregateFlow = (session: FrostSession): string => {
  const selected = session.selectedParticipants;
  const haveShares = selected.length > 0 && selected.every((id) => session.signatureShares[id]);
  if (!haveShares) {
    return `
      <div class="agg-flow agg-flow-empty">
        <p class="muted">Run Round 2, then aggregate — the flow of shares into the single signature will appear here, with the live Lagrange coefficient each signer already folded into its share.</p>
      </div>
    `;
  }

  const ints = selected.map((id) => idToInt(id));
  const allResolved = ints.every((v): v is number => v !== null);
  const idsForLambda = allResolved ? (ints as number[]) : selected.map((_, i) => i + 1);

  const laneRows = selected
    .map((id, i) => {
      const share = session.signatureShares[id] ?? '';
      const lam = lagrangeAtZero(idsForLambda, i);
      const idLabel = ints[i] !== null ? `P${ints[i]}` : `P${i + 1}`;
      return `
        <li class="agg-lane">
          <span class="agg-lane-id">${idLabel}</span>
          <span class="agg-lane-share mono" title="signature share z_${i + 1}, already weighted by this signer's Lagrange coefficient in Round 2">${ellipsisSafe(share, 8, 6)}</span>
          <span class="agg-lane-coeff" title="Lagrange coefficient this signer applied in Round 2 — already inside the share to its left">contains λ = ${fracLabel(lam)}</span>
          <span class="agg-lane-op" aria-hidden="true">+</span>
          <span class="agg-lane-arrow" aria-hidden="true">→</span>
        </li>
      `;
    })
    .join('');

  const finalSig = session.finalSignature;
  const finalCell = finalSig
    ? `<div class="agg-sum-value mono">${ellipsisSafe(finalSig, 10, 8)}</div>
       <div class="agg-sum-note muted">single 64-byte (R, s) signature</div>`
    : `<div class="agg-sum-value muted">Σ → s</div>
       <div class="agg-sum-note muted">press Aggregate to compute</div>`;

  const coeffScope = allResolved
    ? `computed live from <em>this</em> signer set (ids ${idsForLambda.join(', ')})`
    : `shown for the signer positions in this set`;
  const coeffNote = `Coefficients above are ${coeffScope}. Pick a different subset and they change — that is Lagrange interpolation choosing weights so every valid subset lands on the same group key. Note <em>where</em> the coefficient is applied: per RFC 9591 §5.2 each signer multiplies it into its own share during Round 2 (<span class="mono">z_i = d_i + e_i·ρ_i + λ_i·s_i·c</span>), so §5.3 aggregation is just <span class="mono">z = z_1 + … + z_t</span>. The aggregator never multiplies by λ — doing so a second time would destroy the signature.`;

  const sumCheck = checkShareSum(session);
  const sumCheckHtml = sumCheck
    ? `<p class="agg-sum-check ${sumCheck.ok ? 'verified' : 'error'}" role="status">
         ${sumCheck.ok ? '✓' : '✗'} Checked in this page: the ${sumCheck.count} signature shares were re-summed
         mod <span class="mono">ℓ</span> and ${sumCheck.ok ? 'equal' : '<strong>do not equal</strong>'} the
         <span class="mono">s</span> half of the signature the aggregator returned
         ${sumCheck.ok ? '— summed, not concatenated, and not re-weighted' : '— something is wrong with this build'}.
       </p>`
    : '';

  return `
    <div class="agg-flow" role="group" aria-label="Aggregation flow: signature shares combine into one signature">
      <div class="agg-flow-grid">
        <div class="agg-inputs">
          <p class="agg-col-title">Signature shares (public)</p>
          <ul class="agg-lanes">${laneRows}</ul>
        </div>
        <!-- role="group" is load-bearing: aria-label on a role-less div is
             PROHIBITED by ARIA and silently discarded, so this box had no
             accessible name at all. axe files that under "incomplete", never
             "violations", which is why a violations-only gate never saw it. -->
        <div class="agg-sum" role="group" aria-label="Summed into the final signature scalar">
          <div class="agg-sum-symbol" aria-hidden="true">Σ</div>
          ${finalCell}
        </div>
      </div>

      <div class="agg-locked" role="note">
        <span class="agg-lock-icon" aria-hidden="true">🔒</span>
        <div>
          <p class="agg-lock-title"><strong>Secret signing shares → locked box (never reaches the aggregator)</strong></p>
          <p class="agg-lock-body muted">
            The scalars flowing into the sum above are the <em>public</em> signature shares. Each
            signer's <em>secret</em> key share stays on its own device — it is drawn into the locked
            box, with no arrow to the aggregator, because the group private key is reconstructed
            nowhere. Interpolation happened inside each signer's Round 2 share, not here — the
            aggregator only adds them up.
          </p>
        </div>
      </div>

      ${sumCheckHtml}
      <p class="agg-coeff-note muted">${coeffNote}</p>
    </div>
  `;
};
