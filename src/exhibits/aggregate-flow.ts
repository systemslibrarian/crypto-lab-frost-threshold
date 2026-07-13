import { ellipsisSafe } from '../ui/display';
import type { FrostSession } from '../ui/state';

/**
 * Visualize what aggregation actually does — the step the demo names four times
 * ("Lagrange interpolation") but never shows.
 *
 * Each selected signer contributed a signature-share scalar z_i in Round 2. The
 * aggregator forms the final scalar s = Σ z_i (the shares are already weighted by
 * their Lagrange coefficient inside Round 2 per RFC 9591, but the coefficient is
 * the value that makes "any subset" work, so we surface it here for insight). The
 * coefficient λ_i depends ONLY on WHICH signers showed up — recomputed from the
 * signer set every time — which is why two different subsets reach the same key by
 * different paths.
 *
 * We recover each signer's small-integer FROST identifier from its serialized
 * scalar (little-endian; identifiers are 1..n) and compute λ_i(0) exactly as a
 * rational, purely to DISPLAY the real coefficient. No key material touches this;
 * the secret shares are drawn routed to a locked box that does NOT feed the sum.
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

export const renderAggregateFlow = (session: FrostSession): string => {
  const selected = session.selectedParticipants;
  const haveShares = selected.length > 0 && selected.every((id) => session.signatureShares[id]);
  if (!haveShares) {
    return `
      <div class="agg-flow agg-flow-empty">
        <p class="muted">Run Round 2, then aggregate — the flow of shares into the single signature will appear here, with each signer's live Lagrange coefficient.</p>
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
          <span class="agg-lane-share mono" title="signature share z_${i + 1}">${ellipsisSafe(share, 8, 6)}</span>
          <span class="agg-lane-op" aria-hidden="true">×</span>
          <span class="agg-lane-coeff" title="Lagrange coefficient for this signer set">λ = ${fracLabel(lam)}</span>
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

  const coeffNote = allResolved
    ? `Coefficients above are computed live from <em>this</em> signer set (ids ${idsForLambda.join(', ')}). Pick a different subset and they change — that is Lagrange interpolation choosing weights so every valid subset lands on the same group key.`
    : `Coefficients shown for the signer positions in this set. They are recomputed from whichever signers show up — that is Lagrange interpolation choosing weights so every valid subset lands on the same group key.`;

  return `
    <div class="agg-flow" role="group" aria-label="Aggregation flow: signature shares combine into one signature">
      <div class="agg-flow-grid">
        <div class="agg-inputs">
          <p class="agg-col-title">Signature shares (public)</p>
          <ul class="agg-lanes">${laneRows}</ul>
        </div>
        <div class="agg-sum" aria-label="Summed into the final signature scalar">
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
            nowhere. Aggregation interpolates the signature, not the key.
          </p>
        </div>
      </div>

      <p class="agg-coeff-note muted">${coeffNote}</p>
    </div>
  `;
};
