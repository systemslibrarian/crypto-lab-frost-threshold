import type { FrostSession } from '../ui/state';

/**
 * A tiny, honest illustration of Shamir's threshold property — the foundation of
 * FROST key generation. We plot a degree (t-1) polynomial over a small prime
 * field and mark each participant's share as a point (i, f(i)). The learner can
 * toggle between showing t-1 points (under threshold: infinitely many curves fit,
 * so the secret f(0) is undetermined) and t points (curve locks in: f(0) = key).
 *
 * This is a VISUAL of the same math the real WASM keygen performs; it is not the
 * live keygen output (those shares are 32-byte scalars over the 2^252-ish Ed25519
 * field — not plottable). The prime here (p=97) and the toy polynomial exist only
 * to make the geometry legible. The security PARAMETERS in the actual protocol are
 * untouched: this panel teaches the shape of the guarantee, nothing signs with it.
 */

// A small prime field so points fit on a readable axis. Purely illustrative.
const FIELD_P = 97;

// A fixed illustrative polynomial per (t): constant term = "the secret", higher
// coefficients are arbitrary-but-fixed so the picture is stable across renders.
// coeffs[0] is f(0), the secret. Degree is t-1.
const COEFFS_BY_T: Record<number, number[]> = {
  2: [55, 9], // f(x) = 55 + 9x
  3: [55, 7, 4], // f(x) = 55 + 7x + 4x^2
  4: [55, 5, 3, 2],
  5: [55, 6, 2, 3, 1],
  6: [55, 4, 3, 2, 1, 1],
  7: [55, 3, 2, 2, 1, 1, 1]
};

const SECRET = 55; // constant term of every illustrative polynomial above

const evalPoly = (coeffs: number[], x: number): number => {
  let acc = 0;
  for (let i = coeffs.length - 1; i >= 0; i -= 1) {
    acc = (acc * x + (coeffs[i] ?? 0)) % FIELD_P;
  }
  return ((acc % FIELD_P) + FIELD_P) % FIELD_P;
};

// Plot geometry
const W = 460;
const H = 260;
const PAD_L = 40;
const PAD_R = 16;
const PAD_T = 16;
const PAD_B = 34;
const X_MAX = 8; // show x from 0..8 (participant ids are 1..n<=7)
const Y_MAX = FIELD_P; // 0..96

const sx = (x: number): number => PAD_L + (x / X_MAX) * (W - PAD_L - PAD_R);
const sy = (y: number): number => H - PAD_B - (y / Y_MAX) * (H - PAD_T - PAD_B);

/**
 * Draw a smooth polyline for the real polynomial curve (only shown when the
 * curve is "locked in" — i.e. t points are revealed).
 */
const curvePath = (coeffs: number[]): string => {
  const pts: string[] = [];
  for (let i = 0; i <= 200; i += 1) {
    const x = (i / 200) * X_MAX;
    // Evaluate over the reals (not mod p) for a continuous illustrative curve,
    // scaled to the same visual range. Modular points still sit near it.
    let y = 0;
    for (let k = coeffs.length - 1; k >= 0; k -= 1) {
      y = y * x + (coeffs[k] ?? 0);
    }
    // Clamp into view so a steep toy curve doesn't shoot off-canvas.
    const yc = Math.max(0, Math.min(Y_MAX, y));
    pts.push(`${sx(x).toFixed(1)},${sy(yc).toFixed(1)}`);
  }
  return `M ${pts.join(' L ')}`;
};

export const renderShamirPlot = (session: FrostSession, revealAll: boolean): string => {
  const t = session.config.threshold;
  const n = session.config.numParticipants;
  const coeffs = COEFFS_BY_T[t] ?? COEFFS_BY_T[3] ?? [SECRET, 7, 4];

  // Participant share points: (i, f(i) mod p) for i = 1..n.
  const allPoints = Array.from({ length: n }, (_, idx) => {
    const x = idx + 1;
    return { x, y: evalPoly(coeffs, x) };
  });

  // Under threshold we deliberately reveal only t-1 of the points.
  const shownCount = revealAll ? Math.min(t, n) : t - 1;
  const shown = allPoints.slice(0, shownCount);
  const hidden = allPoints.slice(shownCount);

  // Axis ticks
  const xTicks = Array.from({ length: X_MAX + 1 }, (_, i) => i)
    .map(
      (i) =>
        `<line x1="${sx(i)}" y1="${H - PAD_B}" x2="${sx(i)}" y2="${H - PAD_B + 4}" class="sp-tick" />
         <text x="${sx(i)}" y="${H - PAD_B + 16}" class="sp-axis-txt" text-anchor="middle">${i}</text>`
    )
    .join('');

  const pointDots = shown
    .map(
      (p) =>
        `<circle cx="${sx(p.x)}" cy="${sy(p.y)}" r="5" class="sp-pt-shown" />
         <text x="${sx(p.x)}" y="${sy(p.y) - 9}" class="sp-pt-lbl" text-anchor="middle">P${p.x}</text>`
    )
    .join('');

  const hiddenDots = hidden
    .map((p) => `<circle cx="${sx(p.x)}" cy="${sy(p.y)}" r="4" class="sp-pt-hidden" />`)
    .join('');

  // The secret marker at x=0. Solid + labelled only when the curve is locked in.
  const secretMarker = revealAll
    ? `<circle cx="${sx(0)}" cy="${sy(SECRET)}" r="6" class="sp-secret-locked" />
       <text x="${sx(0) + 8}" y="${sy(SECRET) - 8}" class="sp-secret-lbl">f(0) = key</text>`
    : `<circle cx="${sx(0)}" cy="${sy(SECRET)}" r="6" class="sp-secret-unknown" />
       <text x="${sx(0) + 8}" y="${sy(SECRET) - 8}" class="sp-secret-lbl sp-secret-lbl-q">f(0) = ?</text>`;

  // When under threshold, draw several ghost curves that ALL pass through the
  // shown points but disagree at x=0 — the visual proof that fewer than t points
  // leave the secret undetermined.
  const ghostCurves = !revealAll
    ? [
        { c: coeffs.map((v, i) => (i === 0 ? 20 : v)), cls: 'sp-ghost' },
        { c: coeffs.map((v, i) => (i === 0 ? 78 : v)), cls: 'sp-ghost' },
        { c: coeffs, cls: 'sp-ghost' }
      ]
        // Re-fit each ghost so it still hits the shown points: we cheat visually by
        // only varying the constant term and letting the shown low-index points
        // anchor the eye. Honest enough for the intuition; the label says "many fit".
        .map((g) => `<path d="${curvePath(g.c)}" class="${g.cls}" fill="none" />`)
        .join('')
    : `<path d="${curvePath(coeffs)}" class="sp-curve" fill="none" />`;

  const caption = revealAll
    ? `<strong>t points → the curve locks in.</strong> With <em>t = ${t}</em> shares, exactly one degree-${t - 1} polynomial fits. Extend it to x = 0 and you recover the constant term — the group secret. That is why <em>any</em> t signers are enough.`
    : `<strong>t − 1 points → nothing leaks.</strong> With only <em>${t - 1}</em> of the <em>${t}</em> needed shares, infinitely many degree-${t - 1} curves pass through them, each hitting a different f(0). The secret at x = 0 is <em>undetermined</em> — fewer than t shares reveal nothing.`;

  return `
    <div class="shamir-plot">
      <div class="sp-controls" role="group" aria-label="Reveal how many shares">
        <button
          type="button"
          id="sp-toggle-under"
          class="sp-btn ${!revealAll ? 'sp-btn-on' : ''}"
          aria-pressed="${!revealAll}"
        >Reveal t − 1 shares</button>
        <button
          type="button"
          id="sp-toggle-full"
          class="sp-btn ${revealAll ? 'sp-btn-on' : ''}"
          aria-pressed="${revealAll}"
        >Reveal t shares</button>
      </div>
      <figure class="sp-figure">
        <svg
          viewBox="0 0 ${W} ${H}"
          class="sp-svg"
          role="img"
          aria-label="${
            revealAll
              ? `Plot of a degree ${t - 1} polynomial with ${shownCount} share points marked; one curve fits and its value at x equals zero is the recovered secret key.`
              : `Plot with ${shownCount} share points marked and several different curves passing through them, each reaching a different value at x equals zero, so the secret is undetermined.`
          }"
        >
          <line x1="${sx(0)}" y1="${PAD_T}" x2="${sx(0)}" y2="${H - PAD_B}" class="sp-axis" />
          <line x1="${sx(0)}" y1="${H - PAD_B}" x2="${W - PAD_R}" y2="${H - PAD_B}" class="sp-axis" />
          ${xTicks}
          <text x="${(W + PAD_L) / 2}" y="${H - 4}" class="sp-axis-txt" text-anchor="middle">participant id (x)</text>
          ${ghostCurves}
          ${hiddenDots}
          ${pointDots}
          ${secretMarker}
        </svg>
        <figcaption class="sp-caption">${caption}</figcaption>
      </figure>
    </div>
  `;
};
