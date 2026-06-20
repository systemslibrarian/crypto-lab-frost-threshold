import { escapeHtml, ellipsisSafe, bytesLabel, insight } from '../ui/display';
import type { FrostSession } from '../ui/state';

export const renderRound2Exhibit = (
  session: FrostSession,
  busy: boolean,
  error: string | null
): string => {
  const rows = session.selectedParticipants
    .map((id) => {
      const sig = session.signatureShares[id];
      return `
        <article class="card">
          <h3>${ellipsisSafe(id)}</h3>
          <p><strong>Signature share:</strong></p>
          <p class="mono">${sig ? escapeHtml(sig) : '(not generated yet)'}</p>
          <p class="muted">${sig ? `A ${bytesLabel(sig)} scalar — half the size of a real signature, and worthless alone.` : 'This share is worthless alone.'}</p>
        </article>
      `;
    })
    .join('');

  return `
    <section class="exhibit">
      <h2><span class="step-badge">4</span> Round 2 — Signature Shares</h2>
      <p>
        Each signer now combines their secret piece, their dice roll, the message, and everyone's
        promises to produce a partial signature. A tamper-proof lock ties the message to all the
        promises so nobody can swap pieces around. Each partial signature is useless on its own.
        <span class="muted">(Signature share via binding factor; prevents commitment reordering attacks)</span>
      </p>

      ${insight(
        `<strong>A share is not a signature.</strong> Each output below is a 32-byte scalar — a partial value tied to this exact message, this exact set of signers, and this signer's one-time nonce. Hand one to a verifier and it fails: it isn't a 64-byte Ed25519 signature, and it carries no meaning until the next step recombines <em>t</em> of them.`
      )}

      <button id="run-round2" ${busy ? 'disabled' : ''}>Run Round 2</button>
      ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}

      <div class="card-grid" role="region" aria-label="Round 2 signature shares">${rows}</div>
    </section>
  `;
};
