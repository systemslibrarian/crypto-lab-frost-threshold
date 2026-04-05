import { escapeHtml, ellipsis } from '../ui/display';
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
          <h4>${ellipsis(id)}</h4>
          <p><strong>Signature share:</strong></p>
          <p class="mono">${sig ? escapeHtml(sig) : '(not generated yet)'}</p>
          <p class="muted">This share is worthless alone.</p>
        </article>
      `;
    })
    .join('');

  return `
    <section class="exhibit">
      <h3><span class="step-badge">4</span> Round 2 — Signature Shares</h3>
      <p>
        Each signer now combines their secret piece, their dice roll, the message, and everyone's
        promises to produce a partial signature. A tamper-proof lock ties the message to all the
        promises so nobody can swap pieces around. Each partial signature is useless on its own.
        <span class="muted">(Signature share via binding factor; prevents commitment reordering attacks)</span>
      </p>

      <button id="run-round2" ${busy ? 'disabled' : ''}>Run Round 2</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}

      <div class="card-grid" role="region" aria-label="Round 2 signature shares">${rows}</div>
    </section>
  `;
};
