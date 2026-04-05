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
      <h3>Exhibit 4 - Round 2 Signature Shares</h3>
      <p>
        Each participant computes a signature share using their secret share, their nonce pair, the message,
        and the full commitment list. The binding factor - derived by hashing the message and all commitments
        together - prevents mix-and-match attacks. Each share is a scalar value. None of them is a valid
        signature.
      </p>

      <button id="run-round2" ${busy ? 'disabled' : ''}>Run Round 2</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}

      <div class="card-grid">${rows}</div>
    </section>
  `;
};
