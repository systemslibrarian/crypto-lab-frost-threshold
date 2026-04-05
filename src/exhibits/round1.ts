import { bytesLabel, ellipsis, escapeHtml } from '../ui/display';
import type { FrostSession } from '../ui/state';

export const renderRound1Exhibit = (
  session: FrostSession,
  messageText: string,
  busy: boolean,
  error: string | null
): string => {
  const selected = session.selectedParticipants;
  const commitments = selected
    .map((id) => {
      const out = session.round1Output[id];
      if (!out) {
        return `<article class="card"><h4>${ellipsis(id)}</h4><p class="muted">No commitment yet.</p></article>`;
      }

      return `
        <article class="card">
          <h4>${ellipsis(id)}</h4>
          <p>🔒 Nonces are stored in session memory but never displayed.</p>
          <p><strong>Hiding commitment (public):</strong></p>
          <p class="mono">${escapeHtml(out.hidingCommitment)} <span class="muted">(${bytesLabel(out.hidingCommitment)})</span></p>
          <p><strong>Binding commitment (public):</strong></p>
          <p class="mono">${escapeHtml(out.bindingCommitment)} <span class="muted">(${bytesLabel(out.bindingCommitment)})</span></p>
        </article>
      `;
    })
    .join('');

  return `
    <section class="exhibit">
      <h3>Exhibit 3 - Round 1 Commitments</h3>
      <p>
        Each participant generates a fresh nonce pair using a cryptographically secure random number
        generator. The nonces are kept secret. The commitments - elliptic curve points - are published to
        all other participants. Nonce reuse would allow private key recovery: each nonce must be used exactly
        once and then destroyed.
      </p>

      <label>
        Message (plain text)
        <input id="message-input" type="text" value="${escapeHtml(messageText)}" placeholder="hello FROST" />
      </label>
      <p class="mono muted">Message hex: ${session.message || '(empty)'}</p>

      <button id="run-round1" ${busy || selected.length === 0 ? 'disabled' : ''}>Run Round 1</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}

      <div class="card-grid">${commitments}</div>
    </section>
  `;
};
