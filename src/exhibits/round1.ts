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
      <h3><span class="step-badge">3</span> Round 1 — Commitments</h3>
      <p>
        Each signer rolls secret random dice and then shares only a sealed promise of the result.
        The secrets stay hidden; only the promises are published. These single-use values are
        critical — reusing them would leak the private key.
        <span class="muted">(Nonce generation + elliptic-curve commitments; CSPRNG-backed)</span>
      </p>

      <label>
        Message (plain text)
        <input id="message-input" type="text" value="${escapeHtml(messageText)}" placeholder="hello FROST" aria-label="Message to sign" />
      </label>
      <p class="mono muted">Message hex: ${session.message || '(empty)'}</p>

      <button id="run-round1" ${busy || selected.length === 0 ? 'disabled' : ''}>Run Round 1</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}

      <div class="card-grid" role="region" aria-label="Round 1 commitments">${commitments}</div>
    </section>
  `;
};
