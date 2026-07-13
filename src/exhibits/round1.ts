import { bytesLabel, ellipsisSafe, escapeHtml, insight } from '../ui/display';
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
        return `<article class="card"><h3>${ellipsisSafe(id)}</h3><p class="muted">No commitment yet.</p></article>`;
      }

      return `
        <article class="card">
          <h3>${ellipsisSafe(id)}</h3>
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
      <h2><span class="step-badge">3</span> Round 1 — Commitments</h2>
      <p>
        Each signer rolls secret random dice and then shares only a sealed promise of the result.
        The secrets stay hidden; only the promises are published. These single-use values are
        critical — reusing them would leak the private key.
        <span class="muted">(Nonce generation + elliptic-curve commitments; CSPRNG-backed)</span>
      </p>

      ${insight(
        `<strong>Why nonces are single-use:</strong> a Schnorr signature is <span class="mono">s = r + e·x</span>, where <span class="mono">r</span> is the secret nonce and <span class="mono">x</span> is the key share. Sign two different messages with the <em>same</em> <span class="mono">r</span> and an attacker gets two equations with two unknowns — they solve for <span class="mono">x</span> and steal your share. That's why fresh CSPRNG nonces are drawn every Round 1, kept in memory only, and never displayed.`
      )}

      <details class="viz-details" open>
        <summary>Why TWO commitments? Hiding vs binding</summary>
        <p class="viz-lead">
          FROST needs a first round at all because each signer must lock in a nonce
          <em>before</em> anyone reveals a signature. It publishes <strong>two</strong>
          commitments, defending two different things:
        </p>
        <div class="grid-2 hb-grid">
          <article class="card hb-cell">
            <p class="hb-badge hb-badge-hide">HIDING</p>
            <p class="hb-defends"><strong>Defends the secret nonce.</strong></p>
            <p>
              Publishes <span class="mono">H = g·h</span> — an elliptic-curve point that
              <em>proves you committed to a nonce</em> <span class="mono">h</span> without revealing
              it. Like sealing a dice roll in an envelope: the number is fixed, but nobody sees it
              until the reveal. If the raw nonce leaked, the key-recovery attack above would apply.
            </p>
          </article>
          <article class="card hb-cell">
            <p class="hb-badge hb-badge-bind">BINDING</p>
            <p class="hb-defends"><strong>Ties this nonce to this exact signing.</strong></p>
            <p>
              A second commitment <span class="mono">B = g·b</span> gets folded through a
              <em>binding factor</em> derived from <em>who is signing</em> + <em>the message</em> +
              <em>all commitments</em>. Swap or reorder someone's commitment and the factor changes,
              so their share no longer fits — the forgery is rejected. This is what closes the
              <strong>Drijvers attack</strong> on naive one-round multisignatures.
            </p>
          </article>
        </div>
        <div class="hb-swap" role="note">
          <span aria-hidden="true">🚫</span>
          <p class="muted">
            <strong>Swapped commitment → rejected:</strong> because the binding factor mixes in the
            whole signer set and message, a commitment lifted from a different signing attempt yields
            an <span class="mono">s</span> that fails verification. No valid signature can be assembled
            from mismatched pieces — try the "simulate failure" toggle in Step 5 to see aggregation
            refuse rather than emit an "almost valid" result.
          </p>
        </div>
      </details>

      <label>
        Message (plain text)
        <input id="message-input" type="text" value="${escapeHtml(messageText)}" placeholder="hello FROST" aria-label="Message to sign" />
      </label>
      <p class="mono muted">Message hex: <span id="message-hex">${session.message || '(empty)'}</span></p>

      <button id="run-round1" ${busy || selected.length === 0 ? 'disabled' : ''}>Run Round 1</button>
      ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}

      <div class="card-grid" role="region" aria-label="Round 1 commitments">${commitments}</div>
    </section>
  `;
};
