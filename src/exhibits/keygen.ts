import { bytesLabel, ellipsis, escapeHtml } from '../ui/display';
import type { FrostSession } from '../ui/state';

export const renderKeygenExhibit = (
  session: FrostSession,
  busy: boolean,
  error: string | null
): string => {
  const sharesHtml = session.shares
    .map(
      (share, index) => `
      <article class="card">
        <h4>Participant ${index + 1}</h4>
        <p><strong>Identifier (public):</strong> ${ellipsis(share.identifier)}</p>
        <p><strong>VSS commitments (public):</strong></p>
        <ul>
          ${share.commitment
            .map((c) => `<li class="mono">${ellipsis(c, 16, 16)} <span class="muted">(${bytesLabel(c)})</span></li>`)
            .join('')}
        </ul>
        <details>
          <summary>Show secret share scalar</summary>
          <p class="warning">Secret material. Treat as private key share.</p>
          <p class="mono">${escapeHtml(share.secret)}</p>
        </details>
      </article>
    `
    )
    .join('');

  return `
    <section class="exhibit">
      <h3><span class="step-badge">1</span> Key Generation</h3>
      <p>
        A trusted setup splits one master signing key into pieces — like tearing a treasure map
        into fragments. Each participant gets one piece. No single piece can sign anything on its own.
        The group's public identity (Ed25519 public key) looks completely normal to the outside world.
        <span class="muted">(Verifiable Secret Sharing over the Ed25519 scalar field)</span>
      </p>

      <div class="grid-2">
        <label>
          Participants (n): <span id="n-value">${session.config.numParticipants}</span>
          <input id="n-slider" type="range" min="2" max="7" value="${session.config.numParticipants}" aria-label="Number of participants" />
        </label>

        <label>
          Threshold (t): <span id="t-value">${session.config.threshold}</span>
          <input id="t-slider" type="range" min="2" max="${session.config.numParticipants}" value="${session.config.threshold}" aria-label="Signing threshold" />
        </label>
      </div>

      <button id="generate-keys" ${busy ? 'disabled' : ''}>Generate Keys</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}

      ${
        session.groupPublicKey
          ? `<p><strong>Group Public Key:</strong> <span class="mono">${escapeHtml(session.groupPublicKey)}</span> <span class="muted">(${bytesLabel(session.groupPublicKey)})</span></p>`
          : ''
      }

      <div class="card-grid" role="region" aria-label="Generated key shares">${sharesHtml}</div>
    </section>
  `;
};
