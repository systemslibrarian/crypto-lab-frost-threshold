import { escapeHtml, insight } from '../ui/display';
import type { NonceReuseResult, BindingResult } from './attacks';

const short = (hex: string): string => `${hex.slice(0, 12)}…${hex.slice(-12)}`;

const renderNonceReuse = (r: NonceReuseResult | null): string => {
  if (!r) {
    return '<p class="muted">Not run yet.</p>';
  }
  const rows = `
    <ul class="attack-rows">
      <li><span>Real group secret x</span><span class="mono">${short(r.secretHex)}</span></li>
      <li><span>Recovered x</span><span class="mono">${r.recoveredSecretHex ? short(r.recoveredSecretHex) : '— (recovery failed)'}</span></li>
      <li><span>Forged message</span><span>${escapeHtml(r.forgedMessage)}</span></li>
    </ul>`;
  if (r.reuse && r.keyRecovered && r.forgeryAccepted) {
    return `${rows}
      <p class="error" role="status" data-verdict="leaked">
        ⚠ GROUP KEY RECOVERED — it equals the real key exactly. A forged signature on
        “${escapeHtml(r.forgedMessage)}” was <strong>ACCEPTED by the real Ed25519 verifier</strong>.
        Reusing Round-1 commitments across signing sessions is catastrophic.
      </p>`;
  }
  return `${rows}
    <p class="verified" role="status" data-verdict="safe">
      ✓ Fresh nonces each session: the 3×3 system yields the wrong key and the forged
      signature is <strong>REJECTED</strong> by the real Ed25519 verifier. This is why
      Round-1 nonces must never be reused.
    </p>`;
};

const renderBinding = (r: BindingResult | null): string => {
  if (!r) {
    return '<p class="muted">Not run yet.</p>';
  }
  return `
    <ul class="attack-rows">
      <li><span>Correct FROST aggregate (binding folded into R)</span>
        <span class="${r.boundVerified ? 'verified' : 'error'}" data-verdict="bound">${r.boundVerified ? 'ACCEPTED ✓' : 'rejected'}</span></li>
      <li><span>Binding factor skipped at aggregation (ρ<sub>i</sub> = 1)</span>
        <span class="${r.unboundVerified ? 'error' : 'verified'}" data-verdict="unbound">${r.unboundVerified ? 'accepted' : 'REJECTED ✓'}</span></li>
    </ul>
    <p class="${!r.unboundVerified && r.boundVerified ? 'verified' : 'error'}" role="status">
      The RFC 9591 binding factor ρ<sub>i</sub> = H(i, msg, commitments) is a load-bearing term
      in the signature the verifier checks. Drop it at aggregation and the real Ed25519 verifier
      rejects — the same term that closes the Drijvers/Benhamouda concurrent-signing (ROS) attack.
    </p>`;
};

/**
 * "Attacks the design defends against" — mounts the two named FROST failure
 * modes as live, computed exhibits verified by the real @noble/curves Ed25519
 * verifier. Small (default 2-of-3) group so the algebra stays legible; the
 * cryptography is genuine.
 */
export const renderAttacksExhibit = (
  nonceReuse: NonceReuseResult | null,
  binding: BindingResult | null,
  nonceBusy: boolean,
  bindingBusy: boolean,
): string => `
  <section class="exhibit attacks">
    <h2><span class="step-badge" aria-hidden="true">⚔</span> Attacks the design defends against</h2>
    <p>
      Both run for real on a small <strong>2-of-3 FROST(Ed25519)</strong> group built in your browser
      (toy scale, so the algebra is legible) and every verdict comes from the actual Ed25519 verifier
      — nothing is asserted from prose.
    </p>

    <div class="attack-panel">
      <h3>1 · Nonce reuse across signing attempts</h3>
      <p>
        Reuse the same Round-1 nonces across three signing sessions and each signer's secret drops out
        of a 3×3 linear system; summed over the signing set that is the whole group key. Then a forged
        message is signed with it and handed to the real verifier.
      </p>
      ${insight('FROST commits <em>two</em> nonces per signer specifically to make single-reuse harder; reuse the pair across sessions and the guarantee is gone. RFC 9591 §6.1 forbids reusing nonces.')}
      <div class="attack-actions">
        <button id="attack-nonce-reuse" ${nonceBusy ? 'disabled' : ''}>Reuse nonces &rarr; recover key &rarr; forge</button>
        <button id="attack-nonce-control" class="secondary" ${nonceBusy ? 'disabled' : ''}>Control: fresh nonces (safe)</button>
      </div>
      <div id="attack-nonce-output" class="attack-output">${renderNonceReuse(nonceReuse)}</div>
    </div>

    <div class="attack-panel">
      <h3>2 · Skipping the nonce-commitment binding factor</h3>
      <p>
        The same honest signing shares are aggregated two ways: correctly, with each signer's binding
        factor folded into the group commitment R, and with the binding factor skipped. The real Ed25519
        verifier accepts the first and rejects the second.
      </p>
      <div class="attack-actions">
        <button id="attack-binding" ${bindingBusy ? 'disabled' : ''}>Aggregate with vs. without binding</button>
      </div>
      <div id="attack-binding-output" class="attack-output">${renderBinding(binding)}</div>
    </div>
  </section>
`;
