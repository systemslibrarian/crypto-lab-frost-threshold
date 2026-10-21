import './style.css';
import { renderAdaptiveResearch } from './exhibits/adaptive-research';
import { renderAggregateExhibit } from './exhibits/aggregate';
import { renderKeygenExhibit } from './exhibits/keygen';
import { renderRound1Exhibit } from './exhibits/round1';
import { renderRound2Exhibit } from './exhibits/round2';
import { renderAnySubsetExhibit, renderSubsetExhibit } from './exhibits/subset';
import { renderProgress } from './exhibits/progress';
import { renderRecap } from './exhibits/recap';
import { renderAttacksExhibit } from './exhibits/attacks-view';
import {
  renderAccountableExhibit,
  type AccountablePanelState,
} from './exhibits/accountable';
import { atsKeygen, type AtsKeySet } from './ats/bls-ats';
import {
  corruptOneShare,
  editAccountableBitmap,
  frameAbsentSigner,
  runAccountable,
  runDealerFrameFixture,
  runRogueKeyFixture,
  runThresholdGuard,
} from './ats/demo';
import {
  runNonceReuse,
  runBindingOmission,
  type NonceReuseResult,
  type BindingResult,
} from './exhibits/attacks';
import { FrostStateManager, type ParticipantShare } from './ui/state';
import { wasmAggregate, wasmKeygen, wasmRound1Commit, wasmRound2Sign } from './wasm';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app element');
}

type KeygenResult = {
  group_public_key: string;
  shares: Array<{
    identifier: string;
    secret: string;
    commitment: string[];
    verifying_share: string;
  }>;
};

type Round1Result = {
  identifier: string;
  hiding_nonce: string;
  binding_nonce: string;
  hiding_commitment: string;
  binding_commitment: string;
  nonces_serialized: string;
};

type Round2Result = {
  identifier: string;
  signature_share: string;
};

type AggregateResult = {
  signature: string;
  verified: boolean;
  message: string;
  verifying_key: string;
};

const state = new FrostStateManager();

let messageText = 'Hello from FROST';
let shamirRevealAll = false;
let keygenBusy = false;
let round1Busy = false;
let round2Busy = false;
let aggregateBusy = false;
let simulateFailure = false;

// Attack exhibits (live, verified by the real Ed25519 verifier).
let nonceReuseResult: NonceReuseResult | null = null;
let bindingResult: BindingResult | null = null;
let nonceAttackBusy = false;
let bindingAttackBusy = false;

const emptyAccountablePanel = (retiredReason: string | null = null): AccountablePanelState => ({
  run: null,
  bitmapEdit: null,
  thresholdGuard: null,
  corruptedShare: null,
  framing: null,
  rogueKey: null,
  dealerFrame: null,
  busy: false,
  error: null,
  retiredReason,
});

let accountablePanel = emptyAccountablePanel();
let accountableKeys: AtsKeySet | null = null;

let keygenError: string | null = null;
let round1Error: string | null = null;
let round2Error: string | null = null;
let aggregateError: string | null = null;

state.setMessageFromText(messageText);

const toParticipantShares = (shares: KeygenResult['shares']): ParticipantShare[] =>
  shares.map((s) => ({
    identifier: s.identifier,
    secret: s.secret,
    commitment: s.commitment,
    verifyingShare: s.verifying_share
  }));

const getRound1For = (identifier: string) => {
  const out = state.value.round1Output[identifier];
  if (!out) {
    throw new Error(`missing round1 output for participant ${identifier}`);
  }
  return out;
};

const render = (): void => {
  // Preserve keyboard focus (and text caret) across full re-renders. Without this,
  // every action would reset focus to <body>, breaking keyboard/screen-reader flow.
  const active = document.activeElement as HTMLElement | null;
  const focusId = active && active.id ? active.id : null;
  let caret: { start: number; end: number } | null = null;
  if (active instanceof HTMLInputElement && active.type === 'text' && active.selectionStart !== null) {
    caret = { start: active.selectionStart, end: active.selectionEnd ?? active.selectionStart };
  }

  const history = state.signatureHistory;
  const previous = history.length >= 2 ? history[0] : undefined;
  const latest = history.length >= 1 ? history[history.length - 1] : undefined;

  app.innerHTML = `
    <main class="shell" id="main-content" tabindex="-1">
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">FROST</h1>
          <p class="cl-hero-sub">t-of-n Threshold Schnorr &middot; Ed25519 &middot; RFC 9591</p>
          <p class="cl-hero-desc">
            Run FROST live in your browser: generate one shared group key, pick any
            threshold subset, and watch its members jointly produce a single ordinary
            Ed25519 Schnorr signature over two rounds.
          </p>
          <div class="cl-hero-chips">
            <span class="chip">Ed25519</span>
            <span class="chip">Schnorr</span>
            <span class="chip">t-of-n</span>
            <span class="chip">WASM</span>
          </div>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">
            No single person ever holds the whole key, so one compromised or coerced
            signer cannot forge a signature or lose the funds. The output is an ordinary
            signature verifiers already accept — no special multisig support needed.
          </p>
        </aside>
      </header>

      ${renderProgress(state.value)}
      ${renderKeygenExhibit(state.value, keygenBusy, keygenError, shamirRevealAll)}
      ${renderSubsetExhibit(state.value)}
      ${renderRound1Exhibit(state.value, messageText, round1Busy, round1Error)}
      ${renderRound2Exhibit(state.value, round2Busy, round2Error)}
      ${renderAggregateExhibit(state.value, simulateFailure, aggregateBusy, aggregateError)}
      ${renderAnySubsetExhibit(previous, latest, state.value.finalSignature !== null, state.value.groupPublicKey)}
      ${renderAccountableExhibit(state.value, latest, accountablePanel)}
      ${renderAttacksExhibit(nonceReuseResult, bindingResult, nonceAttackBusy, bindingAttackBusy)}
      ${renderAdaptiveResearch()}
      ${renderRecap(state.value)}
    </main>
  `;

  bindEvents();

  if (focusId) {
    const restored = document.getElementById(focusId);
    if (restored && !(restored as HTMLButtonElement).disabled) {
      restored.focus();
      if (caret && restored instanceof HTMLInputElement && restored.type === 'text') {
        try {
          restored.setSelectionRange(caret.start, caret.end);
        } catch {
          /* setSelectionRange can throw on some input states; safe to ignore */
        }
      }
    }
  }
};

const accountableHasEvidence = (): boolean =>
  accountablePanel.run !== null ||
  accountablePanel.bitmapEdit !== null ||
  accountablePanel.thresholdGuard !== null ||
  accountablePanel.corruptedShare !== null ||
  accountablePanel.framing !== null ||
  accountablePanel.rogueKey !== null ||
  accountablePanel.dealerFrame !== null;

/** Retire computed ATS evidence without touching the FROST session. */
const retireAccountable = (reason: string, discardKeys: boolean): boolean => {
  const hadEvidence = accountableHasEvidence();
  if (discardKeys) accountableKeys = null;
  if (!hadEvidence) return false;
  accountablePanel = emptyAccountablePanel(reason);
  return true;
};

const currentAccountableQuorum = (): number[] => {
  const latest = state.signatureHistory.at(-1);
  const identifiers = latest?.participants.length === state.value.config.threshold
    ? latest.participants
    : state.value.selectedParticipants;
  const mapped = identifiers
    .map((identifier) => state.value.shares.findIndex((share) => share.identifier === identifier) + 1)
    .filter((signer) => signer > 0);
  if (mapped.length === state.value.config.threshold && new Set(mapped).size === mapped.length) {
    return mapped.sort((a, b) => a - b);
  }
  return Array.from({ length: state.value.config.threshold }, (_, index) => index + 1);
};

const runAccountableTask = async (task: () => void): Promise<void> => {
  accountablePanel.busy = true;
  accountablePanel.error = null;
  render();
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  try {
    task();
  } catch (error) {
    accountablePanel.error = error instanceof Error ? error.message : String(error);
  } finally {
    accountablePanel.busy = false;
    render();
  }
};

const bindEvents = (): void => {
  const nSlider = document.querySelector<HTMLInputElement>('#n-slider');
  const tSlider = document.querySelector<HTMLInputElement>('#t-slider');
  const nValue = document.querySelector<HTMLSpanElement>('#n-value');
  const tValue = document.querySelector<HTMLSpanElement>('#t-value');

  if (nSlider && tSlider && nValue && tValue) {
    nSlider.addEventListener('input', () => {
      const n = Number.parseInt(nSlider.value, 10);
      const currentT = state.value.config.threshold;
      const t = Math.min(currentT, n);
      const changed = n !== state.value.config.numParticipants || t !== currentT;
      state.setConfig(n, t);
      nValue.textContent = String(n);
      tValue.textContent = String(t);
      tSlider.max = String(n);
      tSlider.value = String(t);
      if (changed && retireAccountable('participant configuration changed', true)) render();
    });

    tSlider.addEventListener('input', () => {
      const t = Number.parseInt(tSlider.value, 10);
      const changed = t !== state.value.config.threshold;
      state.setConfig(state.value.config.numParticipants, t);
      tValue.textContent = String(t);
      if (changed && retireAccountable('threshold changed', true)) render();
    });

    // On release (not every drag tick), if keys were already generated they no longer
    // match the chosen n/t — discard them so the UI cleanly returns to "generate keys".
    const invalidateStaleKeys = (): void => {
      if (state.value.groupPublicKey !== '') {
        state.resetKeysAndSigning();
        keygenError = null;
        round1Error = null;
        round2Error = null;
        aggregateError = null;
        render();
      }
    };
    nSlider.addEventListener('change', invalidateStaleKeys);
    tSlider.addEventListener('change', invalidateStaleKeys);
  }

  const keygenBtn = document.querySelector<HTMLButtonElement>('#generate-keys');
  keygenBtn?.addEventListener('click', async () => {
    keygenBusy = true;
    keygenError = null;
    render();
    try {
      const out = (await wasmKeygen(state.value.config.threshold, state.value.config.numParticipants)) as KeygenResult;
      state.setKeygenResult(out.group_public_key, toParticipantShares(out.shares));
      retireAccountable('FROST keys regenerated', true);
    } catch (error) {
      keygenError = error instanceof Error ? error.message : String(error);
    } finally {
      keygenBusy = false;
      render();
    }
  });

  // Shamir polynomial visual: toggle between showing t-1 shares (secret
  // undetermined) and t shares (curve locks in, secret = f(0)).
  document.querySelector<HTMLButtonElement>('#sp-toggle-under')?.addEventListener('click', () => {
    shamirRevealAll = false;
    render();
  });
  document.querySelector<HTMLButtonElement>('#sp-toggle-full')?.addEventListener('click', () => {
    shamirRevealAll = true;
    render();
  });

  document.querySelectorAll<HTMLButtonElement>('[data-participant-id]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const before = state.value.selectedParticipants.join(',');
      try {
        state.toggleParticipant(btn.dataset.participantId ?? '');
        if (state.value.selectedParticipants.join(',') !== before) {
          retireAccountable('signer quorum changed', false);
        }
        round1Error = null;
        round2Error = null;
        aggregateError = null;
      } catch (error) {
        round1Error = error instanceof Error ? error.message : String(error);
      }
      render();
    });
  });

  const proceed = document.querySelector<HTMLButtonElement>('#proceed-round1');
  proceed?.addEventListener('click', () => {
    round1Error = null;
    render();
  });

  const messageInput = document.querySelector<HTMLInputElement>('#message-input');
  messageInput?.addEventListener('input', () => {
    const changed = messageInput.value !== messageText;
    messageText = messageInput.value;
    state.setMessageFromText(messageText);
    const retiredAccountable = changed && retireAccountable('message changed', false);

    // If signing already started, the message change invalidates it: the Round 1
    // nonces are bound to one signing attempt, so they must be regenerated for the
    // new message (reusing them would be nonce reuse). Re-render to reflect that;
    // focus + caret are preserved by render(), so typing is not interrupted.
    const hasSigningProgress =
      Object.keys(state.value.round1Output).length > 0 || state.value.finalSignature !== null;
    if (hasSigningProgress) {
      state.resetRoundsKeepSelection();
      round1Error = null;
      round2Error = null;
      aggregateError = null;
      render();
      return;
    }

    if (retiredAccountable) {
      render();
      return;
    }

    // Otherwise just update the hex preview in place — cheaper, and avoids any
    // re-render churn while the learner is still composing the message.
    const hexPreview = document.querySelector<HTMLSpanElement>('#message-hex');
    if (hexPreview) {
      hexPreview.textContent = state.value.message || '(empty)';
    }
  });

  const round1Btn = document.querySelector<HTMLButtonElement>('#run-round1');
  round1Btn?.addEventListener('click', async () => {
    round1Busy = true;
    round1Error = null;
    render();
    try {
      for (const identifier of state.value.selectedParticipants) {
        const share = state.value.shares.find((s) => s.identifier === identifier);
        if (!share) {
          throw new Error('missing participant share for round1');
        }
        const out = (await wasmRound1Commit(identifier, share.secret)) as Round1Result;
        state.setRound1(identifier, {
          hidingNonce: out.hiding_nonce,
          bindingNonce: out.binding_nonce,
          hidingCommitment: out.hiding_commitment,
          bindingCommitment: out.binding_commitment,
          noncesSerialized: out.nonces_serialized
        });
      }
    } catch (error) {
      round1Error = error instanceof Error ? error.message : String(error);
    } finally {
      round1Busy = false;
      render();
    }
  });

  const round2Btn = document.querySelector<HTMLButtonElement>('#run-round2');
  round2Btn?.addEventListener('click', async () => {
    round2Busy = true;
    round2Error = null;
    render();

    try {
      state.requireRound1Complete();
      const signingCommitments = state.value.selectedParticipants.map((id) => {
        const r1 = getRound1For(id);
        return {
          identifier: id,
          hiding_commitment: r1.hidingCommitment,
          binding_commitment: r1.bindingCommitment
        };
      });

      for (const identifier of state.value.selectedParticipants) {
        const share = state.value.shares.find((s) => s.identifier === identifier);
        const r1 = state.value.round1Output[identifier];
        if (!share || !r1) {
          throw new Error('missing participant share or round1 output');
        }

        const out = (await wasmRound2Sign({
          secret_share: {
            identifier: share.identifier,
            secret: share.secret,
            commitment: share.commitment
          },
          nonces: {
            hiding_nonce: r1.hidingNonce,
            binding_nonce: r1.bindingNonce,
            nonces_serialized: r1.noncesSerialized
          },
          message: state.value.message,
          signing_commitments: signingCommitments,
          verifying_key: state.value.groupPublicKey
        })) as Round2Result;

        state.setSignatureShare(identifier, out.signature_share);
      }
    } catch (error) {
      round2Error = error instanceof Error ? error.message : String(error);
    } finally {
      round2Busy = false;
      render();
    }
  });

  const runNonceAttack = async (reuse: boolean): Promise<void> => {
    nonceAttackBusy = true;
    render();
    try {
      nonceReuseResult = await runNonceReuse(reuse);
    } finally {
      nonceAttackBusy = false;
      render();
    }
  };
  document
    .querySelector<HTMLButtonElement>('#attack-nonce-reuse')
    ?.addEventListener('click', () => void runNonceAttack(true));
  document
    .querySelector<HTMLButtonElement>('#attack-nonce-control')
    ?.addEventListener('click', () => void runNonceAttack(false));

  document.querySelector<HTMLButtonElement>('#attack-binding')?.addEventListener('click', async () => {
    bindingAttackBusy = true;
    render();
    try {
      bindingResult = await runBindingOmission();
    } finally {
      bindingAttackBusy = false;
      render();
    }
  });

  const failureToggle = document.querySelector<HTMLInputElement>('#simulate-failure');
  failureToggle?.addEventListener('change', () => {
    simulateFailure = failureToggle.checked;
    render();
  });

  const aggregateBtn = document.querySelector<HTMLButtonElement>('#run-aggregate');
  aggregateBtn?.addEventListener('click', async () => {
    aggregateBusy = true;
    aggregateError = null;
    // Retire the previous verdict before re-running: an attempt that fails must
    // not leave the last run's "valid signature" banner standing.
    state.clearAggregateResult();
    render();
    try {
      state.requireEnoughSharesForAggregation();

      const commitmentList = state.value.selectedParticipants.map((id) => {
        const r1 = getRound1For(id);
        return {
          identifier: id,
          hiding_commitment: r1.hidingCommitment,
          binding_commitment: r1.bindingCommitment
        };
      });

      const signatureShares = state.value.selectedParticipants.map((id) => ({
        identifier: id,
        signature_share: state.value.signatureShares[id]
      }));

      const filteredShares = simulateFailure ? signatureShares.slice(0, Math.max(0, signatureShares.length - 1)) : signatureShares;

      // Aggregation only ever receives PUBLIC verifying shares — never the secret
      // signing shares. The group private key is never reconstructed anywhere.
      const participantShares = state.value.selectedParticipants
        .map((id) => {
          const share = state.value.shares.find((s) => s.identifier === id);
          if (!share) {
            return null;
          }
          return {
            identifier: id,
            verifying_share: share.verifyingShare
          };
        })
        .filter((x): x is { identifier: string; verifying_share: string } => x !== null);

      const out = (await wasmAggregate({
        signature_shares: filteredShares,
        signing_commitments: commitmentList,
        message: state.value.message,
        verifying_key: state.value.groupPublicKey,
        participant_shares: participantShares
      })) as AggregateResult;

      state.setAggregateResult(out.signature, out.verified);
    } catch (error) {
      aggregateError = error instanceof Error ? error.message : String(error);
    } finally {
      aggregateBusy = false;
      render();
    }
  });

  document.querySelector<HTMLButtonElement>('#ats-sign')?.addEventListener('click', () => {
    void runAccountableTask(() => {
      const { numParticipants: n, threshold } = state.value.config;
      if (!accountableKeys || accountableKeys.n !== n || accountableKeys.threshold !== threshold) {
        accountableKeys = atsKeygen(n, threshold);
      }
      const run = runAccountable(
        accountableKeys,
        new TextEncoder().encode(messageText),
        currentAccountableQuorum(),
      );
      accountablePanel = { ...emptyAccountablePanel(), run, busy: true };
    });
  });

  document.querySelector<HTMLButtonElement>('#ats-edit-bitmap')?.addEventListener('click', () => {
    void runAccountableTask(() => {
      if (!accountablePanel.run) throw new Error('make an accountable signature first');
      accountablePanel.bitmapEdit = editAccountableBitmap(accountablePanel.run);
    });
  });

  document.querySelector<HTMLButtonElement>('#ats-threshold-guard')?.addEventListener('click', () => {
    void runAccountableTask(() => {
      if (!accountablePanel.run) throw new Error('make an accountable signature first');
      accountablePanel.thresholdGuard = runThresholdGuard(accountablePanel.run);
    });
  });

  document.querySelector<HTMLButtonElement>('#ats-frame')?.addEventListener('click', () => {
    void runAccountableTask(() => {
      if (!accountablePanel.run) throw new Error('make an accountable signature first');
      accountablePanel.framing = frameAbsentSigner(accountablePanel.run);
    });
  });

  document.querySelector<HTMLButtonElement>('#ats-corrupt-share')?.addEventListener('click', () => {
    void runAccountableTask(() => {
      if (!accountablePanel.run) throw new Error('make an accountable signature first');
      accountablePanel.corruptedShare = corruptOneShare(accountablePanel.run);
    });
  });

  document.querySelector<HTMLButtonElement>('#ats-rogue-key')?.addEventListener('click', () => {
    void runAccountableTask(() => {
      accountablePanel.rogueKey = runRogueKeyFixture(new TextEncoder().encode(messageText));
    });
  });

  document.querySelector<HTMLButtonElement>('#ats-dealer-frame')?.addEventListener('click', () => {
    void runAccountableTask(() => {
      accountablePanel.dealerFrame = runDealerFrameFixture(new TextEncoder().encode(messageText));
    });
  });

  const retry = document.querySelector<HTMLButtonElement>('#retry-subset');
  retry?.addEventListener('click', () => {
    state.resetSigningButKeepKeys();
    retireAccountable('signer quorum reset', false);
    round1Error = null;
    round2Error = null;
    aggregateError = null;
    render();
  });
};

render();
