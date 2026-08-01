export interface ParticipantShare {
  identifier: string;
  secret: string;
  commitment: string[];
  /** Public verifying share from keygen. Safe to share; used for aggregation. */
  verifyingShare: string;
}

export interface Round1ParticipantOutput {
  hidingNonce: string;
  bindingNonce: string;
  hidingCommitment: string;
  bindingCommitment: string;
  noncesSerialized: string;
}

export interface FrostSession {
  config: {
    threshold: number;
    numParticipants: number;
  };
  groupPublicKey: string;
  shares: ParticipantShare[];
  selectedParticipants: string[];
  round1Output: Record<string, Round1ParticipantOutput>;
  message: string;
  signatureShares: Record<string, string>;
  finalSignature: string | null;
  verified: boolean;
}

export interface FrostHistoryEntry {
  participants: string[];
  signature: string;
  /** The verdict the WASM verifier returned for this signature. Never assumed. */
  verified: boolean;
  /** The group key this signature was produced under, so the comparison exhibit
   *  can never show a signature next to a key it does not verify against. */
  groupPublicKey: string;
}

const makeInitial = (): FrostSession => ({
  config: {
    threshold: 3,
    numParticipants: 5
  },
  groupPublicKey: '',
  shares: [],
  selectedParticipants: [],
  round1Output: {},
  message: '',
  signatureShares: {},
  finalSignature: null,
  verified: false
});

export class FrostStateManager {
  private session: FrostSession = makeInitial();

  public signatureHistory: FrostHistoryEntry[] = [];

  get value(): FrostSession {
    return this.session;
  }

  resetAll(): void {
    this.session = makeInitial();
    this.signatureHistory = [];
  }

  resetSigningButKeepKeys(): void {
    this.session.selectedParticipants = [];
    this.session.round1Output = {};
    this.session.signatureShares = {};
    this.session.finalSignature = null;
    this.session.verified = false;
  }

  /**
   * Invalidate everything downstream of key generation, keeping the new config.
   * Used when the n/t sliders change after keys already exist — the old shares no
   * longer match the chosen parameters, so they must be regenerated.
   */
  resetKeysAndSigning(): void {
    this.session.groupPublicKey = '';
    this.session.shares = [];
    this.resetSigningButKeepKeys();
    this.signatureHistory = [];
  }

  /**
   * Invalidate the signing rounds but keep keys AND the selected signers. Used when
   * the message changes: Round 1 nonces are bound to a single signing attempt, so
   * reusing them for a new message would be nonce reuse — they must be regenerated.
   */
  resetRoundsKeepSelection(): void {
    this.session.round1Output = {};
    this.session.signatureShares = {};
    this.session.finalSignature = null;
    this.session.verified = false;
  }

  setConfig(numParticipants: number, threshold: number): void {
    if (numParticipants < 2 || numParticipants > 7) {
      throw new Error('numParticipants must be between 2 and 7');
    }
    if (threshold < 2 || threshold > numParticipants) {
      throw new Error('threshold must be between 2 and numParticipants');
    }
    this.session.config = { numParticipants, threshold };
  }

  setKeygenResult(groupPublicKey: string, shares: ParticipantShare[]): void {
    this.session.groupPublicKey = groupPublicKey;
    this.session.shares = shares;
    this.resetSigningButKeepKeys();
    // A new group key retires every earlier signature: those signatures verify
    // against the OLD key, and the comparison exhibit renders history against the
    // current one. Keeping them would show a signature beside a key it fails under.
    this.signatureHistory = [];
  }

  toggleParticipant(identifier: string): void {
    if (!this.session.shares.find((s) => s.identifier === identifier)) {
      throw new Error('cannot select participant that does not exist in shares');
    }

    const selected = new Set(this.session.selectedParticipants);
    if (selected.has(identifier)) {
      selected.delete(identifier);
    } else {
      selected.add(identifier);
    }

    const next = Array.from(selected);
    if (next.length > this.session.config.threshold) {
      throw new Error('cannot select more than threshold participants');
    }
    this.session.selectedParticipants = next;

    // Changing the signing set invalidates any signing already in progress. Round 1
    // nonces are generated for one specific attempt; reusing them with a different
    // signer set would be nonce reuse (the catastrophe this demo teaches). Drop all
    // in-progress signing artifacts so a fresh Round 1 is required. (No-op on the
    // normal path, where the set is chosen before Round 1 runs.)
    if (Object.keys(this.session.round1Output).length > 0 || this.session.finalSignature !== null) {
      this.session.round1Output = {};
      this.session.signatureShares = {};
      this.session.finalSignature = null;
      this.session.verified = false;
    }
  }

  setMessageFromText(text: string): void {
    const encoder = new TextEncoder();
    this.session.message = Array.from(encoder.encode(text))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  setRound1(identifier: string, output: Round1ParticipantOutput): void {
    if (!this.session.selectedParticipants.includes(identifier)) {
      throw new Error('round1 output can only be set for selected participants');
    }
    this.session.round1Output[identifier] = output;
  }

  requireRound1Complete(): void {
    const selected = this.session.selectedParticipants;
    if (selected.length === 0) {
      throw new Error('no participants selected');
    }
    // Membership, not count: every selected signer must have a Round 1 output.
    // (A count check could pass with a stale entry for a now-deselected signer.)
    if (!selected.every((id) => this.session.round1Output[id] !== undefined)) {
      throw new Error('round1 must be completed for all selected participants before round2');
    }
  }

  setSignatureShare(identifier: string, signatureShare: string): void {
    if (!this.session.round1Output[identifier]) {
      throw new Error('cannot store signature share before round1 for this participant');
    }
    this.session.signatureShares[identifier] = signatureShare;
  }

  requireEnoughSharesForAggregation(): void {
    const selected = this.session.selectedParticipants;
    if (selected.length < this.session.config.threshold) {
      throw new Error('aggregation requires at least threshold selected signers');
    }
    // Membership, not count: every selected signer must have produced a share.
    if (!selected.every((id) => this.session.signatureShares[id] !== undefined)) {
      throw new Error('aggregation requires a signature share from every selected signer');
    }
  }

  /**
   * Drop the previous aggregation verdict. Called before every aggregate attempt
   * so a run that errors (e.g. the simulate-failure toggle withholding a share)
   * cannot leave the earlier run's "Valid Ed25519 Schnorr Signature" banner on
   * screen next to the new error. History of successful signatures is kept.
   */
  clearAggregateResult(): void {
    this.session.finalSignature = null;
    this.session.verified = false;
  }

  setAggregateResult(signature: string, verified: boolean): void {
    this.session.finalSignature = signature;
    this.session.verified = verified;
    if (verified) {
      this.signatureHistory.push({
        participants: [...this.session.selectedParticipants],
        signature,
        verified,
        groupPublicKey: this.session.groupPublicKey
      });
      if (this.signatureHistory.length > 2) {
        this.signatureHistory = this.signatureHistory.slice(-2);
      }
    }
  }
}
