use crate::{aggregate, keygen, round1, round2};

fn build_and_sign(
    threshold: u16,
    participants: u16,
) -> (
    keygen::KeygenOutput,
    Vec<round2::Round2Output>,
    Vec<round1::Round1Output>,
    Vec<keygen::KeygenShare>,
    String,
) {
    let keygen_out = keygen::frost_keygen_impl(threshold, participants).expect("keygen must succeed");
    let selected = keygen_out
        .shares
        .iter()
        .take(threshold as usize)
        .cloned()
        .collect::<Vec<_>>();

    let message = hex::encode(format!("frost-demo-{threshold}-of-{participants}").as_bytes());

    let round1_outputs = selected
        .iter()
        .map(|s| {
            round1::frost_round1_commit_impl(&s.identifier, &s.secret).expect("round1 must succeed")
        })
        .collect::<Vec<_>>();

    let commitments = round1_outputs
        .iter()
        .map(|r| round2::SigningCommitmentInput {
            identifier: r.identifier.clone(),
            hiding_commitment: r.hiding_commitment.clone(),
            binding_commitment: r.binding_commitment.clone(),
        })
        .collect::<Vec<_>>();

    let round2_outputs = selected
        .iter()
        .zip(round1_outputs.iter())
        .map(|(share, r1)| {
            round2::frost_round2_sign_impl(round2::Round2Input {
                secret_share: round2::SecretShareInput {
                    identifier: share.identifier.clone(),
                    secret: share.secret.clone(),
                    commitment: share.commitment.clone(),
                },
                nonces: round2::NoncesInput {
                    hiding_nonce: r1.hiding_nonce.clone(),
                    binding_nonce: r1.binding_nonce.clone(),
                    nonces_serialized: Some(r1.nonces_serialized.clone()),
                },
                message: message.clone(),
                signing_commitments: commitments.clone(),
                verifying_key: keygen_out.group_public_key.clone(),
            })
            .expect("round2 must succeed")
        })
        .collect::<Vec<_>>();

    (keygen_out, round2_outputs, round1_outputs, selected, message)
}

/// Run the full sign+aggregate pipeline for an explicit subset of participants
/// (by index into `keygen_out.shares`) over an explicit message. Returns the
/// aggregated signature output. Used to prove subset-independence.
fn sign_subset(
    keygen_out: &keygen::KeygenOutput,
    indices: &[usize],
    message_text: &str,
) -> aggregate::AggregateOutput {
    let selected = indices
        .iter()
        .map(|&i| keygen_out.shares[i].clone())
        .collect::<Vec<_>>();
    let message = hex::encode(message_text.as_bytes());

    let round1_outputs = selected
        .iter()
        .map(|s| {
            round1::frost_round1_commit_impl(&s.identifier, &s.secret).expect("round1 must succeed")
        })
        .collect::<Vec<_>>();

    let commitments = round1_outputs
        .iter()
        .map(|r| round2::SigningCommitmentInput {
            identifier: r.identifier.clone(),
            hiding_commitment: r.hiding_commitment.clone(),
            binding_commitment: r.binding_commitment.clone(),
        })
        .collect::<Vec<_>>();

    let round2_outputs = selected
        .iter()
        .zip(round1_outputs.iter())
        .map(|(share, r1)| {
            round2::frost_round2_sign_impl(round2::Round2Input {
                secret_share: round2::SecretShareInput {
                    identifier: share.identifier.clone(),
                    secret: share.secret.clone(),
                    commitment: share.commitment.clone(),
                },
                nonces: round2::NoncesInput {
                    hiding_nonce: r1.hiding_nonce.clone(),
                    binding_nonce: r1.binding_nonce.clone(),
                    nonces_serialized: Some(r1.nonces_serialized.clone()),
                },
                message: message.clone(),
                signing_commitments: commitments.clone(),
                verifying_key: keygen_out.group_public_key.clone(),
            })
            .expect("round2 must succeed")
        })
        .collect::<Vec<_>>();

    aggregate::frost_aggregate_impl(aggregate::AggregateInput {
        signature_shares: round2_outputs
            .iter()
            .map(|s| aggregate::SignatureShareInput {
                identifier: s.identifier.clone(),
                signature_share: s.signature_share.clone(),
            })
            .collect(),
        signing_commitments: round1_outputs
            .iter()
            .map(|c| aggregate::SigningCommitmentInput {
                identifier: c.identifier.clone(),
                hiding_commitment: c.hiding_commitment.clone(),
                binding_commitment: c.binding_commitment.clone(),
            })
            .collect(),
        message,
        verifying_key: keygen_out.group_public_key.clone(),
        participant_shares: selected
            .iter()
            .map(|s| aggregate::ParticipantShareInput {
                identifier: s.identifier.clone(),
                verifying_share: s.verifying_share.clone(),
            })
            .collect(),
    })
    .expect("aggregate must succeed")
}

#[test]
fn pipeline_2_of_3() {
    let (keygen_out, round2_outputs, round1_outputs, selected, message) = build_and_sign(2, 3);

    let aggregate_out = aggregate::frost_aggregate_impl(aggregate::AggregateInput {
        signature_shares: round2_outputs
            .iter()
            .map(|s| aggregate::SignatureShareInput {
                identifier: s.identifier.clone(),
                signature_share: s.signature_share.clone(),
            })
            .collect(),
        signing_commitments: round1_outputs
            .iter()
            .map(|c| aggregate::SigningCommitmentInput {
                identifier: c.identifier.clone(),
                hiding_commitment: c.hiding_commitment.clone(),
                binding_commitment: c.binding_commitment.clone(),
            })
            .collect(),
        message,
        verifying_key: keygen_out.group_public_key,
        participant_shares: selected
            .iter()
            .map(|s| aggregate::ParticipantShareInput {
                identifier: s.identifier.clone(),
                verifying_share: s.verifying_share.clone(),
            })
            .collect(),
    })
    .expect("aggregate must succeed");

    assert!(aggregate_out.verified);
    assert_eq!(aggregate_out.signature.len(), 128);
}

#[test]
fn pipeline_3_of_5() {
    let (keygen_out, round2_outputs, round1_outputs, selected, message) = build_and_sign(3, 5);

    let aggregate_out = aggregate::frost_aggregate_impl(aggregate::AggregateInput {
        signature_shares: round2_outputs
            .iter()
            .map(|s| aggregate::SignatureShareInput {
                identifier: s.identifier.clone(),
                signature_share: s.signature_share.clone(),
            })
            .collect(),
        signing_commitments: round1_outputs
            .iter()
            .map(|c| aggregate::SigningCommitmentInput {
                identifier: c.identifier.clone(),
                hiding_commitment: c.hiding_commitment.clone(),
                binding_commitment: c.binding_commitment.clone(),
            })
            .collect(),
        message,
        verifying_key: keygen_out.group_public_key,
        participant_shares: selected
            .iter()
            .map(|s| aggregate::ParticipantShareInput {
                identifier: s.identifier.clone(),
                verifying_share: s.verifying_share.clone(),
            })
            .collect(),
    })
    .expect("aggregate must succeed");

    assert!(aggregate_out.verified);
    assert_eq!(aggregate_out.signature.len(), 128);
}

#[test]
fn pipeline_5_of_5() {
    let (keygen_out, round2_outputs, round1_outputs, selected, message) = build_and_sign(5, 5);

    let aggregate_out = aggregate::frost_aggregate_impl(aggregate::AggregateInput {
        signature_shares: round2_outputs
            .iter()
            .map(|s| aggregate::SignatureShareInput {
                identifier: s.identifier.clone(),
                signature_share: s.signature_share.clone(),
            })
            .collect(),
        signing_commitments: round1_outputs
            .iter()
            .map(|c| aggregate::SigningCommitmentInput {
                identifier: c.identifier.clone(),
                hiding_commitment: c.hiding_commitment.clone(),
                binding_commitment: c.binding_commitment.clone(),
            })
            .collect(),
        message,
        verifying_key: keygen_out.group_public_key,
        participant_shares: selected
            .iter()
            .map(|s| aggregate::ParticipantShareInput {
                identifier: s.identifier.clone(),
                verifying_share: s.verifying_share.clone(),
            })
            .collect(),
    })
    .expect("aggregate must succeed");

    assert!(aggregate_out.verified);
    assert_eq!(aggregate_out.signature.len(), 128);
}

#[test]
fn round2_wrong_commitment_list_errors() {
    let (keygen_out, _round2_outputs, round1_outputs, selected, message) = build_and_sign(3, 5);

    let bad_commitments = round1_outputs
        .iter()
        .skip(1)
        .map(|r| round2::SigningCommitmentInput {
            identifier: r.identifier.clone(),
            hiding_commitment: r.hiding_commitment.clone(),
            binding_commitment: r.binding_commitment.clone(),
        })
        .collect::<Vec<_>>();

    let err = round2::frost_round2_sign_impl(round2::Round2Input {
        secret_share: round2::SecretShareInput {
            identifier: selected[0].identifier.clone(),
            secret: selected[0].secret.clone(),
            commitment: selected[0].commitment.clone(),
        },
        nonces: round2::NoncesInput {
            hiding_nonce: round1_outputs[0].hiding_nonce.clone(),
            binding_nonce: round1_outputs[0].binding_nonce.clone(),
            nonces_serialized: Some(round1_outputs[0].nonces_serialized.clone()),
        },
        message,
        signing_commitments: bad_commitments,
        verifying_key: keygen_out.group_public_key,
    })
    .expect_err("round2 must fail with incorrect commitment list");

    assert!(err.contains("incorrect commitment list"));
}

#[test]
fn aggregate_under_threshold_errors() {
    let (keygen_out, round2_outputs, round1_outputs, selected, message) = build_and_sign(3, 5);

    let err = aggregate::frost_aggregate_impl(aggregate::AggregateInput {
        signature_shares: round2_outputs
            .iter()
            .take(2)
            .map(|s| aggregate::SignatureShareInput {
                identifier: s.identifier.clone(),
                signature_share: s.signature_share.clone(),
            })
            .collect(),
        signing_commitments: round1_outputs
            .iter()
            .map(|c| aggregate::SigningCommitmentInput {
                identifier: c.identifier.clone(),
                hiding_commitment: c.hiding_commitment.clone(),
                binding_commitment: c.binding_commitment.clone(),
            })
            .collect(),
        message,
        verifying_key: keygen_out.group_public_key,
        participant_shares: selected
            .iter()
            .map(|s| aggregate::ParticipantShareInput {
                identifier: s.identifier.clone(),
                verifying_share: s.verifying_share.clone(),
            })
            .collect(),
    })
    .expect_err("aggregate must fail under threshold");

    assert!(err.contains("under-threshold input"));
}

/// Core teaching claim #1: any threshold-sized subset produces a VALID signature,
/// and different subsets produce DIFFERENT signature bytes — yet all verify against
/// the same group public key. The secret key is never reassembled in any of them.
#[test]
fn different_subsets_produce_distinct_valid_signatures() {
    let keygen_out = keygen::frost_keygen_impl(3, 5).expect("keygen must succeed");

    let sig_a = sign_subset(&keygen_out, &[0, 1, 2], "same message");
    let sig_b = sign_subset(&keygen_out, &[2, 3, 4], "same message");

    assert!(sig_a.verified, "subset A must verify");
    assert!(sig_b.verified, "subset B must verify");
    assert_eq!(sig_a.signature.len(), 128);
    assert_eq!(sig_b.signature.len(), 128);
    // Distinct nonces/binding factors => distinct signature bytes for distinct subsets.
    assert_ne!(
        sig_a.signature, sig_b.signature,
        "different subsets should yield different signature bytes"
    );
    // ...both bound to the SAME group verifying key.
    assert_eq!(sig_a.verifying_key, sig_b.verifying_key);
}

/// Core teaching claim #2: the signature is bound to the exact message. Verifying
/// the produced signature against a different message must fail.
#[test]
fn signature_does_not_verify_against_tampered_message() {
    use frost_ed25519::{Signature, VerifyingKey};

    let keygen_out = keygen::frost_keygen_impl(2, 3).expect("keygen must succeed");
    let out = sign_subset(&keygen_out, &[0, 1], "transfer 10 to alice");
    assert!(out.verified);

    let vk = VerifyingKey::deserialize(&hex::decode(&out.verifying_key).unwrap()).unwrap();
    let sig = Signature::deserialize(&hex::decode(&out.signature).unwrap()).unwrap();

    assert!(
        vk.verify(b"transfer 10 to alice", &sig).is_ok(),
        "must verify against the original message"
    );
    assert!(
        vk.verify(b"transfer 1000 to mallory", &sig).is_err(),
        "must NOT verify against a tampered message"
    );
}

/// Core teaching claim #3: the aggregated output is a bona fide, standard Ed25519
/// signature — not merely self-consistent inside FROST. We cross-verify it with the
/// independent, unrelated `ed25519-dalek` library, exactly as any external verifier
/// (e.g. a TLS stack or `ssh`) would. A group of signers is indistinguishable from one.
#[test]
fn output_verifies_with_independent_ed25519_verifier() {
    use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey as DalekKey};

    let keygen_out = keygen::frost_keygen_impl(3, 5).expect("keygen must succeed");
    let msg = "the glory of God";
    let out = sign_subset(&keygen_out, &[1, 2, 4], msg);
    assert!(out.verified);

    let key_bytes: [u8; 32] = hex::decode(&out.verifying_key).unwrap().try_into().unwrap();
    let sig_bytes: [u8; 64] = hex::decode(&out.signature).unwrap().try_into().unwrap();

    let dalek_key = DalekKey::from_bytes(&key_bytes).expect("valid ed25519 public key");
    let dalek_sig = DalekSig::from_bytes(&sig_bytes);

    dalek_key
        .verify(msg.as_bytes(), &dalek_sig)
        .expect("FROST output must verify under a standard, independent Ed25519 verifier");
}
