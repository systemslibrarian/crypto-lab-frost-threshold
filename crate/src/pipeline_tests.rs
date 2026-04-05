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
        .map(|s| round1::frost_round1_commit_impl(&s.identifier).expect("round1 must succeed"))
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
                secret: s.secret.clone(),
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
                secret: s.secret.clone(),
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
                secret: s.secret.clone(),
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
                secret: s.secret.clone(),
            })
            .collect(),
    })
    .expect_err("aggregate must fail under threshold");

    assert!(err.contains("under-threshold input"));
}
