use std::collections::BTreeMap;

use frost_ed25519::{keys, round1, round2, Identifier, SigningPackage, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SignatureShareInput {
	pub identifier: String,
	pub signature_share: String,
}

#[derive(Deserialize)]
pub struct SigningCommitmentInput {
	pub identifier: String,
	pub hiding_commitment: String,
	pub binding_commitment: String,
}

#[derive(Deserialize)]
pub struct ParticipantShareInput {
	pub identifier: String,
	pub secret: String,
}

#[derive(Deserialize)]
pub struct AggregateInput {
	pub signature_shares: Vec<SignatureShareInput>,
	pub signing_commitments: Vec<SigningCommitmentInput>,
	pub message: String,
	pub verifying_key: String,
	#[serde(default)]
	pub participant_shares: Vec<ParticipantShareInput>,
}

#[derive(Debug, Serialize)]
pub struct AggregateOutput {
	pub signature: String,
	pub verified: bool,
	pub message: String,
	pub verifying_key: String,
}

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>, String> {
	hex::decode(value).map_err(|e| format!("invalid {label} hex: {e}"))
}

fn parse_identifier(hex_value: &str) -> Result<Identifier, String> {
	let bytes = decode_hex("identifier", hex_value)?;
	Identifier::deserialize(&bytes).map_err(|e| format!("invalid identifier: {e}"))
}

pub fn frost_aggregate_impl(input: AggregateInput) -> Result<AggregateOutput, String> {
	let mut signing_commitments = BTreeMap::new();
	for c in &input.signing_commitments {
		let id = parse_identifier(&c.identifier)?;
		let hiding = round1::NonceCommitment::deserialize(&decode_hex("hiding_commitment", &c.hiding_commitment)?)
			.map_err(|e| format!("invalid hiding_commitment: {e}"))?;
		let binding = round1::NonceCommitment::deserialize(&decode_hex("binding_commitment", &c.binding_commitment)?)
			.map_err(|e| format!("invalid binding_commitment: {e}"))?;
		signing_commitments.insert(id, round1::SigningCommitments::new(hiding, binding));
	}

	let message = decode_hex("message", &input.message)?;
	let signing_package = SigningPackage::new(signing_commitments.clone(), &message);

	let mut signature_shares = BTreeMap::new();
	for s in &input.signature_shares {
		let id = parse_identifier(&s.identifier)?;
		let sig_share = round2::SignatureShare::deserialize(&decode_hex("signature_share", &s.signature_share)?)
			.map_err(|e| format!("invalid signature_share: {e}"))?;
		signature_shares.insert(id, sig_share);
	}

	if signature_shares.len() < signing_commitments.len() {
		return Err("under-threshold input: fewer signature shares than signing commitments".to_string());
	}

	let mut verifying_shares = BTreeMap::new();
	for p in &input.participant_shares {
		let id = parse_identifier(&p.identifier)?;
		let signing_share = keys::SigningShare::deserialize(&decode_hex("participant secret", &p.secret)?)
			.map_err(|e| format!("invalid participant secret: {e}"))?;
		let verifying_share = keys::VerifyingShare::from(signing_share);
		verifying_shares.insert(id, verifying_share);
	}
	if verifying_shares.is_empty() {
		return Err(
			"participant_shares are required for aggregation in this stateless WASM API"
				.to_string(),
		);
	}

	let vk = VerifyingKey::deserialize(&decode_hex("verifying_key", &input.verifying_key)?)
		.map_err(|e| format!("invalid verifying_key: {e}"))?;

	for id in signature_shares.keys() {
		if !verifying_shares.contains_key(id) {
			return Err("missing participant share for at least one signature share identifier".to_string());
		}
	}

	let pubkey_package = keys::PublicKeyPackage::new(verifying_shares, vk);

	let signature = frost_ed25519::aggregate(&signing_package, &signature_shares, &pubkey_package)
		.map_err(|e| format!("aggregate failed: {e}"))?;

	let verified = pubkey_package
		.verifying_key()
		.verify(&message, &signature)
		.is_ok();

	let signature_hex = hex::encode(
		signature
			.serialize()
			.map_err(|e| format!("failed to serialize signature: {e}"))?,
	);

	Ok(AggregateOutput {
		signature: signature_hex,
		verified,
		message: hex::encode(message),
		verifying_key: input.verifying_key.to_lowercase(),
	})
}
