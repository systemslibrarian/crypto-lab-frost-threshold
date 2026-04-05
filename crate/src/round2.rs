use std::collections::BTreeMap;

use frost_ed25519::{
	keys, round1, round2, Identifier, SigningPackage, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Deserialize)]
pub struct SecretShareInput {
	pub identifier: String,
	pub secret: String,
	pub commitment: Vec<String>,
}

#[derive(Clone, Deserialize)]
pub struct NoncesInput {
	pub hiding_nonce: String,
	pub binding_nonce: String,
	pub nonces_serialized: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct SigningCommitmentInput {
	pub identifier: String,
	pub hiding_commitment: String,
	pub binding_commitment: String,
}

#[derive(Clone, Deserialize)]
pub struct Round2Input {
	pub secret_share: SecretShareInput,
	pub nonces: NoncesInput,
	pub message: String,
	pub signing_commitments: Vec<SigningCommitmentInput>,
	pub verifying_key: String,
}

#[derive(Debug, Serialize)]
pub struct Round2Output {
	pub identifier: String,
	pub signature_share: String,
}

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>, String> {
	hex::decode(value).map_err(|e| format!("invalid {label} hex: {e}"))
}

fn parse_identifier(hex_value: &str) -> Result<Identifier, String> {
	let bytes = decode_hex("identifier", hex_value)?;
	Identifier::deserialize(&bytes).map_err(|e| format!("invalid identifier: {e}"))
}

pub fn frost_round2_sign_impl(input: Round2Input) -> Result<Round2Output, String> {
	let identifier = parse_identifier(&input.secret_share.identifier)?;

	let secret_bytes = decode_hex("secret share scalar", &input.secret_share.secret)?;
	let signing_share = keys::SigningShare::deserialize(&secret_bytes)
		.map_err(|e| format!("invalid secret share scalar: {e}"))?;

	let commitment_bytes = input
		.secret_share
		.commitment
		.iter()
		.map(|c| decode_hex("VSS commitment", c))
		.collect::<Result<Vec<_>, _>>()?;

	let vss_commitment = keys::VerifiableSecretSharingCommitment::deserialize(commitment_bytes)
		.map_err(|e| format!("invalid VSS commitment list: {e}"))?;

	let secret_share = keys::SecretShare::new(identifier, signing_share, vss_commitment);
	let key_package = keys::KeyPackage::try_from(secret_share)
		.map_err(|e| format!("failed to verify secret share: {e}"))?;

	let vk_bytes = decode_hex("verifying_key", &input.verifying_key)?;
	let provided_vk = VerifyingKey::deserialize(&vk_bytes)
		.map_err(|e| format!("invalid verifying_key: {e}"))?;
	let expected_vk_bytes = key_package
		.verifying_key()
		.serialize()
		.map_err(|e| format!("failed to serialize key package verifying key: {e}"))?;
	let provided_vk_bytes = provided_vk
		.serialize()
		.map_err(|e| format!("failed to serialize provided verifying_key: {e}"))?;
	if expected_vk_bytes != provided_vk_bytes {
		return Err("verifying_key does not match secret_share commitment".to_string());
	}

	let nonces_serialized_hex = input
		.nonces
		.nonces_serialized
		.as_deref()
		.ok_or_else(|| {
			"nonces.nonces_serialized is required for round2 in this WASM bridge".to_string()
		})?;
	let mut signing_nonces = round1::SigningNonces::deserialize(&decode_hex(
		"nonces_serialized",
		nonces_serialized_hex,
	)?)
	.map_err(|e| format!("invalid nonces_serialized: {e}"))?;

	let mut commitments = BTreeMap::new();
	for c in &input.signing_commitments {
		let id = parse_identifier(&c.identifier)?;
		let hiding = round1::NonceCommitment::deserialize(&decode_hex("hiding_commitment", &c.hiding_commitment)?)
			.map_err(|e| format!("invalid hiding_commitment: {e}"))?;
		let binding = round1::NonceCommitment::deserialize(&decode_hex("binding_commitment", &c.binding_commitment)?)
			.map_err(|e| format!("invalid binding_commitment: {e}"))?;
		commitments.insert(id, round1::SigningCommitments::new(hiding, binding));
	}

	if commitments.len() < *key_package.min_signers() as usize {
		return Err("incorrect commitment list: fewer commitments than threshold".to_string());
	}
	if !commitments.contains_key(&identifier) {
		return Err("incorrect commitment list: missing signer commitment".to_string());
	}

	let message = decode_hex("message", &input.message)?;
	let signing_package = SigningPackage::new(commitments, &message);

	let sig_share = round2::sign(&signing_package, &signing_nonces, &key_package)
		.map_err(|e| format!("round2::sign failed: {e}"))?;

	signing_nonces.zeroize();

	Ok(Round2Output {
		identifier: hex::encode(identifier.serialize()),
		signature_share: hex::encode(sig_share.serialize()),
	})
}
