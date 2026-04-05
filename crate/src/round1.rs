use frost_ed25519::{
	keys,
	rand_core::{CryptoRng, RngCore},
	Identifier,
};
use serde::Serialize;
use zeroize::Zeroize;

#[derive(Default)]
struct JsRng;

impl RngCore for JsRng {
	fn next_u32(&mut self) -> u32 {
		let mut bytes = [0u8; 4];
		self.fill_bytes(&mut bytes);
		u32::from_le_bytes(bytes)
	}

	fn next_u64(&mut self) -> u64 {
		let mut bytes = [0u8; 8];
		self.fill_bytes(&mut bytes);
		u64::from_le_bytes(bytes)
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		if let Err(err) = getrandom::getrandom(dest) {
			panic!("getrandom failed: {err}");
		}
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), frost_ed25519::rand_core::Error> {
		self.fill_bytes(dest);
		Ok(())
	}
}

impl CryptoRng for JsRng {}

#[derive(Serialize)]
pub struct Round1Output {
	pub identifier: String,
	pub hiding_nonce: String,
	pub binding_nonce: String,
	pub hiding_commitment: String,
	pub binding_commitment: String,
	pub nonces_serialized: String,
}

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>, String> {
	hex::decode(value).map_err(|e| format!("invalid {label} hex: {e}"))
}

pub fn frost_round1_commit_impl(identifier_hex: &str) -> Result<Round1Output, String> {
	let identifier_bytes = decode_hex("identifier", identifier_hex)?;
	let identifier = Identifier::deserialize(&identifier_bytes)
		.map_err(|e| format!("invalid identifier: {e}"))?;

	// In production each participant should use its real signing share here; this API only
	// receives an identifier, so we derive a deterministic non-zero scalar from it as a hedge input.
	let nonce_secret = keys::SigningShare::deserialize(&identifier.serialize())
		.map_err(|e| format!("failed to derive nonce secret from identifier: {e}"))?;

	// Nonce reuse is catastrophic: reusing signing nonces across messages can leak the long-lived key share.
	let mut rng = JsRng;
	let (mut signing_nonces, signing_commitments) = frost_ed25519::round1::commit(&nonce_secret, &mut rng);

	let mut hiding_nonce_bytes = signing_nonces.hiding().serialize();
	let mut binding_nonce_bytes = signing_nonces.binding().serialize();
	let mut signing_nonces_bytes = signing_nonces
		.serialize()
		.map_err(|e| format!("failed to serialize signing nonces: {e}"))?;
	let mut hiding_commitment_bytes = signing_commitments
		.hiding()
		.serialize()
		.map_err(|e| format!("failed to serialize hiding commitment: {e}"))?;
	let mut binding_commitment_bytes = signing_commitments
		.binding()
		.serialize()
		.map_err(|e| format!("failed to serialize binding commitment: {e}"))?;

	let out = Round1Output {
		identifier: hex::encode(identifier.serialize()),
		hiding_nonce: hex::encode(&hiding_nonce_bytes),
		binding_nonce: hex::encode(&binding_nonce_bytes),
		hiding_commitment: hex::encode(&hiding_commitment_bytes),
		binding_commitment: hex::encode(&binding_commitment_bytes),
		nonces_serialized: hex::encode(&signing_nonces_bytes),
	};

	hiding_nonce_bytes.zeroize();
	binding_nonce_bytes.zeroize();
	signing_nonces_bytes.zeroize();
	hiding_commitment_bytes.zeroize();
	binding_commitment_bytes.zeroize();
	signing_nonces.zeroize();

	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn round1_outputs_distinct_commitments() {
		let out1 = frost_round1_commit_impl(
			"0100000000000000000000000000000000000000000000000000000000000000",
		)
		.expect("round1 must succeed");
		let out2 = frost_round1_commit_impl(
			"0100000000000000000000000000000000000000000000000000000000000000",
		)
		.expect("round1 must succeed");

		assert_eq!(out1.hiding_commitment.len(), 64);
		assert_eq!(out1.binding_commitment.len(), 64);
		assert_ne!(out1.hiding_commitment, out1.binding_commitment);
		assert_ne!(out1.hiding_nonce, out2.hiding_nonce);
		assert_ne!(out1.binding_nonce, out2.binding_nonce);
	}
}
