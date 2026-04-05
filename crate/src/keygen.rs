use frost_ed25519::{
	keys::{self, SecretShare},
	rand_core::{CryptoRng, RngCore},
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

#[derive(Clone, Serialize)]
pub struct KeygenShare {
	pub identifier: String,
	pub secret: String,
	pub commitment: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct KeygenOutput {
	pub group_public_key: String,
	pub shares: Vec<KeygenShare>,
}

fn share_to_json(mut secret_share: SecretShare) -> Result<KeygenShare, String> {
	let identifier = hex::encode(secret_share.identifier().serialize());

	let mut secret_bytes = secret_share.signing_share().serialize();
	let secret = hex::encode(&secret_bytes);

	let commitment = secret_share
		.commitment()
		.serialize()
		.map_err(|e| format!("failed to serialize VSS commitment: {e}"))?
		.into_iter()
		.map(hex::encode)
		.collect::<Vec<_>>();

	secret_bytes.zeroize();
	secret_share.zeroize();

	Ok(KeygenShare {
		identifier,
		secret,
		commitment,
	})
}

pub fn frost_keygen_impl(threshold: u16, num_participants: u16) -> Result<KeygenOutput, String> {
	if threshold < 2 {
		return Err("threshold must be at least 2".to_string());
	}
	if num_participants < 2 {
		return Err("num_participants must be at least 2".to_string());
	}
	if threshold > num_participants {
		return Err("threshold cannot exceed num_participants".to_string());
	}

	let mut rng = JsRng;
	let (shares, pubkey_package) = keys::generate_with_dealer(
		num_participants,
		threshold,
		keys::IdentifierList::Default,
		&mut rng,
	)
	.map_err(|e| format!("generate_with_dealer failed: {e}"))?;

	let mut group_public_key_bytes = pubkey_package
		.verifying_key()
		.serialize()
		.map_err(|e| format!("failed to serialize verifying key: {e}"))?;
	let group_public_key = hex::encode(&group_public_key_bytes);

	let mut out_shares = Vec::with_capacity(shares.len());
	for (_, secret_share) in shares {
		out_shares.push(share_to_json(secret_share)?);
	}

	group_public_key_bytes.zeroize();

	Ok(KeygenOutput {
		group_public_key,
		shares: out_shares,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn keygen_returns_expected_sizes() {
		let out = frost_keygen_impl(3, 5).expect("keygen must succeed");
		assert_eq!(out.shares.len(), 5);
		assert_eq!(out.group_public_key.len(), 64);
		for s in out.shares {
			assert_eq!(s.identifier.len(), 64);
			assert_eq!(s.secret.len(), 64);
			assert_eq!(s.commitment.len(), 3);
			for c in s.commitment {
				assert_eq!(c.len(), 64);
			}
		}
	}
}
