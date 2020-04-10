use std::{fmt, ops};
use secp256k1::{Message as SecpMessage, PublicKey, PublicKeyFormat, Signature as SecpSignature, verify};
use hex::ToHex;
use crypto::dhash160;
use hash::{H264, H520};
use {AddressHash, Error, Signature, Message};

/// Secret public key
#[derive(Clone)]
pub enum Public {
	/// Normal version of public key
	Normal(H520),
	/// Compressed version of public key
	Compressed(H264),
}

impl Default for Public {
	fn default() -> Public {
		Public::Compressed(H264::default())
	}
}

impl Public {
	pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
		match data.len() {
			33 => {
				let mut public = H264::default();
				public.copy_from_slice(data);
				Ok(Public::Compressed(public))
			},
			65 => {
				let mut public = H520::default();
				public.copy_from_slice(data);
				Ok(Public::Normal(public))
			},
			_ => Err(Error::InvalidPublic)
		}
	}

	pub fn address_hash(&self) -> AddressHash {
		dhash160(self)
	}

	pub fn verify(&self, message: &Message, signature: &Signature) -> Result<bool, Error> {
		let public = match self {
			Public::Compressed(public) => PublicKey::parse_slice(&**public, Some(PublicKeyFormat::Compressed))?,
			Public::Normal(public) => PublicKey::parse_slice(&**public, Some(PublicKeyFormat::Full))?,
		};
		let mut signature = SecpSignature::parse_der_lax(signature)?;
		signature.normalize_s();
		let message = SecpMessage::parse_slice(&**message)?;
		Ok(verify(&message, &signature, &public))
	}
}

impl ops::Deref for Public {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		match *self {
			Public::Normal(ref hash) => &**hash,
			Public::Compressed(ref hash) => &**hash,
		}
	}
}

impl PartialEq for Public {
	fn eq(&self, other: &Self) -> bool {
		let s_slice: &[u8] = self;
		let o_slice: &[u8] = other;
		s_slice == o_slice
	}
}

impl fmt::Debug for Public {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Public::Normal(ref hash) => writeln!(f, "normal: {}", hash.to_hex::<String>()),
			Public::Compressed(ref hash) => writeln!(f, "compressed: {}", hash.to_hex::<String>()),
		}
	}
}

impl fmt::Display for Public {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.to_hex::<String>().fmt(f)
	}
}
