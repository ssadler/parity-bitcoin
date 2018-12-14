//! `AddressHash` with network identifier and format type
//!
//! A Bitcoin address, or simply address, is an identifier of 26-35 alphanumeric characters, beginning with the number 1
//! or 3, that represents a possible destination for a bitcoin payment.
//!
//! https://en.bitcoin.it/wiki/Address

use std::fmt;
use std::str::FromStr;
use std::ops::Deref;
use base58::{ToBase58, FromBase58};
use crypto::checksum;
use {DisplayLayout, Error, AddressHash};

/// There are two address formats currently in use.
/// https://bitcoin.org/en/developer-reference#address-conversion
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Type {
	/// Pay to PubKey Hash
	/// Common P2PKH which begin with the number 1, eg: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
	/// https://bitcoin.org/en/glossary/p2pkh-address
	P2PKH,
	/// Pay to Script Hash
	/// Newer P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
	/// https://bitcoin.org/en/glossary/p2sh-address
	P2SH,
}

/// `AddressHash` with prefix and t addr zcash prefix
#[derive(Debug, PartialEq, Clone)]
pub struct Address {
	/// The prefix of the address.
	pub prefix: u8,
	/// T addr prefix, additional prefix used by Zcash and some forks
	pub t_addr_prefix: u8,
	/// Public key hash.
	pub hash: AddressHash,
}

pub struct AddressDisplayLayout(Vec<u8>);

impl Deref for AddressDisplayLayout {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl DisplayLayout for Address {
	type Target = AddressDisplayLayout;

	fn layout(&self) -> Self::Target {
		let mut result = vec![];

		if self.t_addr_prefix > 0 {
			result.push(self.t_addr_prefix);
		}

		result.push(self.prefix);
		result.extend_from_slice(&*self.hash);
		let cs = checksum(&result);
		result.extend_from_slice(&*cs);

		AddressDisplayLayout(result)
	}

	fn from_layout(data: &[u8]) -> Result<Self, Error> where Self: Sized {
		match data.len() {
			25 => {
				let cs = checksum(&data[0..21]);
				if &data[21..] != &*cs {
					return Err(Error::InvalidChecksum);
				}

				let mut hash = AddressHash::default();
				hash.copy_from_slice(&data[1..21]);

				let address = Address {
					t_addr_prefix: 0,
					prefix: data[0],
					hash,
				};

				Ok(address)
			},
			26 => {
				let cs = checksum(&data[0..22]);
				if &data[22..] != &*cs {
					return Err(Error::InvalidChecksum);
				}

				let mut hash = AddressHash::default();
				hash.copy_from_slice(&data[2..22]);

				let address = Address {
					t_addr_prefix: data[0],
					prefix: data[1],
					hash,
				};

				Ok(address)
			},
			_ => return Err(Error::InvalidAddress),
		}
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.layout().to_base58().fmt(f)
	}
}

impl FromStr for Address {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Error> where Self: Sized {
		let hex = try!(s.from_base58().map_err(|_| Error::InvalidAddress));
		Address::from_layout(&hex)
	}
}

impl From<&'static str> for Address {
	fn from(s: &'static str) -> Self {
		s.parse().unwrap()
	}
}

#[cfg(test)]
mod tests {
	use super::{Address};

	#[test]
	fn test_address_to_string() {
		let address = Address {
			prefix: 0,
			t_addr_prefix: 0,
			hash: "3f4aa1fedf1f54eeb03b759deadb36676b184911".into(),
		};

		assert_eq!("16meyfSoQV6twkAAxPe51RtMVz7PGRmWna".to_owned(), address.to_string());
	}

	#[test]
	fn test_komodo_address_to_string() {
		let address = Address {
			prefix: 60,
			t_addr_prefix: 0,
			hash: "05aab5342166f8594baf17a7d9bef5d567443327".into(),
		};

		assert_eq!("R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".to_owned(), address.to_string());
	}

	#[test]
	fn test_zec_t_address_to_string() {
		let address = Address {
			t_addr_prefix: 29,
			prefix: 37,
			hash: "05aab5342166f8594baf17a7d9bef5d567443327".into(),
		};

		assert_eq!("tmAEKD7psc1ajK76QMGEW8WGQSBBHf9SqCp".to_owned(), address.to_string());
	}

	#[test]
	fn test_komodo_p2sh_address_to_string() {
		let address = Address {
			prefix: 85,
			t_addr_prefix: 0,
			hash: "ca0c3786c96ff7dacd40fdb0f7c196528df35f85".into(),
		};

		assert_eq!("bX9bppqdGvmCCAujd76Tq76zs1suuPnB9A".to_owned(), address.to_string());
	}

	#[test]
	fn test_address_from_str() {
		let address = Address {
			prefix: 0,
			t_addr_prefix: 0,
			hash: "3f4aa1fedf1f54eeb03b759deadb36676b184911".into(),
		};

		assert_eq!(address, "16meyfSoQV6twkAAxPe51RtMVz7PGRmWna".into());
	}

	#[test]
	fn test_komodo_address_from_str() {
		let address = Address {
			prefix: 60,
			t_addr_prefix: 0,
			hash: "05aab5342166f8594baf17a7d9bef5d567443327".into(),
		};

		assert_eq!(address, "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into());
	}

	#[test]
	fn test_zec_address_from_str() {
		let address = Address {
			t_addr_prefix: 29,
			prefix: 37,
			hash: "05aab5342166f8594baf17a7d9bef5d567443327".into(),
		};

		assert_eq!(address, "tmAEKD7psc1ajK76QMGEW8WGQSBBHf9SqCp".into());
	}

	#[test]
	fn test_komodo_p2sh_address_from_str() {
		let address = Address {
			prefix: 85,
			t_addr_prefix: 0,
			hash: "ca0c3786c96ff7dacd40fdb0f7c196528df35f85".into(),
		};

		assert_eq!(address, "bX9bppqdGvmCCAujd76Tq76zs1suuPnB9A".into());
	}
}
