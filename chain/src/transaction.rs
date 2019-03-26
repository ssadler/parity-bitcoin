//! Bitcoin trainsaction.
//! https://en.bitcoin.it/wiki/Protocol_documentation#tx

use std::io;
use hex::FromHex;
use bytes::Bytes;
use ser::{deserialize, serialize, serialize_with_flags, SERIALIZE_TRANSACTION_WITNESS};
use crypto::dhash256;
use hash::{H64, H256, H512, EncCipherText, OutCipherText, ZkProofSapling, CipherText};
use constants::{SEQUENCE_FINAL, LOCKTIME_THRESHOLD};
use ser::{Error, Serializable, Deserializable, Stream, Reader};

/// Must be zero.
const WITNESS_MARKER: u8 = 0;
/// Must be nonzero.
const WITNESS_FLAG: u8 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Default, Serializable, Deserializable)]
pub struct OutPoint {
	pub hash: H256,
	pub index: u32,
}

impl OutPoint {
	pub fn null() -> Self {
		OutPoint {
			hash: H256::default(),
			index: u32::max_value(),
		}
	}

	pub fn is_null(&self) -> bool {
		self.hash.is_zero() && self.index == u32::max_value()
	}
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct TransactionInput {
	pub previous_output: OutPoint,
	pub script_sig: Bytes,
	pub sequence: u32,
	pub script_witness: Vec<Bytes>,
}

impl TransactionInput {
	pub fn coinbase(script_sig: Bytes) -> Self {
		TransactionInput {
			previous_output: OutPoint::null(),
			script_sig,
			sequence: SEQUENCE_FINAL,
			script_witness: vec![],
		}
	}

	pub fn is_final(&self) -> bool {
		self.sequence == SEQUENCE_FINAL
	}

	pub fn has_witness(&self) -> bool {
		!self.script_witness.is_empty()
	}
}

#[derive(Debug, PartialEq, Clone, Serializable, Deserializable)]
pub struct TransactionOutput {
	pub value: u64,
	pub script_pubkey: Bytes,
}

impl Default for TransactionOutput {
	fn default() -> Self {
		TransactionOutput {
			value: 0xffffffffffffffffu64,
			script_pubkey: Bytes::default(),
		}
	}
}

#[derive(Debug, PartialEq, Clone, Serializable, Deserializable)]
pub struct ShieldedSpend {
	pub cv: H256,
	pub anchor: H256,
	pub nullifier: H256,
	pub rk: H256,
	pub zkproof: ZkProofSapling,
	pub spend_auth_sig: H512,
}

#[derive(Debug, PartialEq, Clone, Serializable, Deserializable)]
pub struct ShieldedOutput {
	pub cv: H256,
	pub cmu: H256,
	pub ephemeral_key: H256,
	pub enc_cipher_text: EncCipherText,
	pub out_cipher_text: OutCipherText,
	pub zkproof: ZkProofSapling,
}

#[derive(Debug, PartialEq, Clone)]
pub struct JoinSplit {
	pub v_pub_old: H64,
	pub v_pub_new: H64,
	pub anchor: H256,
	pub nullifiers: [H256; 2],
	pub commitments: [H256; 2],
	pub ephemeral_key: H256,
	pub random_seed: H256,
	pub macs: [H256; 2],
	pub zkproof: ZkProofSapling,
	pub ciphertexts: [CipherText; 2],
}

// TODO Make it more optimal later by adding fixed-size array support to serialization_derive crate
impl Serializable for JoinSplit {
	fn serialize(&self, stream: &mut Stream) {
		stream.append(&self.v_pub_old)
            .append(&self.v_pub_new)
            .append(&self.anchor)
            .append(&self.nullifiers[0])
            .append(&self.nullifiers[1])
		    .append(&self.commitments[0])
		    .append(&self.commitments[1])
		    .append(&self.ephemeral_key)
		    .append(&self.random_seed)
		    .append(&self.macs[0])
		    .append(&self.macs[1])
		    .append(&self.zkproof)
		    .append(&self.ciphertexts[0])
		    .append(&self.ciphertexts[1]);
	}
}

// TODO Make it more optimal later by adding fixed-size array support to serialization_derive crate
impl Deserializable for JoinSplit {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read {
		Ok(JoinSplit {
			v_pub_old: reader.read()?,
			v_pub_new: reader.read()?,
			anchor: reader.read()?,
			nullifiers: [reader.read()?, reader.read()?],
			commitments: [reader.read()?, reader.read()?],
			ephemeral_key: reader.read()?,
			random_seed: reader.read()?,
			macs: [reader.read()?, reader.read()?],
			zkproof: reader.read()?,
			ciphertexts: [reader.read()?, reader.read()?],
		})
	}
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct Transaction {
	pub version: i32,
	pub overwintered: bool,
	pub version_group_id: u32,
	pub inputs: Vec<TransactionInput>,
	pub outputs: Vec<TransactionOutput>,
	pub lock_time: u32,
	pub expiry_height: u32,
	pub shielded_spends: Vec<ShieldedSpend>,
	pub shielded_outputs: Vec<ShieldedOutput>,
	pub join_splits: Vec<JoinSplit>,
	pub value_balance: u64,
	pub join_split_pubkey: H256,
	pub join_split_sig: H512,
	pub binding_sig: H512,
}

impl From<&'static str> for Transaction {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex().unwrap() as &[u8]).unwrap()
	}
}

impl Transaction {
	pub fn hash(&self) -> H256 {
		dhash256(&serialize(self))
	}

	pub fn witness_hash(&self) -> H256 {
		dhash256(&serialize_with_flags(self, SERIALIZE_TRANSACTION_WITNESS))
	}

	pub fn inputs(&self) -> &[TransactionInput] {
		&self.inputs
	}

	pub fn outputs(&self) -> &[TransactionOutput] {
		&self.outputs
	}

	pub fn is_empty(&self) -> bool {
		self.inputs.is_empty() || self.outputs.is_empty()
	}

	pub fn is_null(&self) -> bool {
		self.inputs.iter().any(|input| input.previous_output.is_null())
	}

	pub fn is_coinbase(&self) -> bool {
		self.inputs.len() == 1 && self.inputs[0].previous_output.is_null()
	}

	pub fn is_final(&self) -> bool {
		// if lock_time is 0, transaction is final
		if self.lock_time == 0 {
			return true;
		}
		// setting all sequence numbers to 0xffffffff disables the time lock, so if you want to use locktime,
		// at least one input must have a sequence number below the maximum.
		self.inputs.iter().all(TransactionInput::is_final)
	}

	pub fn is_final_in_block(&self, block_height: u32, block_time: u32) -> bool {
		if self.lock_time == 0 {
			return true;
		}

		let max_lock_time = if self.lock_time < LOCKTIME_THRESHOLD {
			block_height
		} else {
			block_time
		};

		if self.lock_time < max_lock_time {
			return true;
		}

		self.inputs.iter().all(TransactionInput::is_final)
	}

	pub fn has_witness(&self) -> bool {
		self.inputs.iter().any(TransactionInput::has_witness)
	}

	pub fn total_spends(&self) -> u64 {
		let mut result = 0u64;
		for output in self.outputs.iter() {
			if u64::max_value() - result < output.value {
				return u64::max_value();
			}
			result += output.value;
		}
		result
	}
}

impl Serializable for TransactionInput {
	fn serialize(&self, stream: &mut Stream) {
		stream
			.append(&self.previous_output)
			.append(&self.script_sig)
			.append(&self.sequence);
	}
}

impl Deserializable for TransactionInput {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read {
		Ok(TransactionInput {
			previous_output: reader.read()?,
			script_sig: reader.read()?,
			sequence: reader.read()?,
			script_witness: vec![],
		})
	}
}

impl Serializable for Transaction {
	fn serialize(&self, stream: &mut Stream) {
		let include_transaction_witness = stream.include_transaction_witness() && self.has_witness();
		match include_transaction_witness {
			false => {
                let mut header = self.version;
                if self.overwintered {
                    header |= 1 << 31;
                }
                stream.append(&header);

                if self.overwintered {
                    stream.append(&self.version_group_id);
                }

                stream.append_list(&self.inputs)
                    .append_list(&self.outputs)
                    .append(&self.lock_time);

                if self.overwintered && self.version >= 3 {
                    stream.append(&self.expiry_height);
                    if self.version >= 4 {
                        stream.append(&self.value_balance)
                            .append_list(&self.shielded_spends)
                            .append_list(&self.shielded_outputs);
                    }
                }

                if self.version == 2 || self.overwintered {
                    stream.append_list(&self.join_splits);
                    if self.join_splits.len() > 0 {
                        stream.append(&self.join_split_pubkey)
                            .append(&self.join_split_sig);
                    }
                }

                if self.version >= 4 && self.overwintered &&
                    !(self.shielded_outputs.len() == 0 && self.shielded_spends.len() == 0)
                {
                    stream.append(&self.binding_sig);
                }
            },
			true => {
				stream
					.append(&self.version)
					.append(&WITNESS_MARKER)
					.append(&WITNESS_FLAG)
					.append_list(&self.inputs)
					.append_list(&self.outputs);
				for input in &self.inputs {
					stream.append_list(&input.script_witness);
				}
				stream.append(&self.lock_time);
			}
		};
	}
}

impl Deserializable for Transaction {
	fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error> where Self: Sized, T: io::Read {
		let header: i32 = reader.read()?;
		let overwintered: bool = (header >> 31) != 0;
		let version = if overwintered {
			header & 0x7FFFFFFF
		} else {
			header
		};

		let mut version_group_id = 0;
		if overwintered {
			version_group_id = reader.read()?;
		}

		let mut inputs: Vec<TransactionInput> = reader.read_list()?;
		let read_witness = if inputs.is_empty() && !overwintered {
			let witness_flag: u8 = reader.read()?;
			if witness_flag != WITNESS_FLAG {
				return Err(Error::MalformedData);
			}

			inputs = reader.read_list()?;
			true
		} else {
			false
		};
		let outputs = reader.read_list()?;
		if read_witness {
			for input in inputs.iter_mut() {
				input.script_witness = reader.read_list()?;
			}
		}

		let lock_time = reader.read()?;

		let mut expiry_height = 0;
		let mut value_balance = 0;
		let mut shielded_spends = vec![];
		let mut shielded_outputs = vec![];
		if overwintered && version >= 3 {
			expiry_height = reader.read()?;
			if version >= 4 {
				value_balance = reader.read()?;
				shielded_spends = reader.read_list()?;
				shielded_outputs = reader.read_list()?;
			}
		}

		let mut join_splits = vec![];
		let mut join_split_pubkey = H256::default();
		let mut join_split_sig = H512::default();

		if version == 2 || overwintered {
			join_splits = reader.read_list()?;
			if join_splits.len() > 0 {
				join_split_pubkey = reader.read()?;
				join_split_sig = reader.read()?;
			}
		}

		let mut binding_sig = H512::default();
		if overwintered && version >= 4 && !(shielded_spends.len() == 0 && shielded_outputs.len() == 0) {
			binding_sig = reader.read()?;
		}

		Ok(Transaction {
			version,
			overwintered,
			version_group_id,
			expiry_height,
			value_balance,
			inputs,
			outputs,
			lock_time,
			binding_sig,
			join_split_pubkey,
			join_split_sig,
			join_splits,
			shielded_spends,
			shielded_outputs,
		})
	}
}

#[cfg(test)]
mod tests {
	use hash::{H256, H512};
	use ser::{Serializable, serialize, serialize_with_flags, SERIALIZE_TRANSACTION_WITNESS};
	use super::{Transaction, TransactionInput, OutPoint, TransactionOutput, Bytes};

	// real transaction from block 80000
	// https://blockchain.info/rawtx/5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2
	// https://blockchain.info/rawtx/5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2?format=hex
	#[test]
	fn test_transaction_reader() {
		let t: Transaction = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();
		assert_eq!(t.version, 1);
		assert_eq!(t.lock_time, 0);
		assert_eq!(t.inputs.len(), 1);
		assert_eq!(t.outputs.len(), 1);
		let tx_input = &t.inputs[0];
		assert_eq!(tx_input.sequence, 4294967295);
		assert_eq!(tx_input.script_sig, "48304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501".into());
		let tx_output = &t.outputs[0];
		assert_eq!(tx_output.value, 5000000000);
		assert_eq!(tx_output.script_pubkey, "76a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac".into());
		assert!(!t.has_witness());
	}

	#[test]
	fn test_transaction_reader_v7() {
		let raw = "0700000001f87575693f4c038018628ff89f64571f0b9b48cd91a09b984d7eb018f4753bfa000000006a47304402202a3c612b11db1be51ae47fc1c23cc73e7fb14f08f10b3e71e5778d7adad494e90220636ca2580324452d8596cea7b2ebc31d796787108a7f74b676e3f136cb2c56b9012102e75e70baceb8cd5ae2bdc893d018512aafc8aac403ae8c14da66fa3ede87fcc3ffffffff0148b6eb0b000000001976a914139df01a608671fcf24db66d2d02bf2d4274e1f888ac00000000";
		let t: Transaction = raw.into();

		assert_eq!(t.version, 7);
		assert_eq!(t.lock_time, 0);
		assert_eq!(t.inputs.len(), 1);
		assert_eq!(t.outputs.len(), 1);

		let serialized = serialize(&t);
		assert_eq!(Bytes::from(raw), serialized);
	}

    // https://github.com/zcash/zips/blob/master/zip-0243.rst#test-vector-1
    #[test]
	fn test_transaction_serde_overwintered_sapling() {
        let raw = "0400008085202f890002e7719811893e0000095200ac6551ac636565b2835a0805750200025151481cdd86b3cc4318442117623ceb0500031b3d1a027c2c40590958b7eb13d742a997738c46a458965baf276ba92f272c721fe01f7e9c8e36d6a5e29d4e30a73594bf5098421c69378af1e40f64e125946f62c2fa7b2fecbcb64b6968912a6381ce3dc166d56a1d62f5a8d7551db5fd9313e8c7203d996af7d477083756d59af80d06a745f44ab023752cb5b406ed8985e18130ab33362697b0e4e4c763ccb8f676495c222f7fba1e31defa3d5a57efc2e1e9b01a035587d5fb1a38e01d94903d3c3e0ad3360c1d3710acd20b183e31d49f25c9a138f49b1a537edcf04be34a9851a7af9db6990ed83dd64af3597c04323ea51b0052ad8084a8b9da948d320dadd64f5431e61ddf658d24ae67c22c8d1309131fc00fe7f235734276d38d47f1e191e00c7a1d48af046827591e9733a97fa6b679f3dc601d008285edcbdae69ce8fc1be4aac00ff2711ebd931de518856878f73476f21a482ec9378365c8f7393c94e2885315eb4671098b79535e790fe53e29fef2b3766697ac32b4f473f468a008e72389fc03880d780cb07fcfaabe3f1a15825b7acb4d6b57a61bc68f242b52e4fbf85cf1a09cc45b6d6bb3a391578f499486a7afd04a0d9c74c2995d96b4de37b36046a1ef6d190b916b1111c92887311a20da8aba18d1dbebbc862ded42435e92476930d069896cff30eb414f727b89e001afa2fb8dc3436d75a4a6f26572504b192232ecb9f0c02411e52596bc5e90457e745939ffedbd12863ce71a02af117d417adb3d15cc54dcb1fce467500c6b8fb86b12b56da9c382857deecc40a98d5f2935395ee4762dd21afdbb5d47fa9a6dd984d567db2857b927b7fae2db587105415d4642789d38f50b8dbcc129cab3d17d19f3355bcf73cecb8cb8a5da01307152f13936a270572670dc82d39026c6cb4cd4b0f7f5aa2a4f5a5341ec5dd715406f2fdd2afa733f5f641c8c21862a1bafce2609d9eecfa158cfb5cd79f88008e315dc7d8388e76c1782fd2795d18a763624c25fa959cc97489ce75745824b77868c53239cfbdf73caec65604037314faaceb56218c6bd30f8374ac13386793f21a9fb80ad03bc0cda4a44946c00e1b102c78f11876b7065212183199fb5979ca77d2c24c738fe5145f02602053bb4c2f6556df6ed4b4ddd3d9a69f53357d7767f4f5ccbdbc596631277f8fecd08cb056b95e3025b9792fff7f244fc716269b926d62e9596fa825c6bf21aff9e68625a192440ea06828123d97884806f15fa08da52754a1095e3ff1abd5ce4fddfccfc3a6128aef784a64610a89d1a7099216d0814d3a2d452431c32d411ac1cce82ad0229407bbc48985675e3f874a4533f1d63a84dfa3e0f460fe2f57e34fbc75423c3737f5b2a0615f5722db041a3ef66fa483afd3c2e19e59444a64add6df1d963f5dd5b5010d3d025f0287c4cf19c75f33d51ddddba5d657b43ee8da645443814cc7329f3e9b4e54c236c29af3923101756d9fa4bd0f7d2ddaacb6b0f86a2658e0a07a05ac5b950051cd24c47a88d13d659ba2a46ca1830816d09cd7646f76f716abec5de07fe9b523410806ea6f288f8736c23357c85f45791e1708029d9824d90704607f387a03e49bf9836574431345a7877efaa8a08e73081ef8d62cb780a010fa3207ee2f0408097d563da1b2146819edf88d33e7753664fb71d122a6e36998fbd467f75b780149ae8808f4e68f50c0536acddf6f1aeab016b6bc1ec144b4e59aeb77eef49d00e5fbb67101cdd41e6bc9cf641a52fca98be915f8440a410d74cb30e15914f01bc6bc2307b488d2556d7b7380ea4ffd712f6b02fe806b94569cd4059f396bf29b99d0a40e5e1711ca944f72d436a102fca4b97693da0b086fe9d2e7162470d02e0f05d4bec9512bfb3f38327296efaa74328b118c27402c70c3a90b49ad4bbc68e37c0aa7d9b3fe17799d73b841e751713a02943905aae0803fd69442eb7681ec2a05600054e92eed555028f21b6a155268a2dd6640a69301a52a38d4d9f9f957ae35af7167118141ce4c9be0a6a492fe79f1581a155fa3a2b9dafd82e650b386ad3a08cb6b83131ac300b0846354a7eef9c410e4b62c47c5426907dfc6685c5c99b7141ac626ab4761fd3f41e728e1a28f89db89ffdeca364dd2f0f0739f0534556483199c71f189341ac9b78a269164206a0ea1ce73bfb2a942e7370b247c046f8e75ef8e3f8bd821cf577491864e20e6d08fd2e32b555c92c661f19588b72a89599710a88061253ca285b6304b37da2b5294f5cb354a894322848ccbdc7c2545b7da568afac87ffa005c312241c2d57f4b45d6419f0d2e2c5af33ae243785b325cdab95404fc7aed70525cddb41872cfcc214b13232edc78609753dbff930eb0dc156612b9cb434bc4b693392deb87c530435312edcedc6a961133338d786c4a3e103f60110a16b1337129704bf4754ff6ba9fbe65951e610620f71cda8fc877625f2c5bb04cbe1228b1e886f4050afd8fe94e97d2e9e85c6bb748c0042d3249abb1342bb0eebf62058bf3de080d94611a3750915b5dc6c0b3899d41222bace760ee9c8818ded599e34c56d7372af1eb86852f2a732104bdb750739de6c2c6e0f9eb7cb17f1942bfc9f4fd6ebb6b4cdd4da2bca26fac4578e9f543405acc7d86ff59158bd0cba3aef6f4a8472d144d99f8b8d1dedaa9077d4f01d4bb27bbe31d88fbefac3dcd4797563a26b1d61fcd9a464ab21ed550fe6fa09695ba0b2f10eea6468cc6e20a66f826e3d14c5006f0563887f5e1289be1b2004caca8d3f34d6e84bf59c1e04619a7c23a996941d889e4622a9b9b1d59d5e319094318cd405ba27b7e2c084762d31453ec4549a4d97729d033460fcf89d6494f2ffd789e98082ea5ce9534b3acd60fe49e37e4f666931677319ed89f85588741b3128901a93bd78e4be0225a9e2692c77c969ed0176bdf9555948cbd5a332d045de6ba6bf4490adfe7444cd467a09075417fc0200000000000000000000000000000000062e49f008c51ad4227439c1b4476ccd8e97862dab7be1e8d399c05ef27c6e22ee273e15786e394c8f1be31682a30147963ac8da8d41d804258426a3f70289b8ad19d8de13be4eebe3bd4c8a6f55d6e0c373d456851879f5fbc282db9e134806bff71e11bc33ab75dd6ca067fb73a043b646a7cf39cab4928386786d2f24141ee120fdc34d6764eafc66880ee0204f53cc1167ed20b43a52dea3ca7cff8ef35cd8e6d7c111a68ef44bcd0c1513ad47ca61c659cc5d325b440f6b9f59aff66879bb6688fd2859362b182f207b3175961f6411a493bffd048e7d0d87d82fe6f990a2b0a25f5aa0111a6e68f37bf6f3ac2d26b84686e569d58d99c1383597fad81193c4c1b16e6a90e2d507cdfe6fbdaa86163e9cf5de3100fbca7e8da047b090db9f37952fbfee76af61668190bd52ed490e677b515d014384af07219c7c0ee7fc7bfc79f325644e4df4c0d7db08e9f0bd024943c705abff8994bfa605cfbc7ed746a7d3f7c37d9e8bdc433b7d79e08a12f738a8f0dbddfef2f2657ef3e47d1b0fd11e6a13311fb799c79c641d9da43b33e7ad012e28255398789262275f1175be8462c01491c4d842406d0ec4282c9526174a09878fe8fdde33a29604e5e5e7b2a025d6650b97dbb52befb59b1d30a57433b0a351474444099daa371046613260cf3354cfcdada663ece824ffd7e44393886a86165ddddf2b4c41773554c86995269408b11e6737a4c447586f69173446d8e48bf84cbc000a807899973eb93c5e819aad669413f8387933ad1584aa35e43f4ecd1e2d0407c0b1b89920ffdfdb9bea51ac95b557af71b89f903f5d9848f14fcbeb1837570f544d6359eb23faf38a0822da36ce426c4a2fbeffeb0a8a2e297a9d19ba15024590e3329d9fa9261f9938a4032dd34606c9cf9f3dd33e576f05cd1dd6811c6298757d77d9e810abdb226afcaa4346a6560f8932b3181fd355d5d391976183f8d99388839632d6354f666d09d3e5629ea19737388613d38a34fd0f6e50ee5a0cc9677177f50028c141378187bd2819403fc534f80076e9380cb4964d3b6b45819d3b8e9caf54f051852d671bf8c1ffde2d1510756418cb4810936aa57e6965d6fb656a760b7f19adf96c173488552193b147ee58858033dac7cd0eb204c06490bbdedf5f7571acb2ebe76acef3f2a01ee987486dfe6c3f0a5e234c127258f97a28fb5d164a8176be946b8097d0e317287f33bf9c16f9a545409ce29b1f4273725fc0df02a04ebae178b3414fb0a82d50deb09fcf4e6ee9d180ff4f56ff3bc1d3601fc2dc90d814c3256f4967d3a8d64c83fea339c51f5a8e5801fbb97835581b602465dee04b5922c2761b54245bec0c9eef2db97d22b2b3556cc969fbb13d06509765a52b3fac54b93f421bf08e18d52ddd52cc1c8ca8adfaccab7e5cc2f4573fbbf8239bb0b8aedbf8dad16282da5c9125dba1c059d0df8abf621078f02d6c4bc86d40845ac1d59710c45f07d585eb48b32fc0167ba256e73ca3b9311c62d109497957d8dbe10aa3e866b40c0baa2bc492c19ad1e6372d9622bf163fbffeaeee796a3cd9b6fbbfa4d792f34d7fd6e763cd5859dd26833d21d9bc5452bd19515dff9f4995b35bc0c1f876e6ad11f2452dc9ae85aec01fc56f8cbfda75a7727b75ebbd6bbffb43b63a3b1b671e40feb0db002974a3c3b1a788567231bf6399ff89236981149d423802d2341a3bedb9ddcbac1fe7b6435e1479c72e7089d029e7fbbaf3cf37e9b9a6b776791e4c5e6fda57e8d5f14c8c35a2d270846b9dbe005cda16af4408f3ab06a916eeeb9c9594b70424a4c1d171295b6763b22f47f80b53ccbb904bd68fd65fbd3fbdea1035e98c21a7dbc91a9b5bc7690f05ec317c97f8764eb48e911d428ec8d861b708e8298acb62155145155ae95f0a1d1501034753146e22d05f586d7f6b4fe12dad9a17f5db70b1db96b8d9a83edadc966c8a5466b61fc998c31f1070d9a5c9a6d268d304fe6b8fd3b4010348611abdcbd49fe4f85b623c7828c71382e1034ea67bc8ae97404b0c50b2a04f559e49950afcb0ef462a2ae024b0f0224dfd73684b88c7fbe92d02b68f759c4752663cd7b97a14943649305521326bde085630864629291bae25ff8822a14c4b666a9259ad0dc42a8290ac7bc7f53a16f379f758e5de750f04fd7cad47701c8597f97888bea6fa0bf2999956fbfd0ee68ec36e4688809ae231eb8bc4369f5fe1573f57e099d9c09901bf39caac48dc11956a8ae905ead86954547c448ae43d315e669c4242da565938f417bf43ce7b2b30b1cd4018388e1a910f0fc41fb0877a5925e466819d375b0a912d4fe843b76ef6f223f0f7c894f38f7ab780dfd75f669c8c06cffa0000000000000000000000000000000043eb47565a50e3b1fa45ad61ce9a1c4727b7aaa53562f523e73952bbf33d8a4104078ade3eaaa49699a69fdf1c5ac7732146ee5e1d6b6ca9b9180f964cc9d0878ae1373524d7d510e58227df6de9d30d271867640177b0f1856e28d5c8afb095ef6184fed651589022eeaea4c0ce1fa6f085092b04979489172b3ef8194a798df5724d6b05f1ae000013a08d612bca8a8c31443c10346dbf61de8475c0bbec5104b47556af3d514458e2321d146071789d2335934a680614e83562f82dfd405b54a45eb32c165448d4d5d61ca2859585369f53f1a137e9e82b67b8fdaf01bda54a317311896ae10280a032440c420a421e944d1e952b70d5826cd3b08b7db9630fe4fd5f22125de840fcc40b98038af11d55be25432597b4b65b9ec1c7a8bbfd052cbf7e1c1785314934b262d5853754f1f17771cfb7503072655753fa3f54ecc587e9f83b581916092df26e63e18994cb0db91a0bbdc7b6119b32222adf5e61d8d8ae89dae4954b54813bb33f08d562ba513fee1b09c0fcd516055419474dd7fda038a89c84ea7b9468287f0eb0c10c4b132520194d3d8d5351fc10d09c15c8cc101aa1663bbf17b84111f38bb439f07353bdea3596d15e713e1e2e7d3f1c383135b47fa7f81f46df7a902a404699ec912f5656c35b85763e4de583aecaa1dfd5d2677d9c8ffee877f63f40a5ca0d67f6e554124739f805af876aeede53aa8b0f8e5604a73c30cbd09dad963d6f8a5dcc40def40797342113ba206fae8ebe4f3bc3caf69259e462eff9ba8b3f4bfaa1300c26925a8729cd32915bfc966086f0d5560bbe32a598c22adfb48cef72ba5d4287c0cefbacfd8ce195b4963c34a94bba7a175dae4bbe3ef4863d53708915090f47a068e227433f9e49d3aa09e356d8d66d0c0121e91a3c4aa3f27fa1b63396e2b41db908fdab8b18cc7304e94e970568f9421c0dbbbaf84598d972b0534f48a5e52670436aaa776ed2482ad703430201e53443c36dcfd34a0cb6637876105e79bf3bd58ec148cb64970e3223a91f71dfcfd5a04b667fbaf3d4b3b908b9828820dfecdd753750b5f9d2216e56c615272f854464c0ca4b1e85aedd038292c4e1a57744ebba010b9ebfbb011bd6f0b78805025d27f3c17746bae116c15d9f471f0f6288a150647b2afe9df7cccf01f5cde5f04680bbfed87f6cf429fb27ad6babe791766611cf5bc20e48bef119259b9b8a0e39c3df28cb9582ea338601cdc481b32fb82adeebb3dade25d1a3df20c37e712506b5d996c49a9f0f30ddcb91fe9004e1e83294a6c9203d94e8dc2cbb449de4155032604e47997016b304fd437d8235045e255a19b743a0a9f2e336b44cae307bb3987bd3e4e777fbb34c0ab8cc3d67466c0a88dd4ccad18a07a8d1068df5b629e5718d0f6df5c957cf71bb00a5178f175caca944e635c5159f738e2402a2d21aa081e10e456afb00b9f62416c8b9c0f7228f510729e0be3f305313d77f7379dc2af24869c6c74ee4471498861d192f0ff0f508285dab6b6a36ccf7d12256cc76b95503720ac672d08268d2cf7773b6ba2a5f664847bf707f2fc10c98f2f006ec22ccb5a8c8b7c40c7c2d49a6639b9f2ce33c25c04bc461e744dfa536b00d94baddf4f4d14044c695a33881477df124f0fcf206a9fb2e65e304cdbf0c4d2390170c130ab849c2f22b5cdd3921640c8cf1976ae1010b0dfd9cb2543e45f99749cc4d61f2e8aabfe98bd905fa39951b33ea769c45ab9531c57209862ad12fd76ba4807e65417b6cd12fa8ec916f013ebb8706a96effeda06c4be24b04846392e9d1e6930eae01fa21fbd700583fb598b92c8f4eb8a61aa6235db60f2841cf3a1c6ab54c67066844711d091eb931a1bd6281aedf2a0e8fab18817202a9be06402ed9cc720c16bfe881e4df4255e87afb7fc62f38116bbe03cd8a3cb11a27d568414782f47b1a44c97c680467694bc9709d32916c97e8006cbb07ba0e4180a3738038c374c4cce8f32959afb25f303f5815c4533124acf9d18940e77522ac5dc4b9570aae8f47b7f57fd8767bea1a24ae7bed65b4afdc8f1278c30e2db98fd172730ac6bbed4f1127cd32b04a95b205526cfcb4c4e1cc955175b3e8de1f5d81b18669692350aaa1a1d797617582e54d7a5b57a683b32fb1098062dad7b0c2eb518f6862e83db25e3dbaf7aed504de932acb99d735992ce62bae9ef893ff6acc0ffcf8e3483e146b9d49dd8c7835f43a37dca0787e3ec9f6605223d5ba7ae0ab9025b73bc03f7fac36c009a56d4d95d1e81d3b3ebca7e54cc1a12d127b57c8138976e791013b015f06a624f521b6ee04ec980893c7e5e01a336203594094f82833d7445fe2d09130f63511da54832de9136b39f4599f5aa5dfbb45da60cdceab7eefde89be63f3f7c0d2324847cce1405def7c469b0e272494e5df54f568656cb9c8818d92b72b8bc34db7bb3112487e746eefe4e808bbb287d99bf07d00dabededc5e5f074ffeae0cba7da3a516c173be1c513323e119f635e8209a074b216b7023fadc2d25949c90037e71e3e550726d210a2c688342e52440635e9cc14afe10102621a9c9accb782e9e4a5fa87f0a956f5b";
		let t: Transaction = raw.into();
		assert_eq!(t.version, 4);
		assert!(t.overwintered);
		assert!(!t.has_witness());
        assert_eq!(t.inputs.len(), 0);
        assert_eq!(t.outputs.len(), 2);
        assert_eq!(t.shielded_spends.len(), 3);
        assert_eq!(t.shielded_outputs.len(), 1);
        assert_eq!(t.join_splits.len(), 2);

        let serialized = serialize(&t);
        assert_eq!(Bytes::from(raw), serialized);
	}

	// http://explore.myce.world/api/getrawtransaction?txid=248b2cadff69bb58f3232b914d32588cd9cd014d4f3dc29cd39d1914bf1d7f43&decrypt=0
	// MYCE has txversion = 3, but no Zcash upgrades
	#[test]
	fn test_transaction_serde_tx_version_3_not_overwintered() {
        let raw = "030000000145f09710b0d6ff73a52bffdd1661f2f001783fb6f947ecf253462359dca19e990100000049483045022100e2f6183e2008e6b0aa31f728f289c66436bf4d4be7aedfe0c3f582e60d16443e0220741548d2cee78a2b39a8e1146b131a69211da025ff0859dba60e38b12a46a0b501ffffffff026c39ea0b000000001976a9142b79bc408688f48858083de027a1b42ed3e39da188ac380265d9450000001976a914066baabb56dc1588afd7fa83e0ffd4729aee89d588ac00000000";
		let t: Transaction = raw.into();
		assert_eq!(t.version, 3);
		assert!(!t.overwintered);
		assert!(!t.has_witness());
        assert_eq!(t.inputs.len(), 1);
        assert_eq!(t.outputs.len(), 2);
        assert_eq!(t.shielded_spends.len(), 0);
        assert_eq!(t.shielded_outputs.len(), 0);
        assert_eq!(t.join_splits.len(), 0);
        let serialized = serialize(&t);
        assert_eq!(Bytes::from(raw), serialized);
	}

	#[test]
	fn test_transaction_hash() {
		let t: Transaction = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();
		let hash = H256::from_reversed_str("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2");
		assert_eq!(t.hash(), hash);
	}

	#[test]
	fn test_transaction_serialized_len() {
		let raw_tx: &'static str = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000";
		let tx: Transaction = raw_tx.into();
		assert_eq!(tx.serialized_size(), raw_tx.len() / 2);
	}

	#[test]
	fn test_transaction_reader_with_witness() {
		// test case from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
		let actual: Transaction = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000".into();
		let expected = Transaction {
			version: 1,
			overwintered: false,
			expiry_height: 0,
			binding_sig: H512::default(),
			join_split_pubkey: H256::default(),
			join_split_sig: H512::default(),
			join_splits: vec![],
			shielded_spends: vec![],
			shielded_outputs: vec![],
			value_balance: 0,
			version_group_id: 0,
			inputs: vec![TransactionInput {
				previous_output: OutPoint {
					hash: "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f".into(),
					index: 0,
				},
				script_sig: "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01".into(),
				sequence: 0xffffffee,
				script_witness: vec![],
			}, TransactionInput {
				previous_output: OutPoint {
					hash: "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a".into(),
					index: 1,
				},
				script_sig: "".into(),
				sequence: 0xffffffff,
				script_witness: vec![
					"304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01".into(),
					"025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357".into(),
				],
			}],
			outputs: vec![TransactionOutput {
				value: 0x0000000006b22c20,
				script_pubkey: "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac".into(),
			}, TransactionOutput {
				value: 0x000000000d519390,
				script_pubkey: "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac".into(),
			}],
			lock_time: 0x00000011,
		};
		assert_eq!(actual, expected);
	}

	#[test]
	fn test_serialization_with_flags() {
		let transaction_without_witness: Transaction = "000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();
		assert_eq!(serialize_with_flags(&transaction_without_witness, 0), serialize_with_flags(&transaction_without_witness, SERIALIZE_TRANSACTION_WITNESS));

		let transaction_with_witness: Transaction = "0000000000010100000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000000000".into();
		assert!(serialize_with_flags(&transaction_with_witness, 0) != serialize_with_flags(&transaction_with_witness, SERIALIZE_TRANSACTION_WITNESS));
	}

	#[test]
	fn test_witness_hash_differs() {
		let transaction_without_witness: Transaction = "000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();
		assert_eq!(transaction_without_witness.hash(), transaction_without_witness.witness_hash());

		let transaction_with_witness: Transaction = "0000000000010100000000000000000000000000000000000000000000000000000000000000000000000000000000000001010000000000".into();
		assert!(transaction_with_witness.hash() != transaction_with_witness.witness_hash());
	}
}
