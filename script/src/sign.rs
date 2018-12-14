//! Transaction signer

use blake2b_simd::{Params as Blake2b, State as Blake2bState};
use bytes::Bytes;
use chain::{Transaction, TransactionOutput, OutPoint, TransactionInput, JoinSplit, ShieldedSpend, ShieldedOutput};
use crypto::dhash256;
use hash::{H256, H512};
use keys::KeyPair;
use ser::{serialize, Stream};
use {Script, Builder};

const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8] = b"ZcashOutputsHash";
const ZCASH_JOIN_SPLITS_HASH_PERSONALIZATION: &[u8] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8] = b"ZcashSOutputHash";
const ZCASH_SIG_HASH_PERSONALIZATION: &[u8] = b"ZcashSigHash";

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SignatureVersion {
	Base,
	WitnessV0,
	ForkId,
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum SighashBase {
	All = 1,
	None = 2,
	Single = 3,
}

impl From<SighashBase> for u32 {
	fn from(s: SighashBase) -> Self {
		s as u32
	}
}

#[cfg_attr(feature="cargo-clippy", allow(doc_markdown))]
/// Signature hash type. [Documentation](https://en.bitcoin.it/wiki/OP_CHECKSIG#Procedure_for_Hashtype_SIGHASH_SINGLE)
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Sighash {
	pub base: SighashBase,
	pub anyone_can_pay: bool,
	pub fork_id: bool,
}

impl From<Sighash> for u32 {
	fn from(s: Sighash) -> Self {
		let base = s.base as u32;
		let base = if s.anyone_can_pay {
			base | 0x80
		} else {
			base
		};

		if s.fork_id {
			base | 0x40
		} else {
			base
		}
	}
}

impl Sighash {
	pub fn new(base: SighashBase, anyone_can_pay: bool, fork_id: bool) -> Self {
		Sighash {
			base,
			anyone_can_pay,
			fork_id,
		}
	}

	/// Used by SCRIPT_VERIFY_STRICTENC
	pub fn is_defined(version: SignatureVersion, u: u32) -> bool {
		// reset anyone_can_pay && fork_id (if applicable) bits
		let u = match version {
			SignatureVersion::ForkId => u & !(0x40 | 0x80),
			_ => u & !(0x80),
		};

		// Only exact All | None | Single values are passing this check
		match u {
			1 | 2 | 3 => true,
			_ => false,
		}
	}

	/// Creates Sighash from any u, even if is_defined() == false
	pub fn from_u32(version: SignatureVersion, u: u32) -> Self {
		let anyone_can_pay = (u & 0x80) == 0x80;
		let fork_id = version == SignatureVersion::ForkId && (u & 0x40) == 0x40;
		let base = match u & 0x1f {
			2 => SighashBase::None,
			3 => SighashBase::Single,
			1 | _ => SighashBase::All,
		};

		Sighash::new(base, anyone_can_pay, fork_id)
	}
}

#[derive(Debug)]
pub struct UnsignedTransactionInput {
	pub previous_output: OutPoint,
	pub sequence: u32,
}

/// Used for resigning and loading test transactions
impl From<TransactionInput> for UnsignedTransactionInput {
	fn from(i: TransactionInput) -> Self {
		UnsignedTransactionInput {
			previous_output: i.previous_output,
			sequence: i.sequence,
		}
	}
}

#[derive(Debug)]
pub struct TransactionInputSigner {
	pub version: i32,
	pub overwintered: bool,
	pub version_group_id: u32,
	pub expiry_height: u32,
	pub value_balance: u64,
	pub inputs: Vec<UnsignedTransactionInput>,
	pub outputs: Vec<TransactionOutput>,
	pub lock_time: u32,
	pub join_splits: Vec<JoinSplit>,
	pub shielded_spends: Vec<ShieldedSpend>,
	pub shielded_outputs: Vec<ShieldedOutput>,
}

/// Used for resigning and loading test transactions
impl From<Transaction> for TransactionInputSigner {
	fn from(t: Transaction) -> Self {
		TransactionInputSigner {
			version: t.version,
			overwintered: t.overwintered,
			version_group_id: t.version_group_id,
			expiry_height: t.expiry_height,
			value_balance: t.value_balance,
			inputs: t.inputs.into_iter().map(Into::into).collect(),
			outputs: t.outputs,
			lock_time: t.lock_time,
			join_splits: t.join_splits.clone(),
			shielded_spends: t.shielded_spends.clone(),
			shielded_outputs: t.shielded_outputs.clone(),
		}
	}
}

impl TransactionInputSigner {
	pub fn signature_hash(&self, input_index: usize, input_amount: u64, script_pubkey: &Script, sigversion: SignatureVersion, sighashtype: u32) -> H256 {
		let sighash = Sighash::from_u32(sigversion, sighashtype);
		match sigversion {
			SignatureVersion::ForkId if sighash.fork_id => self.signature_hash_fork_id(input_index, input_amount, script_pubkey, sighashtype, sighash),
			SignatureVersion::Base | SignatureVersion::ForkId => self.signature_hash_original(input_index, script_pubkey, sighashtype, sighash),
			SignatureVersion::WitnessV0 => self.signature_hash_witness0(input_index, input_amount, script_pubkey, sighashtype, sighash),
		}
	}

	/// input_index - index of input to sign
	/// script_pubkey - script_pubkey of input's previous_output pubkey
	pub fn signed_input(
		&self,
		keypair: &KeyPair,
		input_index: usize,
		input_amount: u64,
		script_pubkey: &Script,
		sigversion: SignatureVersion,
		sighash: u32,
	) -> TransactionInput {
		let hash = self.signature_hash(input_index, input_amount, script_pubkey, sigversion, sighash);

		let mut signature: Vec<u8> = keypair.private().sign(&hash).unwrap().into();
		signature.push(sighash as u8);
		let script_sig = Builder::default()
			.push_data(&signature)
			//.push_data(keypair.public())
			.into_script();

		let unsigned_input = &self.inputs[input_index];
		TransactionInput {
			previous_output: unsigned_input.previous_output.clone(),
			sequence: unsigned_input.sequence,
			script_sig: script_sig.to_bytes(),
			script_witness: vec![],
		}
	}

	pub fn signature_hash_original(&self, input_index: usize, script_pubkey: &Script, sighashtype: u32, sighash: Sighash) -> H256 {
		if input_index >= self.inputs.len() {
			return 1u8.into();
		}

		if sighash.base == SighashBase::Single && input_index >= self.outputs.len() {
			return 1u8.into();
		}

		let script_pubkey = script_pubkey.without_separators();

		let inputs = if sighash.anyone_can_pay {
			let input = &self.inputs[input_index];
			vec![TransactionInput {
				previous_output: input.previous_output.clone(),
				script_sig: script_pubkey.to_bytes(),
				sequence: input.sequence,
				script_witness: vec![],
			}]
		} else {
			self.inputs.iter()
				.enumerate()
				.map(|(n, input)| TransactionInput {
					previous_output: input.previous_output.clone(),
					script_sig: if n == input_index {
						script_pubkey.to_bytes()
					} else {
						Bytes::default()
					},
					sequence: match sighash.base {
						SighashBase::Single | SighashBase::None if n != input_index => 0,
						_ => input.sequence,
					},
					script_witness: vec![],
				})
				.collect()
		};

		let outputs = match sighash.base {
			SighashBase::All => self.outputs.clone(),
			SighashBase::Single => self.outputs.iter()
				.take(input_index + 1)
				.enumerate()
				.map(|(n, out)| if n == input_index {
					out.clone()
				} else {
					TransactionOutput::default()
				})
				.collect(),
			SighashBase::None => Vec::new(),
		};

		let tx = Transaction {
			inputs,
			outputs,
			version: self.version,
			lock_time: self.lock_time,
			binding_sig: H512::default(),
			expiry_height: 0,
			join_split_pubkey: H256::default(),
			join_split_sig: H512::default(),
			join_splits: vec![],
			overwintered: false,
			shielded_spends: vec![],
			shielded_outputs: vec![],
			value_balance: 0,
			version_group_id: 0,
		};

		let mut stream = Stream::default();
		stream.append(&tx);
		stream.append(&sighashtype);
		let out = stream.out();
		dhash256(&out)
	}

	fn signature_hash_witness0(&self, input_index: usize, input_amount: u64, script_pubkey: &Script, sighashtype: u32, sighash: Sighash) -> H256 {
		let hash_prevouts = compute_hash_prevouts(sighash, &self.inputs);
		let hash_sequence = compute_hash_sequence(sighash, &self.inputs);
		let hash_outputs = compute_hash_outputs(sighash, input_index, &self.outputs);

		let mut stream = Stream::default();
		stream.append(&self.version);
		stream.append(&hash_prevouts);
		stream.append(&hash_sequence);
		stream.append(&self.inputs[input_index].previous_output);
		stream.append_list(&**script_pubkey);
		stream.append(&input_amount);
		stream.append(&self.inputs[input_index].sequence);
		stream.append(&hash_outputs);
		stream.append(&self.lock_time);
		stream.append(&sighashtype); // this also includes 24-bit fork id. which is 0 for BitcoinCash
		let out = stream.out();
		dhash256(&out)
	}

	fn signature_hash_fork_id(&self, input_index: usize, input_amount: u64, script_pubkey: &Script, sighashtype: u32, sighash: Sighash) -> H256 {
		if input_index >= self.inputs.len() {
			return 1u8.into();
		}

		if sighash.base == SighashBase::Single && input_index >= self.outputs.len() {
			return 1u8.into();
		}

		self.signature_hash_witness0(input_index, input_amount, script_pubkey, sighashtype, sighash)
	}

	/// https://github.com/zcash/zips/blob/master/zip-0243.rst#notes
	/// This method doesn't cover all possible Sighash combinations so it doesn't fully match the
	/// specification, however I don't need other cases yet as BarterDEX marketmaker always uses
	/// SIGHASH_ALL
	pub fn signature_hash_overwintered(
		&self,
		input_index: usize,
		input_amount: u64,
		script_pubkey: &Script,
		sighashtype: u32,
		sighash: Sighash
	) -> Result<H256, String> {
		let mut personalization = ZCASH_SIG_HASH_PERSONALIZATION.to_vec();
		// uint32_t leConsensusBranchId = htole32(consensusBranchId);
		// unsigned char personalization[16] = {};
		// memcpy(personalization, "ZcashSigHash", 12);
		// memcpy(personalization+12, &leConsensusBranchId, 4);
		// https://github.com/zcash/zcash/issues/3413
		if self.version == 3 {
			personalization.extend_from_slice(&[0x19, 0x1B, 0xA8, 0x5B]);
		} else if self.version == 4 {
			personalization.extend_from_slice(&[0xBB, 0x09, 0xB8, 0x76]);
		} else {
			return Err("Invalid tx version, don't have the consensus branch id for it".to_owned())
		}

		let mut sig_hash = blake_2b_256_personal(&personalization);

		let mut header = self.version;
		if self.overwintered {
			header |= 1 << 31;
		}
		sig_hash.update(&serialize(&header));
		sig_hash.update(&serialize(&self.version_group_id));
		let mut prev_out_hash = blake_2b_256_personal(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
		for input in self.inputs.iter() {
			prev_out_hash.update(&serialize(&input.previous_output));
		}
		sig_hash.update(prev_out_hash.finalize().as_bytes());

		let mut sequence_hash = blake_2b_256_personal(ZCASH_SEQUENCE_HASH_PERSONALIZATION);
		for input in self.inputs.iter() {
			sequence_hash.update(&serialize(&input.sequence));
		}

		sig_hash.update(sequence_hash.finalize().as_bytes());

		let mut outputs_hash = blake_2b_256_personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
		for output in self.outputs.iter() {
			outputs_hash.update(&serialize(output));
		}
		sig_hash.update(outputs_hash.finalize().as_bytes());

		if self.join_splits.len() > 0 {
			let mut join_splits_hash = blake_2b_256_personal(ZCASH_JOIN_SPLITS_HASH_PERSONALIZATION);
			for split in self.join_splits.iter() {
				join_splits_hash.update(&serialize(split));
			}
			sig_hash.update(join_splits_hash.finalize().as_bytes());
		} else {
			sig_hash.update(&[0; 32]);
		}

		if self.shielded_spends.len() > 0 {
			let mut s_spends_hash = blake_2b_256_personal(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION);
			for spend in self.shielded_spends.iter() {
				s_spends_hash.update(&serialize(&spend.cv))
					.update(&serialize(&spend.anchor))
					.update(&serialize(&spend.nullifier))
					.update(&serialize(&spend.rk))
					.update(&serialize(&spend.zkproof));
			}
			sig_hash.update(s_spends_hash.finalize().as_bytes());
		} else {
			sig_hash.update(&[0; 32]);
		}

		if self.shielded_outputs.len() > 0 {
			let mut s_outputs_hash = blake_2b_256_personal(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION);
			for output in self.shielded_outputs.iter() {
				s_outputs_hash.update(&serialize(output));
			}
			sig_hash.update(s_outputs_hash.finalize().as_bytes());
		} else {
			sig_hash.update(&[0; 32]);
		}

		sig_hash.update(&serialize(&self.lock_time));
		sig_hash.update(&serialize(&self.expiry_height));
		sig_hash.update(&serialize(&self.value_balance));
		sig_hash.update(&serialize(&sighashtype));

		sig_hash.update(&serialize(&self.inputs[input_index].previous_output));
		sig_hash.update(script_pubkey);
		sig_hash.update(&serialize(&input_amount));
		sig_hash.update(&serialize(&self.inputs[input_index].sequence));

		Ok(H256::from(sig_hash.finalize().as_bytes()))
	}
}

fn compute_hash_prevouts(sighash: Sighash, inputs: &[UnsignedTransactionInput]) -> H256 {
	match sighash.anyone_can_pay {
		false => {
			let mut stream = Stream::default();
			for input in inputs {
				stream.append(&input.previous_output);
			}
			dhash256(&stream.out())
		},
		true => 0u8.into(),
	}
}

fn compute_hash_sequence(sighash: Sighash, inputs: &[UnsignedTransactionInput]) -> H256 {
	match sighash.base {
		SighashBase::All if !sighash.anyone_can_pay => {
			let mut stream = Stream::default();
			for input in inputs {
				stream.append(&input.sequence);
			}
			dhash256(&stream.out())
		},
		_ => 0u8.into(),
	}
}

fn compute_hash_outputs(sighash: Sighash, input_index: usize, outputs: &[TransactionOutput]) -> H256 {
	match sighash.base {
		SighashBase::All => {
			let mut stream = Stream::default();
			for output in outputs {
				stream.append(output);
			}
			dhash256(&stream.out())
		},
		SighashBase::Single if input_index < outputs.len() => {
			let mut stream = Stream::default();
			stream.append(&outputs[input_index]);
			dhash256(&stream.out())
		},
		_ => 0u8.into(),
	}
}

fn blake_2b_256_personal(personal: &[u8]) -> Blake2bState {
	Blake2b::new()
		.hash_length(32)
		.personal(personal)
		.to_state()
}

#[cfg(test)]
mod tests {
	use bytes::Bytes;
	use hash::H256;
	use keys::{KeyPair, Private, Address};
	use chain::{OutPoint, TransactionOutput, Transaction};
	use script::Script;
	use super::{Sighash, UnsignedTransactionInput, TransactionInputSigner, SighashBase, SignatureVersion, blake_2b_256_personal};

	// http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
	// https://blockchain.info/rawtx/81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48
	// https://blockchain.info/rawtx/3f285f083de7c0acabd9f106a43ec42687ab0bebe2e6f0d529db696794540fea
	#[test]
	fn test_signature_hash_simple() {
		let private: Private = "5HusYj2b2x4nroApgfvaSfKYZhRbKFH41bVyPooymbC6KfgSXdD".into();
		let previous_tx_hash = H256::from_reversed_str("81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48");
		let previous_output_index = 0;
		let to: Address = "1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa".into();
		let previous_output = "76a914df3bd30160e6c6145baaf2c88a8844c13a00d1d588ac".into();
		let current_output: Bytes = "76a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac".into();
		let value = 91234;
		let expected_signature_hash = "5fda68729a6312e17e641e9a49fac2a4a6a680126610af573caab270d232f850".into();

		// this is irrelevant
		assert_eq!(&current_output[3..23], &*to.hash);

		let unsigned_input = UnsignedTransactionInput {
			sequence: 0xffff_ffff,
			previous_output: OutPoint {
				index: previous_output_index,
				hash: previous_tx_hash,
			},
		};

		let output = TransactionOutput {
			value,
			script_pubkey: current_output,
		};

		let input_signer = TransactionInputSigner {
			version: 1,
			overwintered: false,
			version_group_id: 0,
			expiry_height: 0,
			value_balance: 0,
			lock_time: 0,
			inputs: vec![unsigned_input],
			outputs: vec![output],
			join_splits: vec![],
			shielded_spends: vec![],
			shielded_outputs: vec![],
		};

		let hash = input_signer.signature_hash(0, 0, &previous_output, SignatureVersion::Base, SighashBase::All.into());
		assert_eq!(hash, expected_signature_hash);
	}

	fn run_test_sighash(
		tx: &'static str,
		script: &'static str,
		input_index: usize,
		hash_type: i32,
		result: &'static str
	) {
		let tx: Transaction = tx.into();
		let signer: TransactionInputSigner = tx.into();
		let script: Script = script.into();
		let expected = H256::from_reversed_str(result);

		let sighash = Sighash::from_u32(SignatureVersion::Base, hash_type as u32);
		let hash = signer.signature_hash_original(input_index, &script, hash_type as u32, sighash);
		assert_eq!(expected, hash);
	}

	#[test]
	fn test_sighash_forkid_from_u32() {
		assert!(!Sighash::is_defined(SignatureVersion::Base, 0xFFFFFF82));
		assert!(!Sighash::is_defined(SignatureVersion::Base, 0x00000182));
		assert!(!Sighash::is_defined(SignatureVersion::Base, 0x00000080));
		assert!( Sighash::is_defined(SignatureVersion::Base, 0x00000001));
		assert!( Sighash::is_defined(SignatureVersion::Base, 0x00000082));
		assert!( Sighash::is_defined(SignatureVersion::Base, 0x00000003));

		assert!(!Sighash::is_defined(SignatureVersion::ForkId, 0xFFFFFFC2));
		assert!(!Sighash::is_defined(SignatureVersion::ForkId, 0x000001C2));
		assert!( Sighash::is_defined(SignatureVersion::ForkId, 0x00000081));
		assert!( Sighash::is_defined(SignatureVersion::ForkId, 0x000000C2));
		assert!( Sighash::is_defined(SignatureVersion::ForkId, 0x00000043));
	}

	#[test]
	fn test_blake_2b_personal() {
		let mut state = blake_2b_256_personal(b"ZcashPrevoutHash");
		state.update(b"");
		assert_eq!("d53a633bbecf82fe9e9484d8a0e727c73bb9e68c96e72dec30144f6a84afa136", &state.finalize().to_hex());
	}

	// https://github.com/zcash/zips/blob/master/zip-0243.rst#test-vector-3
	#[test]
	fn test_sapling_sig_hash() {
		let tx: Transaction = "0400008085202f8901a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9010000006b483045022100a61e5d557568c2ddc1d9b03a7173c6ce7c996c4daecab007ac8f34bee01e6b9702204d38fdc0bcf2728a69fde78462a10fb45a9baa27873e6a5fc45fb5c76764202a01210365ffea3efa3908918a8b8627724af852fc9b86d7375b103ab0543cf418bcaa7ffeffffff02005a6202000000001976a9148132712c3ff19f3a151234616777420a6d7ef22688ac8b959800000000001976a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac29b0040048b004000000000000000000000000".into();
		let signer = TransactionInputSigner::from(tx);

		let sig_hash = Sighash::from_u32(SignatureVersion::Base, 1);
		let hash = signer.signature_hash_overwintered(
			0,
			50000000,
			&Script::from("1976a914507173527b4c3318a2aecd793bf1cfed705950cf88ac"),
			1,
			sig_hash
		);

		assert_eq!(H256::from("f3148f80dfab5e573d5edfe7a850f5fd39234f80b5429d3a57edcc11e34c585b"), hash.unwrap());
	}
}
