use std::fmt;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::ser::SerializeMap;
use keys::Address;
use v1::types;
use super::bytes::Bytes;
use super::hash::H256;
use super::script::ScriptType;

/// Hex-encoded transaction
pub type RawTransaction = Bytes;

/// Transaction input
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TransactionInput {
	/// Previous transaction id
	pub txid: H256,
	/// Previous transaction output index
	pub vout: u32,
	/// Sequence number
	pub sequence: Option<u32>,
}

/// Transaction output of form "address": amount
#[derive(Debug, PartialEq)]
pub struct TransactionOutputWithAddress {
	/// Receiver' address
	pub address: Address,
	/// Amount in BTC
	pub amount: f64,
}

/// Trasaction output of form "data": serialized(output script data)
#[derive(Debug, PartialEq)]
pub struct TransactionOutputWithScriptData {
	/// Serialized script data
	pub script_data: Bytes,
}

/// Transaction output
#[derive(Debug, PartialEq)]
pub enum TransactionOutput {
	/// Of form address: amount
	Address(TransactionOutputWithAddress),
	/// Of form data: script_data_bytes
	ScriptData(TransactionOutputWithScriptData),
}

/// Transaction outputs, which serializes/deserializes as KV-map
#[derive(Debug, PartialEq)]
pub struct TransactionOutputs {
	/// Transaction outputs
	pub outputs: Vec<TransactionOutput>,
}

/// Transaction input script
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransactionInputScript {
	/// Script code
	pub asm: String,
	/// Script hex
	pub hex: Bytes,
}

/// Transaction output script
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransactionOutputScript {
	/// Script code
	pub asm: String,
	/// Script hex
	pub hex: Bytes,
	/// Number of required signatures
	#[serde(rename = "reqSigs")]
	#[serde(default)]
	pub req_sigs: u32,
	/// Type of script
	#[serde(rename = "type")]
	pub script_type: ScriptType,
	/// Array of bitcoin addresses
	#[serde(default)]
	pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum TransactionInputEnum {
	Signed(SignedTransactionInput),
	Coinbase(CoinbaseTransactionInput),
}

/// Signed transaction input
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignedTransactionInput {
	/// Previous transaction id
	pub txid: H256,
	/// Previous transaction output index
	pub vout: u32,
	/// Input script
	#[serde(rename = "scriptSig")]
	pub script_sig: TransactionInputScript,
	/// Sequence number
	pub sequence: u32,
	/// Hex-encoded witness data (if any)
	pub txinwitness: Option<Vec<String>>,
}

/// Coinbase transaction input
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CoinbaseTransactionInput {
	/// coinbase
	pub coinbase: Bytes,
	/// Sequence number
	pub sequence: u32,
}

/// Signed transaction output
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignedTransactionOutput {
	/// Output value in BTC
	pub value: f64,
	/// Output index
	pub n: u32,
	/// Output script
	#[serde(rename = "scriptPubKey")]
	pub script: TransactionOutputScript,
}

/// Transaction
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
	/// Raw transaction
	pub hex: RawTransaction,
	/// The transaction id (same as provided)
	pub txid: H256,
	/// The transaction hash (differs from txid for witness transactions)
	pub hash: Option<H256>,
	/// The serialized transaction size
	pub size: Option<usize>,
	/// The virtual transaction size (differs from size for witness transactions)
	pub vsize: Option<usize>,
	/// The version
	pub version: i32,
	/// The lock time
	pub locktime: i32,
	/// Transaction inputs
	pub vin: Vec<TransactionInputEnum>,
	/// Transaction outputs
	pub vout: Vec<SignedTransactionOutput>,
	/// Hash of the block this transaction is included in
	#[serde(default)]
	pub blockhash: H256,
	/// Number of confirmations of this transaction
	#[serde(default)]
	pub confirmations: u32,
	/// The transaction time in seconds since epoch (Jan 1 1970 GMT)
	#[serde(default)]
	pub time: u32,
	/// The block time in seconds since epoch (Jan 1 1970 GMT)
	#[serde(default)]
	pub blocktime: u32,
	/// The block height transaction mined in
	#[serde(default)]
	pub height: u64,
}

/// Return value of `getrawtransaction` method
#[derive(Debug, PartialEq)]
pub enum GetRawTransactionResponse {
	/// Return value when asking for raw transaction
	Raw(RawTransaction),
	/// Return value when asking for verbose transaction
	Verbose(Transaction),
}

impl Serialize for GetRawTransactionResponse {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
		match *self {
			GetRawTransactionResponse::Raw(ref raw_transaction) => raw_transaction.serialize(serializer),
			GetRawTransactionResponse::Verbose(ref verbose_transaction) => verbose_transaction.serialize(serializer),
		}
	}
}

impl TransactionOutputs {
	pub fn len(&self) -> usize {
		self.outputs.len()
	}
}

impl Serialize for TransactionOutputs {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
		let mut state = serializer.serialize_map(Some(self.len()))?;
		for output in &self.outputs {
			match output {
				&TransactionOutput::Address(ref address_output) => {
					state.serialize_entry(&address_output.address.to_string(), &address_output.amount)?;
				},
				&TransactionOutput::ScriptData(ref script_output) => {
					state.serialize_entry("data", &script_output.script_data)?;
				},
			}
		}
		state.end()
	}
}

impl<'a> Deserialize<'a> for TransactionOutputs {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'a> {
		use serde::de::{Visitor, MapAccess};

		struct TransactionOutputsVisitor;

		impl<'b> Visitor<'b> for TransactionOutputsVisitor {
			type Value = TransactionOutputs;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("a transaction output object")
			}

			fn visit_map<V>(self, mut visitor: V) -> Result<TransactionOutputs, V::Error> where V: MapAccess<'b> {
				let mut outputs: Vec<TransactionOutput> = Vec::with_capacity(visitor.size_hint().unwrap_or(0));

				while let Some(key) = try!(visitor.next_key::<String>()) {
					if &key == "data" {
						let value: Bytes = try!(visitor.next_value());
						outputs.push(TransactionOutput::ScriptData(TransactionOutputWithScriptData {
							script_data: value,
						}));
					} else {
						let address = types::address::AddressVisitor::default().visit_str(&key)?;
						let amount: f64 = try!(visitor.next_value());
						outputs.push(TransactionOutput::Address(TransactionOutputWithAddress {
							address: address,
							amount: amount,
						}));
					}
				}

				Ok(TransactionOutputs {
					outputs: outputs,
				})
			}
		}

		deserializer.deserialize_identifier(TransactionOutputsVisitor)
	}
}

#[cfg(test)]
mod tests {
	use serde_json;
	use super::super::bytes::Bytes;
	use super::super::hash::H256;
	use super::super::script::ScriptType;
	use super::*;

	#[test]
	fn transaction_input_serialize() {
		let txinput = TransactionInput {
			txid: H256::from(7),
			vout: 33,
			sequence: Some(88),
		};
		assert_eq!(serde_json::to_string(&txinput).unwrap(), r#"{"txid":"0700000000000000000000000000000000000000000000000000000000000000","vout":33,"sequence":88}"#);
	}

	#[test]
	fn transaction_input_deserialize() {
		let txinput = TransactionInput {
			txid: H256::from(7),
			vout: 33,
			sequence: Some(88),
		};

		assert_eq!(
			serde_json::from_str::<TransactionInput>(r#"{"txid":"0700000000000000000000000000000000000000000000000000000000000000","vout":33,"sequence":88}"#).unwrap(),
			txinput);
	}

	#[test]
	fn transaction_outputs_serialize() {
		let txout = TransactionOutputs {
			outputs: vec![
				TransactionOutput::Address(TransactionOutputWithAddress {
					address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(),
					amount: 123.45,
				}),
				TransactionOutput::Address(TransactionOutputWithAddress {
					address: "1H5m1XzvHsjWX3wwU781ubctznEpNACrNC".into(),
					amount: 67.89,
				}),
				TransactionOutput::ScriptData(TransactionOutputWithScriptData {
					script_data: Bytes::new(vec![1, 2, 3, 4]),
				}),
				TransactionOutput::ScriptData(TransactionOutputWithScriptData {
					script_data: Bytes::new(vec![5, 6, 7, 8]),
				}),
			]
		};
		assert_eq!(serde_json::to_string(&txout).unwrap(), r#"{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa":123.45,"1H5m1XzvHsjWX3wwU781ubctznEpNACrNC":67.89,"data":"01020304","data":"05060708"}"#);
	}

	#[test]
	fn transaction_outputs_deserialize() {
		let txout = TransactionOutputs {
			outputs: vec![
				TransactionOutput::Address(TransactionOutputWithAddress {
					address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(),
					amount: 123.45,
				}),
				TransactionOutput::Address(TransactionOutputWithAddress {
					address: "1H5m1XzvHsjWX3wwU781ubctznEpNACrNC".into(),
					amount: 67.89,
				}),
				TransactionOutput::ScriptData(TransactionOutputWithScriptData {
					script_data: Bytes::new(vec![1, 2, 3, 4]),
				}),
				TransactionOutput::ScriptData(TransactionOutputWithScriptData {
					script_data: Bytes::new(vec![5, 6, 7, 8]),
				}),
			]
		};
		assert_eq!(
			serde_json::from_str::<TransactionOutputs>(r#"{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa":123.45,"1H5m1XzvHsjWX3wwU781ubctznEpNACrNC":67.89,"data":"01020304","data":"05060708"}"#).unwrap(),
			txout);
	}

	#[test]
	fn transaction_input_script_serialize() {
		let txin = TransactionInputScript {
			asm: "Hello, world!!!".to_owned(),
			hex: Bytes::new(vec![1, 2, 3, 4]),
		};
		assert_eq!(serde_json::to_string(&txin).unwrap(), r#"{"asm":"Hello, world!!!","hex":"01020304"}"#);
	}

	#[test]
	fn transaction_input_script_deserialize() {
		let txin = TransactionInputScript {
			asm: "Hello, world!!!".to_owned(),
			hex: Bytes::new(vec![1, 2, 3, 4]),
		};
		assert_eq!(
			serde_json::from_str::<TransactionInputScript>(r#"{"asm":"Hello, world!!!","hex":"01020304"}"#).unwrap(),
			txin);
	}

	#[test]
	fn transaction_output_script_serialize() {
		let txout = TransactionOutputScript {
			asm: "Hello, world!!!".to_owned(),
			hex: Bytes::new(vec![1, 2, 3, 4]),
			req_sigs: 777,
			script_type: ScriptType::Multisig,
			addresses: vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(), "1H5m1XzvHsjWX3wwU781ubctznEpNACrNC".into()],
		};
		assert_eq!(serde_json::to_string(&txout).unwrap(), r#"{"asm":"Hello, world!!!","hex":"01020304","reqSigs":777,"type":"multisig","addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","1H5m1XzvHsjWX3wwU781ubctznEpNACrNC"]}"#);
	}

	#[test]
	fn transaction_output_script_deserialize() {
		let txout = TransactionOutputScript {
			asm: "Hello, world!!!".to_owned(),
			hex: Bytes::new(vec![1, 2, 3, 4]),
			req_sigs: 777,
			script_type: ScriptType::Multisig,
			addresses: vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(), "1H5m1XzvHsjWX3wwU781ubctznEpNACrNC".into()],
		};

		assert_eq!(
			serde_json::from_str::<TransactionOutputScript>(r#"{"asm":"Hello, world!!!","hex":"01020304","reqSigs":777,"type":"multisig","addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","1H5m1XzvHsjWX3wwU781ubctznEpNACrNC"]}"#).unwrap(),
			txout);
	}

	#[test]
	fn signed_transaction_input_serialize() {
		let txin = SignedTransactionInput {
			txid: H256::from(77),
			vout: 13,
			script_sig: TransactionInputScript {
				asm: "Hello, world!!!".to_owned(),
				hex: Bytes::new(vec![1, 2, 3, 4]),
			},
			sequence: 123,
			txinwitness: None,
		};
		assert_eq!(serde_json::to_string(&txin).unwrap(), r#"{"txid":"4d00000000000000000000000000000000000000000000000000000000000000","vout":13,"scriptSig":{"asm":"Hello, world!!!","hex":"01020304"},"sequence":123,"txinwitness":null}"#);
	}

	#[test]
	fn signed_transaction_input_deserialize() {
		let txin = SignedTransactionInput {
			txid: H256::from(77),
			vout: 13,
			script_sig: TransactionInputScript {
				asm: "Hello, world!!!".to_owned(),
				hex: Bytes::new(vec![1, 2, 3, 4]),
			},
			sequence: 123,
			txinwitness: Some(vec![]),
		};
		assert_eq!(
			serde_json::from_str::<SignedTransactionInput>(r#"{"txid":"4d00000000000000000000000000000000000000000000000000000000000000","vout":13,"scriptSig":{"asm":"Hello, world!!!","hex":"01020304"},"sequence":123,"txinwitness":[]}"#).unwrap(),
			txin);
	}

	#[test]
	fn signed_transaction_output_serialize() {
		let txout = SignedTransactionOutput {
			value: 777.79,
			n: 12,
			script: TransactionOutputScript {
				asm: "Hello, world!!!".to_owned(),
				hex: Bytes::new(vec![1, 2, 3, 4]),
				req_sigs: 777,
				script_type: ScriptType::Multisig,
				addresses: vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(), "1H5m1XzvHsjWX3wwU781ubctznEpNACrNC".into()],
			},
		};
		assert_eq!(serde_json::to_string(&txout).unwrap(), r#"{"value":777.79,"n":12,"scriptPubKey":{"asm":"Hello, world!!!","hex":"01020304","reqSigs":777,"type":"multisig","addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","1H5m1XzvHsjWX3wwU781ubctznEpNACrNC"]}}"#);
	}

	#[test]
	fn signed_transaction_output_deserialize() {
		let txout = SignedTransactionOutput {
			value: 777.79,
			n: 12,
			script: TransactionOutputScript {
				asm: "Hello, world!!!".to_owned(),
				hex: Bytes::new(vec![1, 2, 3, 4]),
				req_sigs: 777,
				script_type: ScriptType::Multisig,
				addresses: vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(), "1H5m1XzvHsjWX3wwU781ubctznEpNACrNC".into()],
			},
		};
		assert_eq!(
			serde_json::from_str::<SignedTransactionOutput>(r#"{"value":777.79,"n":12,"scriptPubKey":{"asm":"Hello, world!!!","hex":"01020304","reqSigs":777,"type":"multisig","addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","1H5m1XzvHsjWX3wwU781ubctznEpNACrNC"]}}"#).unwrap(),
			txout);
	}

	#[test]
	fn transaction_serialize() {
		let tx = Transaction {
			hex: "DEADBEEF".into(),
			txid: H256::from(4),
			hash: Some(H256::from(5)),
			size: Some(33),
			vsize: Some(44),
			version: 55,
			locktime: 66,
			vin: vec![],
			vout: vec![],
			blockhash: H256::from(6),
			confirmations: 77,
			time: 88,
			blocktime: 99,
			height: 0,
		};
		assert_eq!(serde_json::to_string(&tx).unwrap(), r#"{"hex":"deadbeef","txid":"0400000000000000000000000000000000000000000000000000000000000000","hash":"0500000000000000000000000000000000000000000000000000000000000000","size":33,"vsize":44,"version":55,"locktime":66,"vin":[],"vout":[],"blockhash":"0600000000000000000000000000000000000000000000000000000000000000","confirmations":77,"time":88,"blocktime":99,"height":0}"#);
	}

	#[test]
	fn transaction_deserialize() {
		let tx = Transaction {
			hex: "DEADBEEF".into(),
			txid: H256::from(4),
			hash: Some(H256::from(5)),
			size: Some(33),
			vsize: Some(44),
			version: 55,
			locktime: 66,
			vin: vec![],
			vout: vec![],
			blockhash: H256::from(6),
			confirmations: 77,
			time: 88,
			blocktime: 99,
			height: 0,
		};
		assert_eq!(
			serde_json::from_str::<Transaction>(r#"{"hex":"deadbeef","txid":"0400000000000000000000000000000000000000000000000000000000000000","hash":"0500000000000000000000000000000000000000000000000000000000000000","size":33,"vsize":44,"version":55,"locktime":66,"vin":[],"vout":[],"blockhash":"0600000000000000000000000000000000000000000000000000000000000000","confirmations":77,"time":88,"blocktime":99}"#).unwrap(),
			tx);
	}

	#[test]
	// https://kmdexplorer.io/tx/88893f05764f5a781f2e555a5b492c064f2269a4a44c51afdbe98fab54361bb5
	fn test_kmd_json_transaction_parse_fail() {
		let tx_str = r#"{
			"hex":"0100000001ebca38fa14b1ec029c3e08a2e87940c1f796b1588674b4c386f09626ee702576010000006a4730440220070963b9460d9bafe7865563574594fc3f823e5cdf7c49a5642dade76502547f022023fd90d41e34e514237f4b5967f83c9af27673d6de2eae3d88079a988fa5be3e012103668e3368c9fb67d8fc808a5fe74d5a8d21b6eed726838122d5f7716fb3328998ffffffff03e87006060000000017a914fef59ae800bb89050d25f67be432b231097e1849878758c100000000001976a91473122bcec852f394e51496e39fca5111c3d7ae5688ac00000000000000000a6a08303764643135633400000000",
			"txid":"88893f05764f5a781f2e555a5b492c064f2269a4a44c51afdbe98fab54361bb5",
			"overwintered":false,
			"version":1,
			"last_notarized_height":1415230,
			"locktime":0,
			"vin":[
				{
					"txid":"762570ee2696f086c3b4748658b196f7c14079e8a2083e9c02ecb114fa38caeb",
					"vout":1,
					"address":"RKmdZ8QA7XbJ4JGUAvtHtWEogKxfgaQuqv",
					"scriptSig":{
					"asm":"30440220070963b9460d9bafe7865563574594fc3f823e5cdf7c49a5642dade76502547f022023fd90d41e34e514237f4b5967f83c9af27673d6de2eae3d88079a988fa5be3e[ALL] 03668e3368c9fb67d8fc808a5fe74d5a8d21b6eed726838122d5f7716fb3328998",
					"hex":"4730440220070963b9460d9bafe7865563574594fc3f823e5cdf7c49a5642dade76502547f022023fd90d41e34e514237f4b5967f83c9af27673d6de2eae3d88079a988fa5be3e012103668e3368c9fb67d8fc808a5fe74d5a8d21b6eed726838122d5f7716fb3328998"
				},
					"value":1.13766527,
					"valueSat":113766527,
					"sequence":4294967295
				}
			],
			"vout":[
				{
					"value":1.01085416,
					"valueSat":101085416,
					"n":0,
					"scriptPubKey":{
					"asm":"OP_HASH160 fef59ae800bb89050d25f67be432b231097e1849 OP_EQUAL",
					"hex":"a914fef59ae800bb89050d25f67be432b231097e184987",
					"reqSigs":1,
					"type":"scripthash",
					"addresses":[
						"bbyNYu11Qs3PowiPr1Su4ozQk7hsVmv821"
					]
				}
				},
				{
					"value":0.12671111,
					"valueSat":12671111,
					"n":1,
					"scriptPubKey":{
					"asm":"OP_DUP OP_HASH160 73122bcec852f394e51496e39fca5111c3d7ae56 OP_EQUALVERIFY OP_CHECKSIG",
					"hex":"76a91473122bcec852f394e51496e39fca5111c3d7ae5688ac",
					"reqSigs":1,
					"type":"pubkeyhash",
					"addresses":[
						"RKmdZ8QA7XbJ4JGUAvtHtWEogKxfgaQuqv"
					]
				}
				},
				{
					"value":0.0,
					"valueSat":0,
					"n":2,
					"scriptPubKey":{
					"asm":"OP_RETURN 3037646431356334",
					"hex":"6a083037646431356334",
					"type":"nulldata"
				}
				}
			],
			"vjoinsplit":[

			],
			"blockhash":"086c0807a67d8411743f7eaf0a687721eadaa6c8190dfd36f4de9d939c796e82",
			"height":865648,
			"confirmations":549608,
			"rawconfirmations":549608,
			"time":1528215344,
			"blocktime":1528215344
		}"#;

		let _tx: Transaction = serde_json::from_str(tx_str).unwrap();
	}

	#[test]
	fn test_kmd_coinbase_transaction_parse() {
		let tx_str = r#"{
			"hex": "0400008085202f89010000000000000000000000000000000000000000000000000000000000000000ffffffff06030a4b020101ffffffff0178e600000000000023210388392e0885e449ea9745ce7ad2631fdca5288f9d790cee1b696e67c75ad54a2dac1ad92f5d000000000000000000000000000000",
			"txid": "6f173d96987e765b0fd8a47fdb976e8edc767207f3c0028e17a224380d9a14a3",
			"overwintered": true,
			"version": 4,
			"versiongroupid": "892f2085",
			"locktime": 1563416858,
			"expiryheight": 0,
			"vin": [
				{
				  "coinbase": "030a4b020101",
				  "sequence": 4294967295
				}
			],
			"vout": [
				{
				  "value": 0.00059000,
				  "valueSat": 59000,
				  "n": 0,
				  "scriptPubKey": {
					"asm": "0388392e0885e449ea9745ce7ad2631fdca5288f9d790cee1b696e67c75ad54a2d OP_CHECKSIG",
					"hex": "210388392e0885e449ea9745ce7ad2631fdca5288f9d790cee1b696e67c75ad54a2dac",
					"reqSigs": 1,
					"type": "pubkey",
					"addresses": [
					  "RM5wffThEVKQdG98uLa2gc8Nk4CzX9Fq4q"
					]
				  }
				}
			],
			"vjoinsplit": [
			],
			"valueBalance": 0.00000000,
			"vShieldedSpend": [
			],
			"vShieldedOutput": [
			],
			"blockhash": "04b08f77065a70c86fd47e92cbff2cd73b1768428da7c8e328d903d76e8dc37e",
			"height": 150282,
			"confirmations": 1,
			"rawconfirmations": 6,
			"time": 1563416858,
			"blocktime": 1563416858
		}"#;

		let _tx: Transaction = serde_json::from_str(tx_str).unwrap();
	}
}
