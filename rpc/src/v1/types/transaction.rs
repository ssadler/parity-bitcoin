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
	/// Number of rawconfirmations of this transaction, KMD specific
	#[serde(skip_serializing_if = "Option::is_none")]
	pub rawconfirmations: Option<u32>,
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
			rawconfirmations: None,
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
			rawconfirmations: None,
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

	// https://live.blockcypher.com/btc/tx/4ab5828480046524afa3fac5eb7f93f768c3eeeaeb5d4d6b6ff22801d3dc521e/
	#[test]
	fn test_btc_4ab5828480046524afa3fac5eb7f93f768c3eeeaeb5d4d6b6ff22801d3dc521e() {
		let tx_str = r#"{
			"txid":"4ab5828480046524afa3fac5eb7f93f768c3eeeaeb5d4d6b6ff22801d3dc521e",
			"hash":"89f9ae508f67ce79181f43cd4823e9899ef3116d658457c992b8411674f80c5c",
			"version":2,
			"size":3316,
			"vsize":3231,
			"weight":12922,
			"locktime":582070,
			"vin":[
				{
					"txid":"bc1cac1354e18195bbcb56e9b6212bc7ceb481ea46d18ed39493fbe028af370e",
					"vout":0,
					"scriptSig":{
						"asm":"3045022100a8fdfac02ecba2cfa25d74f76dcfba41791563d9aac29063dab7f9865009212002200a79c035e48f675c0527f33926ebdbb8dbae89c0a77f1e7ba229126b9fa97cc6[ALL] 02679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67",
						"hex":"483045022100a8fdfac02ecba2cfa25d74f76dcfba41791563d9aac29063dab7f9865009212002200a79c035e48f675c0527f33926ebdbb8dbae89c0a77f1e7ba229126b9fa97cc6012102679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67"
					},
					"sequence":4294967294
				},
				{
					"txid":"40bbaf2e6f209fd798c5d4dbbb53059b1b3fbe74d1bdd4defda3041a67d72122",
					"vout":0,
					"scriptSig":{
						"asm":"3045022100913d8dd7fc3e2114bec634886b0189cc400cba036c168228b9423f5526a9d361022008b3b02d3c0270911def718c1859aba34233e2e3c7327e2f5ac7d1a7fd65b9eb[ALL] 02679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67",
						"hex":"483045022100913d8dd7fc3e2114bec634886b0189cc400cba036c168228b9423f5526a9d361022008b3b02d3c0270911def718c1859aba34233e2e3c7327e2f5ac7d1a7fd65b9eb012102679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67"
					},
					"sequence":4294967294
				},
				{
					"txid":"f5abe9270190bb39a1b45ff8229913c7edc684e896df86033d2d0994e67fcb6b",
					"vout":0,
					"scriptSig":{
						"asm":"30440220103bac3e985912b388f48cc979f82821cb637f690fdd497efe4fceb86e00122f022026173b0e6a5e5eef7483b94f7589e78810eae8f8249ff7b03876f6ae24faa19b[ALL] 02679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67",
						"hex":"4730440220103bac3e985912b388f48cc979f82821cb637f690fdd497efe4fceb86e00122f022026173b0e6a5e5eef7483b94f7589e78810eae8f8249ff7b03876f6ae24faa19b012102679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67"
					},
					"sequence":4294967294
				},
				{
					"txid":"7cdd760d5d4ce952c9d25128a1f475b1a058cd71506cb7af956f2ab933b4d8a8",
					"vout":1,
					"scriptSig":{
						"asm":"30450221009f9188ef194366c3bb4cd520eb9d8a68c3f2fb6ea591f671a00039f05f67b9420220579874562e721bf8d07a34adc1ac587b6b48609100c43ba8e8bf180c86763adf[ALL] 02679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67",
						"hex":"4830450221009f9188ef194366c3bb4cd520eb9d8a68c3f2fb6ea591f671a00039f05f67b9420220579874562e721bf8d07a34adc1ac587b6b48609100c43ba8e8bf180c86763adf012102679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67"
					},
					"sequence":4294967294
				},
				{
					"txid":"73a7faa14c4e654f327d6be4f685f91234a6682b97bf0f5384e90bff861786ce",
					"vout":45,
					"scriptSig":{
						"asm":"",
						"hex":""
					},
					"txinwitness":[
						"3045022100b7b6368e45383b2da463ba56397a1966b94be5ef860ac95f1067e62a4531e75a022077bc58f3ea606219fe086f291d39b805faec10c848b525f4997f32979bab5aca01",
						"0253a13bae39c5604dc4e9634c10e87e33d0c2d1a618efc0726af5a4a4ea81f7ab"
					],
					"sequence":4294967294
				}
			],
			"vout":[
				{
					"value":0.0095,
					"n":0,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 66f8da41c6bb10975f565bde68b5df07003c59cb OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a91466f8da41c6bb10975f565bde68b5df07003c59cb88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1APU39UZbmpV3RB2EXQmKikKEgovLVoXzv"
						]
					}
				},
				{
					"value":0.56054866,
					"n":1,
					"scriptPubKey":{
						"asm":"OP_HASH160 46e14b4a4ff41785017080cd63aa5d17513e1854 OP_EQUAL",
						"hex":"a91446e14b4a4ff41785017080cd63aa5d17513e185487",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"389o7gRfw13GnRYg4yuhsATJ1iiJ8QFiBv"
						]
					}
				},
				{
					"value":1.9995,
					"n":2,
					"scriptPubKey":{
						"asm":"OP_HASH160 99bbebbdf7f2dc038b904103237765a77282b42b OP_EQUAL",
						"hex":"a91499bbebbdf7f2dc038b904103237765a77282b42b87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3FhtRs6hwos3uS62XhfkoP9PwnGFb9u9AT"
						]
					}
				},
				{
					"value":0.04788773,
					"n":3,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 c78ac0df6b8241075d66f7f986653604a2c6a6fc OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914c78ac0df6b8241075d66f7f986653604a2c6a6fc88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1KC5gvwy5SSarNgL7pVcEdrB7Gj1upeni9"
						]
					}
				},
				{
					"value":0.137,
					"n":4,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 79f1db0274de574d49f9fc794b349ef81529fb18 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a91479f1db0274de574d49f9fc794b349ef81529fb1888ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1C7nVdM4vYjSE23SnyEEbdEhzp3LXAwssr"
						]
					}
				},
				{
					"value":0.55,
					"n":5,
					"scriptPubKey":{
						"asm":"OP_HASH160 840f4d27071f400c5674b1a686235cb641ef34b8 OP_EQUAL",
						"hex":"a914840f4d27071f400c5674b1a686235cb641ef34b887",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3DjHT2Ks4bmJUQh8exeQYcGpXuHe4deVy8"
						]
					}
				},
				{
					"value":2.87351761,
					"n":6,
					"scriptPubKey":{
						"asm":"OP_HASH160 c2f1c77b4ab921d9a2b7a36b250e4ac5a29afe92 OP_EQUAL",
						"hex":"a914c2f1c77b4ab921d9a2b7a36b250e4ac5a29afe9287",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3KTnese7izLxXTSBe86fY7Cg2tHyApdsV5"
						]
					}
				},
				{
					"value":0.00343558,
					"n":7,
					"scriptPubKey":{
						"asm":"OP_HASH160 d58ee5f1a2bc153ce58145676a679d7b31a1a5ae OP_EQUAL",
						"hex":"a914d58ee5f1a2bc153ce58145676a679d7b31a1a5ae87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3MAD39R5NPANmrbgybN93jMsiTWd9sgB7A"
						]
					}
				},
				{
					"value":0.0345,
					"n":8,
					"scriptPubKey":{
						"asm":"OP_HASH160 a61b218139c3cd63abbfc6d221f28019d86837d6 OP_EQUAL",
						"hex":"a914a61b218139c3cd63abbfc6d221f28019d86837d687",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3GqJbUSzTZomr9Jjz9Rj4Kb3idbaA7FwvA"
						]
					}
				},
				{
					"value":0.04904543,
					"n":9,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 8aeadc4ab5fbdf6fba1396405388868395cf4f1b OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9148aeadc4ab5fbdf6fba1396405388868395cf4f1b88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1DfXbsJTxDuhtbBNz5njZdSZcGGBcerYPr"
						]
					}
				},
				{
					"value":0.0355541,
					"n":10,
					"scriptPubKey":{
						"asm":"OP_HASH160 f9e4dab5529cda97fe7d0ea9c6dfd828c9160c82 OP_EQUAL",
						"hex":"a914f9e4dab5529cda97fe7d0ea9c6dfd828c9160c8287",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3QULLPQRcFmQNCUyR66wSgJm8YAFBAq7Yg"
						]
					}
				},
				{
					"value":0.0085,
					"n":11,
					"scriptPubKey":{
						"asm":"OP_HASH160 551343b34a385e392562ead50b2588ee97307c37 OP_EQUAL",
						"hex":"a914551343b34a385e392562ead50b2588ee97307c3787",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"39SrSNFBzzMqZw1mAaLwotixK4oRQymBw2"
						]
					}
				},
				{
					"value":0.00991826,
					"n":12,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 633a3cd7a6ce04165619539a87ee5671d0537e4e OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914633a3cd7a6ce04165619539a87ee5671d0537e4e88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1A3ffR5ag9iJM8jrkYdF4ohx9E87RkLBGt"
						]
					}
				},
				{
					"value":0.02,
					"n":13,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 9f59e0163f592c3de094bc12ae338d8140c77c54 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9149f59e0163f592c3de094bc12ae338d8140c77c5488ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1FXa79ea27eR92vxSiVGnwtjRNjSMLkHzx"
						]
					}
				},
				{
					"value":0.2495,
					"n":14,
					"scriptPubKey":{
						"asm":"OP_HASH160 7b7f9a5fa10a45fc828d6a47ee6dbbbb2364cee2 OP_EQUAL",
						"hex":"a9147b7f9a5fa10a45fc828d6a47ee6dbbbb2364cee287",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3Cx1u9nW5Q585bBqkVz1ETjogZZB67d1KZ"
						]
					}
				},
				{
					"value":0.47461784,
					"n":15,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 221a6189701ce0874c4ba6fc0f91579f68f05895 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914221a6189701ce0874c4ba6fc0f91579f68f0589588ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"147KaWNp6T7BRBhWkwKaYobPXX7ydyuo3S"
						]
					}
				},
				{
					"value":0.029,
					"n":16,
					"scriptPubKey":{
						"asm":"OP_HASH160 1e5f0577643f2c17ecd5037034824e6b55f2f37f OP_EQUAL",
						"hex":"a9141e5f0577643f2c17ecd5037034824e6b55f2f37f87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"34Tc2Vqb4xC2UanZaDUBRWvGXrETVrSmiY"
						]
					}
				},
				{
					"value":0.0495,
					"n":17,
					"scriptPubKey":{
						"asm":"OP_HASH160 a70f43b2b0bded27e58ba7997e15936d86b5b4cd OP_EQUAL",
						"hex":"a914a70f43b2b0bded27e58ba7997e15936d86b5b4cd87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3GvM4AupUGYA5asAZWcR88qBbRepyd8VE4"
						]
					}
				},
				{
					"value":0.018,
					"n":18,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 2388eb0f84b2ec9d0e35ceda9019e389aee2243f OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9142388eb0f84b2ec9d0e35ceda9019e389aee2243f88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"14EtfxYvGBbCMDZGCW2sp7NB2qDwFZBB8L"
						]
					}
				},
				{
					"value":0.26611821,
					"n":19,
					"scriptPubKey":{
						"asm":"OP_HASH160 e0a8d9fe6832f56524ad51e40c6b34cc212dad4c OP_EQUAL",
						"hex":"a914e0a8d9fe6832f56524ad51e40c6b34cc212dad4c87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3NAuZXN4HCHnAubDpcXHJBQXJsShuER2Rs"
						]
					}
				},
				{
					"value":0.0295,
					"n":20,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 97dfc57e73ab8a3b9bda027b79a28bc2e9fc1931 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a91497dfc57e73ab8a3b9bda027b79a28bc2e9fc193188ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1Er36t3XCRycpJYZ4J4FH5jQFSu8K9VVyU"
						]
					}
				},
				{
					"value":0.0314192,
					"n":21,
					"scriptPubKey":{
						"asm":"OP_HASH160 be3d917f8b403b3e6b1cf900e29d686bddc8ce64 OP_EQUAL",
						"hex":"a914be3d917f8b403b3e6b1cf900e29d686bddc8ce6487",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3K2v4qRPzHD2J2VRwwXtUf5BpFtTB8HfRj"
						]
					}
				},
				{
					"value":0.00322,
					"n":22,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 f04d6dc750f0b2d3e648ab5afcc5b1c2cedb36f7 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914f04d6dc750f0b2d3e648ab5afcc5b1c2cedb36f788ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1NubvtWw5ZfcFaKNAgg199wpuvFcnP4BoD"
						]
					}
				},
				{
					"value":1.9995,
					"n":23,
					"scriptPubKey":{
						"asm":"OP_HASH160 e366f89679d01a89599c9794a35872e5f3cb3d29 OP_EQUAL",
						"hex":"a914e366f89679d01a89599c9794a35872e5f3cb3d2987",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3NRQfeFCWG3SqbK1ATfsZTVXS6ZD33i6Rr"
						]
					}
				},
				{
					"value":0.15653823,
					"n":24,
					"scriptPubKey":{
						"asm":"OP_HASH160 af5c84f9b702a4c60611b6272c6670c4e9614741 OP_EQUAL",
						"hex":"a914af5c84f9b702a4c60611b6272c6670c4e961474187",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3HgF1UdMmdgv1kmTc8BZVBhGMXmywny2qL"
						]
					}
				},
				{
					"value":0.026613,
					"n":25,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 2a80328a0c51051bf0e76eddbf5342178128096f OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9142a80328a0c51051bf0e76eddbf5342178128096f88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"14sixNSgFLN9zEmtcTtWAX7WsAWiwfiRir"
						]
					}
				},
				{
					"value":0.00707306,
					"n":26,
					"scriptPubKey":{
						"asm":"OP_HASH160 370628b7101a7ff461de2ab0a80a8703317c7811 OP_EQUAL",
						"hex":"a914370628b7101a7ff461de2ab0a80a8703317c781187",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"36hxU2pmkkU1TnHn7wdrDYSkYpdm7bQ5Co"
						]
					}
				},
				{
					"value":0.00880634,
					"n":27,
					"scriptPubKey":{
						"asm":"OP_HASH160 166c9a23dc39fbd57e58ff794069d083933cbc4c OP_EQUAL",
						"hex":"a914166c9a23dc39fbd57e58ff794069d083933cbc4c87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"33jata4jJH1a4tnpvSGzmNwfd4yQvKigEB"
						]
					}
				},
				{
					"value":1.657691,
					"n":28,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 6f4bceafb26023db265d9abc763ab2ccbd0213ae OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9146f4bceafb26023db265d9abc763ab2ccbd0213ae88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1B9UpUvgSNEqCJZPWGCTQj9Veg21jkvaGR"
						]
					}
				},
				{
					"value":0.00593755,
					"n":29,
					"scriptPubKey":{
						"asm":"OP_HASH160 fc8d98b2a4ea22f24e50261fd065afd99a8274a0 OP_EQUAL",
						"hex":"a914fc8d98b2a4ea22f24e50261fd065afd99a8274a087",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3QiPqBRvzvVQYpVAJtuwjNY4bsLX1CF6F5"
						]
					}
				},
				{
					"value":0.00308227,
					"n":30,
					"scriptPubKey":{
						"asm":"OP_HASH160 d1803af27bed138379b501e91f368d500b0b49e7 OP_EQUAL",
						"hex":"a914d1803af27bed138379b501e91f368d500b0b49e787",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3LnkmEMq99eLSSJRH3q1UickE2nKq5QH3C"
						]
					}
				},
				{
					"value":0.01524004,
					"n":31,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 e39546887c31afee7a067432902239f44e644067 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914e39546887c31afee7a067432902239f44e64406788ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1MkMDPeYqNL4UytZCQt9QQnWYiuDwdxqom"
						]
					}
				},
				{
					"value":0.00320799,
					"n":32,
					"scriptPubKey":{
						"asm":"OP_HASH160 62830624a7d20d6c86ceeeac5a3e7bdea6773927 OP_EQUAL",
						"hex":"a91462830624a7d20d6c86ceeeac5a3e7bdea677392787",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3Afu73rZdGhcuvZXLy868Q45ZfNmuwsJqC"
						]
					}
				},
				{
					"value":0.16818798,
					"n":33,
					"scriptPubKey":{
						"asm":"OP_HASH160 66b967a217fc91d260025d46c9c9eacb746b5f9d OP_EQUAL",
						"hex":"a91466b967a217fc91d260025d46c9c9eacb746b5f9d87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3B4AxGCwpojNPr6o2VFkqjSadnrMzDseqX"
						]
					}
				},
				{
					"value":0.02369191,
					"n":34,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 0f530ba894b185be3fd809e3992145f533e99536 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9140f530ba894b185be3fd809e3992145f533e9953688ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"12Q2cz1AcyMrcttBrVTyQLaJpWjoEjyQQ7"
						]
					}
				},
				{
					"value":0.001815,
					"n":35,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 df9443d2b7b497d1e7a950379f95be6ba9ea5628 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914df9443d2b7b497d1e7a950379f95be6ba9ea562888ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1MPBJQa8fCy8ieQicaFRVj965uTdi6Ax9z"
						]
					}
				},
				{
					"value":0.0015,
					"n":36,
					"scriptPubKey":{
						"asm":"OP_HASH160 ccfccb33575cfe97d39b6d0d0fad8f09cce2fe1a OP_EQUAL",
						"hex":"a914ccfccb33575cfe97d39b6d0d0fad8f09cce2fe1a87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3LNtc6TnCNaYQE2s5tm3CXsBxzS1GvSGLD"
						]
					}
				},
				{
					"value":0.23089985,
					"n":37,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 1fec4449c7ba080cf0c85eb87ab0c855f0c3959d OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9141fec4449c7ba080cf0c85eb87ab0c855f0c3959d88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"13unz3oktsAkNXiopiCGQV1X8E4z35CAKo"
						]
					}
				},
				{
					"value":0.04740793,
					"n":38,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 e5527898cbf243993a8b5b967120cc9a9a96d092 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914e5527898cbf243993a8b5b967120cc9a9a96d09288ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1MuYY7yugviXBcFY7i9ikFxjZ6hDVCkLHC"
						]
					}
				},
				{
					"value":0.00610039,
					"n":39,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 34f2329553b026ee1aa0c02dc0743ae0cf0062a7 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a91434f2329553b026ee1aa0c02dc0743ae0cf0062a788ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"15pxHADHoN45jPxjNyxxgE3Lw8cTEDEQNF"
						]
					}
				},
				{
					"value":0.11053671,
					"n":40,
					"scriptPubKey":{
						"asm":"OP_HASH160 9f2ad2868872be8c065cc9e2e20adf31e0cc44d5 OP_EQUAL",
						"hex":"a9149f2ad2868872be8c065cc9e2e20adf31e0cc44d587",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3GCcfPrgAAqpE9vLPeNcUHdUUFMkNh2jX7"
						]
					}
				},
				{
					"value":0.03754281,
					"n":41,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 50c4073088d9ecfa0791033d17a992e8b779f127 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a91450c4073088d9ecfa0791033d17a992e8b779f12788ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"18N3tckwus8UXADPJEYzmxBMZ5m8JbG9hU"
						]
					}
				},
				{
					"value":0.06452373,
					"n":42,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 2a27eb2171827358522c29a659aaea0f50b77579 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9142a27eb2171827358522c29a659aaea0f50b7757988ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"14quCeCm2ngSgU2HqZpcdDtCQDT8rsCFMm"
						]
					}
				},
				{
					"value":0.30842538,
					"n":43,
					"scriptPubKey":{
						"asm":"OP_HASH160 b8d0465ed10eac76fc86646ace6fa64b64cf357e OP_EQUAL",
						"hex":"a914b8d0465ed10eac76fc86646ace6fa64b64cf357e87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3JYDm2sy128oyvENgtXhE1YUfugo8Ym3qd"
						]
					}
				},
				{
					"value":0.0311296,
					"n":44,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 faecf0266209f760f5d5ec498f74a0ecca351a62 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914faecf0266209f760f5d5ec498f74a0ecca351a6288ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1Psmmhrdg3FSPdq57ApmkMyVpbrjTBWctt"
						]
					}
				},
				{
					"value":0.01411207,
					"n":45,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 2e30c6bb9396a24c4cdd56f20c74f7681d812d2b OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9142e30c6bb9396a24c4cdd56f20c74f7681d812d2b88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"15DEWrw7xzinkHAarjHo33cNrfyAvj87mg"
						]
					}
				},
				{
					"value":1.2005,
					"n":46,
					"scriptPubKey":{
						"asm":"OP_HASH160 69f3751d9b18b84c15ddb3d1a5349657585c61a7 OP_EQUAL",
						"hex":"a91469f3751d9b18b84c15ddb3d1a5349657585c61a787",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3BMEXQeB9Mr5hpgYdpnJLC1MQKHQ1NfYtM"
						]
					}
				},
				{
					"value":0.04702,
					"n":47,
					"scriptPubKey":{
						"asm":"OP_HASH160 65a11389f21ba13527b1c7629e999719f3241259 OP_EQUAL",
						"hex":"a91465a11389f21ba13527b1c7629e999719f324125987",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3AxP8hReJhzjozXfaY34gDeYbGQp6LSbJh"
						]
					}
				},
				{
					"value":0.9995,
					"n":48,
					"scriptPubKey":{
						"asm":"OP_HASH160 dd005ce549e1a57453dfcb8fef3522d83f069432 OP_EQUAL",
						"hex":"a914dd005ce549e1a57453dfcb8fef3522d83f06943287",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3MqZh9ips9W5ekHbzLaRxs8xZZTbJzTLwd"
						]
					}
				},
				{
					"value":0.0023939,
					"n":49,
					"scriptPubKey":{
						"asm":"OP_HASH160 3ab72a89b9706691ac4de3871e0f63efaeed880b OP_EQUAL",
						"hex":"a9143ab72a89b9706691ac4de3871e0f63efaeed880b87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"373UYH5oSBagXbohkbVDiT45bvM9ARVJiN"
						]
					}
				},
				{
					"value":0.15724136,
					"n":50,
					"scriptPubKey":{
						"asm":"OP_HASH160 b5022f11a874eea98b9f7e34c80d143f3b036789 OP_EQUAL",
						"hex":"a914b5022f11a874eea98b9f7e34c80d143f3b03678987",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3JC6r16n98UKgR5urase5cpYExr4eJtKBn"
						]
					}
				},
				{
					"value":1.4145,
					"n":51,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 87db0ef6cde94004fabec6bb7dfb675fd691b670 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a91487db0ef6cde94004fabec6bb7dfb675fd691b67088ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1DPLeM2Xzr9aW5qxSX1TaN8MYVwm2nFtgU"
						]
					}
				},
				{
					"value":0.04914942,
					"n":52,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 b827bbd222b251930da17d0a86ba0c5e19e3b27c OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914b827bbd222b251930da17d0a86ba0c5e19e3b27c88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1Hniw3NkC35q2N9J2ZKAgQtiCcJdo1HMom"
						]
					}
				},
				{
					"value":0.00990259,
					"n":53,
					"scriptPubKey":{
						"asm":"OP_HASH160 a0c63d441be7fd967ae9ef4af028092b446a43cb OP_EQUAL",
						"hex":"a914a0c63d441be7fd967ae9ef4af028092b446a43cb87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3GM7X9RgBkBL2TvbfmAzLfzVVxaEoBfSkY"
						]
					}
				},
				{
					"value":0.0015,
					"n":54,
					"scriptPubKey":{
						"asm":"OP_HASH160 cf8df73caf54d7a8e54b1247c51b2566ae128fc1 OP_EQUAL",
						"hex":"a914cf8df73caf54d7a8e54b1247c51b2566ae128fc187",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3LcTsCyUCfNmkoZ3Jvr1cnnq27A4AjAEqj"
						]
					}
				},
				{
					"value":0.0368,
					"n":55,
					"scriptPubKey":{
						"asm":"OP_HASH160 de796fa9d384058fcaab5b37c45803af4a739931 OP_EQUAL",
						"hex":"a914de796fa9d384058fcaab5b37c45803af4a73993187",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3MyMQfUWdbrcokj7A4AKFLZqDBMq3gsbjx"
						]
					}
				},
				{
					"value":0.13156522,
					"n":56,
					"scriptPubKey":{
						"asm":"OP_HASH160 04308a751559f8af188dc67a0dac238447e91416 OP_EQUAL",
						"hex":"a91404308a751559f8af188dc67a0dac238447e9141687",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"325AmzHDJ7XaTPiuudj8iBCnJiUsiZVpwM"
						]
					}
				},
				{
					"value":0.15517116,
					"n":57,
					"scriptPubKey":{
						"asm":"OP_HASH160 28c28ea4ab911d65d2568fe2a2ade143f1804b15 OP_EQUAL",
						"hex":"a91428c28ea4ab911d65d2568fe2a2ade143f1804b1587",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"35QY2HfqzscoKuMWR9GRqyELcRvguNYvdm"
						]
					}
				},
				{
					"value":0.02739512,
					"n":58,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 6e9f5b3aefdd8b079e2d77a682a6276640b5a779 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9146e9f5b3aefdd8b079e2d77a682a6276640b5a77988ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1B5vENoZK1VAEt5xfuQLZ5cApGoyjNspWB"
						]
					}
				},
				{
					"value":0.024003,
					"n":59,
					"scriptPubKey":{
						"asm":"OP_HASH160 185f5481e1c5ab6d9926207fbfd86d85d51d7bdc OP_EQUAL",
						"hex":"a914185f5481e1c5ab6d9926207fbfd86d85d51d7bdc87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"33utLoLCbf2WwccKyvpfRYdCncQUWGLBXK"
						]
					}
				},
				{
					"value":0.0995,
					"n":60,
					"scriptPubKey":{
						"asm":"OP_HASH160 f4761ebdd81b9b7e06a207a7a3d55332d016db3e OP_EQUAL",
						"hex":"a914f4761ebdd81b9b7e06a207a7a3d55332d016db3e87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3PycJUfHHBZmGehQUGbSTmD9Pdz2s61CtY"
						]
					}
				},
				{
					"value":0.33990654,
					"n":61,
					"scriptPubKey":{
						"asm":"OP_HASH160 9841711ba7b69aa821e5e4e78b07013789c0f1cf OP_EQUAL",
						"hex":"a9149841711ba7b69aa821e5e4e78b07013789c0f1cf87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3Fa52gPVesWsG66JZGqRyjY3Pu8jPYPSYA"
						]
					}
				},
				{
					"value":0.0095,
					"n":62,
					"scriptPubKey":{
						"asm":"OP_HASH160 54d1d3982910165eddd607622cf2aa2518cf5405 OP_EQUAL",
						"hex":"a91454d1d3982910165eddd607622cf2aa2518cf540587",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"39RW3fJJXZHaikDoJHWaHSGPYeVGuCSngD"
						]
					}
				},
				{
					"value":0.3791111,
					"n":63,
					"scriptPubKey":{
						"asm":"OP_HASH160 0ac0973483473fc700352483d72211ef74b7f77a OP_EQUAL",
						"hex":"a9140ac0973483473fc700352483d72211ef74b7f77a87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"32fsPtquwdaAJXaWUhAHfmJZUmSo4iUkBT"
						]
					}
				},
				{
					"value":0.0344179,
					"n":64,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 05da50df6705f7528c0de919a87a02ca74b635fc OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a91405da50df6705f7528c0de919a87a02ca74b635fc88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1XwupEjUAd8frdAFMSUaRATgXUhQM2u1y"
						]
					}
				},
				{
					"value":0.07881161,
					"n":65,
					"scriptPubKey":{
						"asm":"OP_HASH160 69f37547d53a98c778289f01066ab23b41680905 OP_EQUAL",
						"hex":"a91469f37547d53a98c778289f01066ab23b4168090587",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3BMEXTEn8uR2utJUEAQxEG2mare7KeZKxt"
						]
					}
				},
				{
					"value":0.00247,
					"n":66,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 2889396473e1709927065dc363210386afd99407 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9142889396473e1709927065dc363210386afd9940788ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"14hLRBGW8gRCX8vUPLeBzE6T8cQ2A8zNhz"
						]
					}
				},
				{
					"value":1.0,
					"n":67,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 c625e5f34f3b2617326adbae2e73a1bb0a6be371 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914c625e5f34f3b2617326adbae2e73a1bb0a6be37188ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1K4iCCWzLgawbAJbYbDG9v81z6n6y72KNq"
						]
					}
				},
				{
					"value":2.08197368,
					"n":68,
					"scriptPubKey":{
						"asm":"OP_HASH160 2d717f7aa62e57ba6eaceca169cd7f63a54d679b OP_EQUAL",
						"hex":"a9142d717f7aa62e57ba6eaceca169cd7f63a54d679b87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"35qJJ9pwEoEwdnbfnsN1L1jdFRiyZKBEAK"
						]
					}
				},
				{
					"value":0.01,
					"n":69,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 f4f89313803d610fa472a5849d2389ca6df3b900 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914f4f89313803d610fa472a5849d2389ca6df3b90088ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1PLHf4siiNLC61LXZswQUznuMUCWcRa3e7"
						]
					}
				},
				{
					"value":0.1995,
					"n":70,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 f63784063000439d873f12041e8799d0252db89e OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914f63784063000439d873f12041e8799d0252db89e88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"1PSsjVRff6QpkJfDLyi3jVAePTSh4t4WdL"
						]
					}
				},
				{
					"value":0.03005473,
					"n":71,
					"scriptPubKey":{
						"asm":"OP_HASH160 4b098f67e04f711baa310758169f129cbda6385f OP_EQUAL",
						"hex":"a9144b098f67e04f711baa310758169f129cbda6385f87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"38Xn4Bcu6A6u9ShKDRhLoVTG8tkmC9aMSp"
						]
					}
				},
				{
					"value":0.00190118,
					"n":72,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 494ee9282fb208d60a6765c11310a09524280137 OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a914494ee9282fb208d60a6765c11310a0952428013788ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"17gcrpZVCmvdH3o3H1orsRaQ7wDAyNQ39j"
						]
					}
				},
				{
					"value":0.03079627,
					"n":73,
					"scriptPubKey":{
						"asm":"OP_HASH160 69d1a07e7d5fcb62a322c8fb24ae76ebe3c88374 OP_EQUAL",
						"hex":"a91469d1a07e7d5fcb62a322c8fb24ae76ebe3c8837487",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3BLXzpY4LN5mSXpBfkoMsAABNLRqdQ8EKM"
						]
					}
				},
				{
					"value":0.0995,
					"n":74,
					"scriptPubKey":{
						"asm":"OP_HASH160 ffe19b0c48d473db72ca2d243476183b64b4f5d4 OP_EQUAL",
						"hex":"a914ffe19b0c48d473db72ca2d243476183b64b4f5d487",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3R1zVpJKgvxKXuqL2bYm9xS8gwLWAiL9uC"
						]
					}
				},
				{
					"value":0.01924206,
					"n":75,
					"scriptPubKey":{
						"asm":"OP_HASH160 816b46471ee03653597995a2dfa65f0f39eaaf0a OP_EQUAL",
						"hex":"a914816b46471ee03653597995a2dfa65f0f39eaaf0a87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3DVKbrWQbiLMuaaWRJzsHAfMMHiC1uj5f5"
						]
					}
				},
				{
					"value":0.01392176,
					"n":76,
					"scriptPubKey":{
						"asm":"OP_HASH160 88d8d90979c558004f248cfcf0ae6efa3061100f OP_EQUAL",
						"hex":"a91488d8d90979c558004f248cfcf0ae6efa3061100f87",
						"reqSigs":1,
						"type":"scripthash",
						"addresses":[
							"3EAbbUup1nBgprztckGgKJRyB7rCiSWBPP"
						]
					}
				},
				{
					"value":0.0134,
					"n":77,
					"scriptPubKey":{
						"asm":"OP_DUP OP_HASH160 1302fb1cdc92135634e69f69feba89070a1c1b2f OP_EQUALVERIFY OP_CHECKSIG",
						"hex":"76a9141302fb1cdc92135634e69f69feba89070a1c1b2f88ac",
						"reqSigs":1,
						"type":"pubkeyhash",
						"addresses":[
							"12jXQmCHi93zKH1HQgc5fsn11beeKdMwL7"
						]
					}
				}
			],
			"hex":"020000000001050e37af28e0fb9394d38ed146ea81b4cec72b21b6e956cbbb9581e15413ac1cbc000000006b483045022100a8fdfac02ecba2cfa25d74f76dcfba41791563d9aac29063dab7f9865009212002200a79c035e48f675c0527f33926ebdbb8dbae89c0a77f1e7ba229126b9fa97cc6012102679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67feffffff2221d7671a04a3fdded4bdd174be3f1b9b0553bbdbd4c598d79f206f2eafbb40000000006b483045022100913d8dd7fc3e2114bec634886b0189cc400cba036c168228b9423f5526a9d361022008b3b02d3c0270911def718c1859aba34233e2e3c7327e2f5ac7d1a7fd65b9eb012102679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67feffffff6bcb7fe694092d3d0386df96e884c6edc7139922f85fb4a139bb900127e9abf5000000006a4730440220103bac3e985912b388f48cc979f82821cb637f690fdd497efe4fceb86e00122f022026173b0e6a5e5eef7483b94f7589e78810eae8f8249ff7b03876f6ae24faa19b012102679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67feffffffa8d8b433b92a6f95afb76c5071cd58a0b175f4a12851d2c952e94c5d0d76dd7c010000006b4830450221009f9188ef194366c3bb4cd520eb9d8a68c3f2fb6ea591f671a00039f05f67b9420220579874562e721bf8d07a34adc1ac587b6b48609100c43ba8e8bf180c86763adf012102679a681d9b5bf5c672e0413997762664a17009038674b806bf27dd6b368d9b67feffffffce861786ff0be984530fbf972b68a63412f985f6e46b7d324f654e4ca1faa7732d00000000feffffff4ef07e0e00000000001976a91466f8da41c6bb10975f565bde68b5df07003c59cb88ac525457030000000017a91446e14b4a4ff41785017080cd63aa5d17513e185487b0feea0b0000000017a91499bbebbdf7f2dc038b904103237765a77282b42b8725124900000000001976a914c78ac0df6b8241075d66f7f986653604a2c6a6fc88aca00bd100000000001976a91479f1db0274de574d49f9fc794b349ef81529fb1888acc03b47030000000017a914840f4d27071f400c5674b1a686235cb641ef34b887d1a320110000000017a914c2f1c77b4ab921d9a2b7a36b250e4ac5a29afe9287063e05000000000017a914d58ee5f1a2bc153ce58145676a679d7b31a1a5ae8790a434000000000017a914a61b218139c3cd63abbfc6d221f28019d86837d6875fd64a00000000001976a9148aeadc4ab5fbdf6fba1396405388868395cf4f1b88ac524036000000000017a914f9e4dab5529cda97fe7d0ea9c6dfd828c9160c828750f80c000000000017a914551343b34a385e392562ead50b2588ee97307c378752220f00000000001976a914633a3cd7a6ce04165619539a87ee5671d0537e4e88ac80841e00000000001976a9149f59e0163f592c3de094bc12ae338d8140c77c5488acf0b47c010000000017a9147b7f9a5fa10a45fc828d6a47ee6dbbbb2364cee2879835d402000000001976a914221a6189701ce0874c4ba6fc0f91579f68f0589588ac20402c000000000017a9141e5f0577643f2c17ecd5037034824e6b55f2f37f87f0874b000000000017a914a70f43b2b0bded27e58ba7997e15936d86b5b4cd8740771b00000000001976a9142388eb0f84b2ec9d0e35ceda9019e389aee2243f88ac6d1096010000000017a914e0a8d9fe6832f56524ad51e40c6b34cc212dad4c8770032d00000000001976a91497dfc57e73ab8a3b9bda027b79a28bc2e9fc193188ac20f12f000000000017a914be3d917f8b403b3e6b1cf900e29d686bddc8ce6487d0e90400000000001976a914f04d6dc750f0b2d3e648ab5afcc5b1c2cedb36f788acb0feea0b0000000017a914e366f89679d01a89599c9794a35872e5f3cb3d2987bfdbee000000000017a914af5c84f9b702a4c60611b6272c6670c4e961474187b49b2800000000001976a9142a80328a0c51051bf0e76eddbf5342178128096f88aceaca0a000000000017a914370628b7101a7ff461de2ab0a80a8703317c781187fa6f0d000000000017a914166c9a23dc39fbd57e58ff794069d083933cbc4c878c6fe109000000001976a9146f4bceafb26023db265d9abc763ab2ccbd0213ae88ac5b0f09000000000017a914fc8d98b2a4ea22f24e50261fd065afd99a8274a08703b404000000000017a914d1803af27bed138379b501e91f368d500b0b49e78724411700000000001976a914e39546887c31afee7a067432902239f44e64406788ac1fe504000000000017a91462830624a7d20d6c86ceeeac5a3e7bdea6773927876ea200010000000017a91466b967a217fc91d260025d46c9c9eacb746b5f9d87a7262400000000001976a9140f530ba894b185be3fd809e3992145f533e9953688acfcc40200000000001976a914df9443d2b7b497d1e7a950379f95be6ba9ea562888acf04902000000000017a914ccfccb33575cfe97d39b6d0d0fad8f09cce2fe1a8741536001000000001976a9141fec4449c7ba080cf0c85eb87ab0c855f0c3959d88acb9564800000000001976a914e5527898cbf243993a8b5b967120cc9a9a96d09288acf74e0900000000001976a91434f2329553b026ee1aa0c02dc0743ae0cf0062a788ac67aaa8000000000017a9149f2ad2868872be8c065cc9e2e20adf31e0cc44d58729493900000000001976a91450c4073088d9ecfa0791033d17a992e8b779f12788ac95746200000000001976a9142a27eb2171827358522c29a659aaea0f50b7757988acaa9ed6010000000017a914b8d0465ed10eac76fc86646ace6fa64b64cf357e8700802f00000000001976a914faecf0266209f760f5d5ec498f74a0ecca351a6288ac87881500000000001976a9142e30c6bb9396a24c4cdd56f20c74f7681d812d2b88ac50d127070000000017a91469f3751d9b18b84c15ddb3d1a5349657585c61a78730bf47000000000017a91465a11389f21ba13527b1c7629e999719f324125987b01df5050000000017a914dd005ce549e1a57453dfcb8fef3522d83f069432871ea703000000000017a9143ab72a89b9706691ac4de3871e0f63efaeed880b8768eeef000000000017a914b5022f11a874eea98b9f7e34c80d143f3b03678987105b6e08000000001976a91487db0ef6cde94004fabec6bb7dfb675fd691b67088acfefe4a00000000001976a914b827bbd222b251930da17d0a86ba0c5e19e3b27c88ac331c0f000000000017a914a0c63d441be7fd967ae9ef4af028092b446a43cb87f04902000000000017a914cf8df73caf54d7a8e54b1247c51b2566ae128fc187002738000000000017a914de796fa9d384058fcaab5b37c45803af4a73993187aac0c8000000000017a91404308a751559f8af188dc67a0dac238447e9141687bcc5ec000000000017a91428c28ea4ab911d65d2568fe2a2ade143f1804b158738cd2900000000001976a9146e9f5b3aefdd8b079e2d77a682a6276640b5a77988ac2ca024000000000017a914185f5481e1c5ab6d9926207fbfd86d85d51d7bdc8730d397000000000017a914f4761ebdd81b9b7e06a207a7a3d55332d016db3e87fea706020000000017a9149841711ba7b69aa821e5e4e78b07013789c0f1cf87f07e0e000000000017a91454d1d3982910165eddd607622cf2aa2518cf540587467a42020000000017a9140ac0973483473fc700352483d72211ef74b7f77a877e843400000000001976a91405da50df6705f7528c0de919a87a02ca74b635fc88acc94178000000000017a91469f37547d53a98c778289f01066ab23b4168090587d8c40300000000001976a9142889396473e1709927065dc363210386afd9940788ac00e1f505000000001976a914c625e5f34f3b2617326adbae2e73a1bb0a6be37188acf8d6680c0000000017a9142d717f7aa62e57ba6eaceca169cd7f63a54d679b8740420f00000000001976a914f4f89313803d610fa472a5849d2389ca6df3b90088acb0693001000000001976a914f63784063000439d873f12041e8799d0252db89e88ac21dc2d000000000017a9144b098f67e04f711baa310758169f129cbda6385f87a6e60200000000001976a914494ee9282fb208d60a6765c11310a0952428013788accbfd2e000000000017a91469d1a07e7d5fcb62a322c8fb24ae76ebe3c883748730d397000000000017a914ffe19b0c48d473db72ca2d243476183b64b4f5d4876e5c1d000000000017a914816b46471ee03653597995a2dfa65f0f39eaaf0a87303e15000000000017a91488d8d90979c558004f248cfcf0ae6efa3061100f8760721400000000001976a9141302fb1cdc92135634e69f69feba89070a1c1b2f88ac0000000002483045022100b7b6368e45383b2da463ba56397a1966b94be5ef860ac95f1067e62a4531e75a022077bc58f3ea606219fe086f291d39b805faec10c848b525f4997f32979bab5aca01210253a13bae39c5604dc4e9634c10e87e33d0c2d1a618efc0726af5a4a4ea81f7abb6e10800",
			"blockhash":"0000000000000000000ae5f893bc9156bf24938ff6ee1d5a1555a6b7d82ce176",
			"confirmations":13533,
			"time":1561311885,
			"blocktime":1561311885
		}"#;

		let _tx: Transaction = serde_json::from_str(tx_str).unwrap();
	}

	fn test_kmd_raw_confirmations() {
		let json_str = r#"{
			"hex":"0400008085202f89010000000000000000000000000000000000000000000000000000000000000000ffffffff0603aed11a0101ffffffff0188b6e11100000000232103fff24efd5648870a23badf46e26510e96d9e79ce281b27cfe963993039dd1351ac3b5e4e5e000000000000000000000000000000",
			"txid":"1b1a413c7205dc07f23ef60ca04d29ca33d72e9f6c473ddd8b02aaac53fb8e7a",
			"overwintered":true,
			"version":4,
			"last_notarized_height":1757600,
			"versiongroupid":"892f2085",
			"locktime":1582194235,
			"expiryheight":0,
			"vin":[
				{
					"coinbase":"03aed11a0101",
					"sequence":4294967295
				}
			],
			"vout":[
				{
					"value":3.00005,
					"interest":0.0,
					"valueSat":300005000,
					"n":0,
					"scriptPubKey":{
					"asm":"03fff24efd5648870a23badf46e26510e96d9e79ce281b27cfe963993039dd1351 OP_CHECKSIG",
					"hex":"2103fff24efd5648870a23badf46e26510e96d9e79ce281b27cfe963993039dd1351ac",
					"reqSigs":1,
					"type":"pubkey",
					"addresses":[
						"RTPBi5hpdSUARnh9gGahv6tr4ppHDwAkxD"
					]
				}
				}
			],
			"vjoinsplit":[

			],
			"valueBalance":0.0,
			"vShieldedSpend":[

			],
			"vShieldedOutput":[

			],
			"blockhash":"059ad2e93f92de1ff80432ba1227c83739ed76bc78f41630dd6a773dc6595dc8",
			"height":1757614,
			"confirmations":1,
			"rawconfirmations":8,
			"time":1582194235,
			"blocktime":1582194235
		}"#;

		let tx: Transaction = serde_json::from_str(json_str).unwrap();
		assert_eq!(tx.rawconfirmations, Some(8));
	}
}
