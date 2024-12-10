use crate::tx::{Fees, Generator, GeneratorSettings, PaymentDestination, PaymentOutput, PaymentOutputs};
use crate::utils::kaspa_to_sompi;
use kaspa_addresses::Address;
use kaspa_consensus_client::{TransactionOutpoint, UtxoEntry, UtxoEntryReference};
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_consensus_core::tx::ScriptVec;
use kaspa_hashes::Hash;
use kaspa_utils::hex::FromHex;
use serde_json::Value;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use itertools::Itertools;
use workflow_core::prelude::Abortable;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpEndIf, OpFalse, OpIf};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::standard;
use kaspa_wallet_keys::prelude::PrivateKey;

const SENDER_ADDR: &str = "kaspatest:qzzzvv57j68mcv3rsd2reshhtv4rcw4xc8snhenp2k4wu4l30jfjxlgfr8qcz";
const RECEIVER_ADDR: &str = "kaspatest:qrjcg7hsgjapumpn8egyu6544qzdqs2lssas4nfwewl55lnenr5pyzd7cmyx6";
const P2SH_ADDR: &str = "kaspatest:pz6gd03xxw0hy6aj4mrnqq8pcrwgxafc986fh2ky030csevvvaeeuysw0srlr";
#[test]
fn test_generate_tx() {
    // current path
    let kas_amount = kaspa_to_sompi(10.0);
    let sender: Address = SENDER_ADDR.try_into().unwrap();
    let receiver: Address = RECEIVER_ADDR.try_into().unwrap();
    //let p2sh: Address = P2SH_ADDR.try_into().unwrap();
    let current_path = std::env::current_dir().unwrap();
    let r_path = format!("{}/src/tx/generator/generator/utxos.json", current_path.display());
    let utxos = parse_utxos_from_file(&r_path).unwrap();
    let testnet_10 = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let change_address = sender.clone();
    let sig_op_count = 1u8;
    let minimum_signatures = 1u16;
    let final_transaction_priority_fee = Fees::SenderPays(2000000); // 0.02
    let payment_output = PaymentOutput::new(receiver, kas_amount);
    let payment_outputs = PaymentOutputs { outputs: vec![payment_output] };
    let final_transaction_payload = None;
    let priority_utxo_entries = None;
    let final_transaction_destination = PaymentDestination::PaymentOutputs(payment_outputs);
    let settings = GeneratorSettings::try_new_with_iterator(
        testnet_10,
        Box::new(utxos.into_iter()),
        priority_utxo_entries,
        change_address,
        sig_op_count,
        minimum_signatures,
        final_transaction_destination,
        final_transaction_priority_fee,
        final_transaction_payload,
        None,
    )
    .unwrap();
    let abortable = Abortable::default();
    let generator = Generator::try_new(settings, None, Some(&abortable)).unwrap();
    let mut txs = vec![];
    loop {
        if let Some(transaction) = generator.generate_transaction().transpose() {
            if let Ok(transaction) = transaction {
                txs.push(transaction);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    assert_eq!(txs.len(), 1);
}

#[test]
fn test_generate_tx2() {
    let commit_tx_id = Hash::from_str("5c1ddb4494ac8eb6488808c8be89f91e76402da497182a271eaec9227a10a1ea").unwrap();
    // current path
    let kas_amount_03 = kaspa_to_sompi(0.3);
    let sender: Address = SENDER_ADDR.try_into().unwrap();
    let receiver: Address = RECEIVER_ADDR.try_into().unwrap();
    //let p2sh: Address = P2SH_ADDR.try_into().unwrap();
    let current_path = std::env::current_dir().unwrap();
    let r_path = format!("{}/src/tx/generator/generator/utxos.json", current_path.display());
    let utxosOrigin = parse_utxos_from_file(&r_path).unwrap();
    let usedUtxos = vec![
        TransactionOutpoint::new(Hash::from_str("cf123968f3a93c8ba328c81a25ac6ec3d20101d2f5a2f2db7e472d5cc95747b6").unwrap(), 6),
        TransactionOutpoint::new(Hash::from_str("622741bbf81acc97d49b29c5ae6912c98620ceaaaac6d93597b8496eaec4cc14").unwrap(), 1),
    ];

    let utxos = utxosOrigin
        .iter()
        .filter(|utxo| {
            !usedUtxos.iter().any(|u| {
                u.transaction_id() == utxo.utxo.outpoint.transaction_id() && u.index() == utxo.utxo.outpoint.index()
            })
        })
        .map(|utxo| utxo.clone())
        .collect::<Vec<_>>();

    let str=r#"{"p":"krc-20","op":"transfer","tick":"KAST","amt":"10100000000","to":"kaspatest:qrjcg7hsgjapumpn8egyu6544qzdqs2lssas4nfwewl55lnenr5pyzd7cmyx6"}"#;
    let mut builder=  ScriptBuilder::new();
    builder.add_data(sender.payload.as_slice())
        .unwrap();
    builder.add_op(OpCheckSig).unwrap();
    builder.add_op(OpFalse).unwrap();
    builder.add_op(OpIf).unwrap();
    builder.add_data("kasplex".as_bytes()).unwrap();
    builder.add_i64(0).unwrap();
    builder.add_data(str.as_bytes()).unwrap();
    builder.add_op(OpEndIf).unwrap();

    let script=builder.script();
    let sk=standard::pay_to_script_hash_script(script.clone());
    let script_k1= ScriptPublicKey::from_hex("0000aa20b486be26339f726bb2aec73000e1c0dc83753829f49baac47c5f88658c67739e87").unwrap();
     assert_eq!(sk,script_k1);
    let testnet_10 = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let change_address = sender.clone();
    let sig_op_count = 1u8;
    let minimum_signatures = 1u16;
    let final_transaction_priority_fee = Fees::SenderPays(2000000); // 0.02
    let payment_outputs = PaymentOutputs { outputs: vec![] };
    let final_transaction_payload = None;
    let input_utxo = UtxoEntry {
        address: Some(sender.clone()),
        outpoint: TransactionOutpoint::new(commit_tx_id, 0),
        amount: kas_amount_03,
        script_public_key: standard::pay_to_script_hash_script(script.clone()),
        block_daa_score: 0,
        is_coinbase: false,
    };
    let priority_utxo_entries = Some(vec![UtxoEntryReference { utxo: Arc::new(input_utxo) }]);
    let final_transaction_destination = PaymentDestination::PaymentOutputs(payment_outputs);
    let settings = GeneratorSettings::try_new_with_iterator(
        testnet_10,
        Box::new(utxos.into_iter()),
        priority_utxo_entries,
        change_address,
        sig_op_count,
        minimum_signatures,
        final_transaction_destination,
        final_transaction_priority_fee,
        final_transaction_payload,
        None,
    )
    .unwrap();
    let abortable = Abortable::default();
    let generator = Generator::try_new(settings, None, Some(&abortable)).unwrap();
    let mut txs = vec![];
    loop {
        if let Some(transaction) = generator.generate_transaction().transpose() {
            if let Ok(transaction) = transaction {
                txs.push(transaction);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    assert_eq!(txs.len(), 1);
    let p= PrivateKey::try_new("5cd51b74226a845b8c757494136659997db1aaedf34c528e297f849f0fe87faf").unwrap();

    let tx = txs.get(0).unwrap();
    tx.try_sign_with_keys(&[p.secret_bytes()], Some(false)).unwrap();
    let unsigned_input_index=tx.transaction().inputs.iter().find_position(|input| input.signature_script.is_empty()).unwrap().0;

    let sig = tx.create_input_signature(unsigned_input_index, &p.secret_bytes(),SIG_HASH_ALL).unwrap();
    let encoded_sig= standard::pay_to_script_hash_signature_script(script.to_vec(), sig).unwrap();
}


fn parse_utxos_from_file(file: &str) -> Result<Vec<UtxoEntryReference>, Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(file)?;
    let utxos: Vec<Value> = serde_json::from_str(&file_content)?;

    let utxo_entries = utxos
        .into_iter()
        .map(|utxo| {
            let address: Address =
                format!("{}:{}", utxo["address"]["prefix"].as_str().unwrap(), utxo["address"]["payload"].as_str().unwrap())
                    .try_into()?;
            let tx_id = utxo["outpoint"]["transactionId"].as_str().unwrap();
            let outpoint = TransactionOutpoint::new(Hash::from_str(tx_id)?, utxo["outpoint"]["index"].as_u64().unwrap() as u32);
            let amount = utxo["amount"].as_str().unwrap().replace("n", "").parse::<u64>()?;
            let script_str = utxo["scriptPublicKey"]["script"].as_str().unwrap();
            let mut bytes = vec![0u8; script_str.len() / 2];
            faster_hex::hex_decode(script_str.as_bytes(), &mut bytes)?;

            let script_public_key =
                ScriptPublicKey::new(utxo["scriptPublicKey"]["version"].as_u64().unwrap() as u16, ScriptVec::from(bytes));
            let block_daa_score = utxo["blockDaaScore"].as_str().unwrap().replace("n", "").parse::<u64>()?;
            let is_coinbase = utxo["isCoinbase"].as_bool().unwrap();

            let val = UtxoEntry {
                address: Some(address),
                outpoint: outpoint.into(),
                amount,
                script_public_key,
                block_daa_score,
                is_coinbase,
            };
            Ok(UtxoEntryReference { utxo: Arc::new(val) })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

    Ok(utxo_entries)
}
