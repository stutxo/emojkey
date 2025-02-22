use std::str::{self, FromStr};

use bitcoin::{
    Address, Amount, Network, OutPoint, TapSighashType, Transaction, TxIn, TxOut,
    absolute::LockTime,
    consensus::{deserialize, encode::serialize_hex},
    key::{Keypair, Secp256k1, TapTweak},
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::{TaprootBuilder, TaprootSpendInfo},
};
use hex::FromHex;
use leptos::{mount::mount_to_body, task::spawn_local, view};
use log::info;
use rand::rngs::ThreadRng;
use reqwasm::http::Request;
use schnorr_fun::{Schnorr, fun::Scalar, nonce};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    status: UtxoStatus,
    value: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
}

fn byte_to_variation_selector(byte: u8) -> char {
    if byte < 16 {
        char::from_u32(0xFE00 + byte as u32).unwrap()
    } else {
        char::from_u32(0xE0100 + (byte - 16) as u32).unwrap()
    }
}

fn encode(base: char, bytes: &[u8]) -> String {
    let mut result = String::new();
    result.push(base);
    for byte in bytes {
        result.push(byte_to_variation_selector(*byte));
    }
    result
}

fn variation_selector_to_byte(variation_selector: char) -> Option<u8> {
    let vs = variation_selector as u32;
    if (0xFE00..=0xFE0F).contains(&vs) {
        Some((vs - 0xFE00) as u8)
    } else if (0xE0100..=0xE01EF).contains(&vs) {
        Some((vs - 0xE0100 + 16) as u8)
    } else {
        None
    }
}

fn decode_with_variation_selectors(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for ch in s.chars() {
        if let Some(byte) = variation_selector_to_byte(ch) {
            result.push(byte);
        }
    }
    result
}

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    let secp = Secp256k1::new();

    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

    // let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));

    let scalar = Scalar::from(1).non_zero().expect("scalar is zero");

    let keypair = schnorr.new_keypair(scalar);

    let keypair_bytes = keypair.secret_key().to_bytes();

    let public_key = keypair.public_key().to_xonly_bytes();

    let builder = TaprootBuilder::new();
    let xonly_public_key = bitcoin::XOnlyPublicKey::from_slice(public_key.as_ref()).unwrap();
    let taproot_spend_info = builder.finalize(&secp, xonly_public_key).unwrap();

    let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), Network::Signet);

    info!("Address: {}", address);

    let encoded = encode('😊', &keypair_bytes);
    info!("Encoded (invisible data behind emoji): {encoded}");

    let decoded_bytes = decode_with_variation_selectors(&encoded);

    info!("Decoded hex: {}", hex::encode(decoded_bytes.clone()));

    let decoded_array: [u8; 32] = decoded_bytes
        .try_into()
        .expect("slice with incorrect length");
    let scalar = Scalar::from_bytes_mod_order(decoded_array)
        .non_zero()
        .expect("scalar is zero");
    let keypair = schnorr.new_keypair(scalar);
    let public_key = keypair.public_key().to_xonly_bytes();

    let builder = TaprootBuilder::new();
    let xonly_public_key = bitcoin::XOnlyPublicKey::from_slice(public_key.as_ref()).unwrap();
    let taproot_spend_info = builder.finalize(&secp, xonly_public_key).unwrap();

    let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), Network::Signet);

    info!("Decoded address: {}", address);

    //check address balance

    mount_to_body(|| {
        view! { <address/> }
    });

    spawn_local(async move {
        let res_utxo = Request::get(&format!(
            "https://mempool.space/signet/api/address/{}/utxo",
            address
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

        let utxos: Vec<Utxo> = serde_json::from_str(&res_utxo).expect("Failed to parse JSON");

        if utxos.is_empty() {
            info!("No UTXOs found, pls fund address");
            return;
        }

        let inputs: Vec<TxIn> = utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: OutPoint::new(
                    bitcoin::Txid::from_str(&utxo.txid).expect("Invalid txid format"),
                    utxo.vout,
                ),
                ..Default::default()
            })
            .collect();

        info!("Found UTXOs: {:?}. {:?}", inputs.len(), inputs);

        let mut prev_tx = Vec::new();

        for input in inputs.clone() {
            info!(
                "Fetching previous tx: {:?}, {:?}",
                input.previous_output.txid, input.previous_output.vout
            );
            let url = format!(
                "https://mempool.space/signet/api/tx/{}/hex",
                input.previous_output.txid
            );
            let response = Request::get(&url)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();

            let tx: Transaction = deserialize(&Vec::<u8>::from_hex(&response).unwrap()).unwrap();

            let mut outpoint: Option<OutPoint> = None;
            for (i, out) in tx.output.iter().enumerate() {
                if address.script_pubkey() == out.script_pubkey {
                    outpoint = Some(OutPoint::new(tx.compute_txid(), i as u32));
                    break;
                }
            }

            let prevout = outpoint.expect("Outpoint must exist in tx");

            prev_tx.push(tx.output[prevout.vout as usize].clone());
        }

        let total_amount = utxos.iter().map(|utxo| utxo.value).sum::<u64>();
        let fee = 200;

        let spend = TxOut {
            value: Amount::from_sat(total_amount - fee),
            script_pubkey: address.script_pubkey(),
        };

        let mut unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: inputs,
            output: vec![spend],
        };

        let secret_key =
            bitcoin::secp256k1::SecretKey::from_slice(&keypair.secret_key().to_bytes())
                .expect("32 bytes, within curve order");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        let signed_tx = happy_spend(
            &mut unsigned_tx,
            keypair,
            prev_tx,
            TapSighashType::All,
            taproot_spend_info,
        );

        let serialized_tx = serialize_hex(&signed_tx);
        info!("Hex Encoded Transaction: {}", serialized_tx);

        let res = Request::post("https://mempool.space/signet/api/tx")
            .body(serialized_tx)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        info!("TXID: {:?}", res);
    });
}

fn happy_spend(
    unsigned_tx: &mut Transaction,
    keys: Keypair,
    prev_tx: Vec<TxOut>,
    sighash_type: TapSighashType,
    taproot_spend_info: TaprootSpendInfo,
) -> &mut Transaction {
    info!("Spending for happy path");
    let secp = Secp256k1::new();
    let mut unsigned_tx_clone = unsigned_tx.clone();

    for (index, input) in unsigned_tx.input.iter_mut().enumerate() {
        let mut sighasher = SighashCache::new(&mut unsigned_tx_clone);
        let sighash = sighasher
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prev_tx), sighash_type)
            .expect("failed to construct sighash");

        let message = Message::from(sighash);
        let tweak_key_pair = keys.tap_tweak(&secp, taproot_spend_info.merkle_root());
        let signature = secp.sign_schnorr_no_aux_rand(&message, &tweak_key_pair.to_inner());

        let signature = bitcoin::taproot::Signature {
            signature,
            sighash_type,
        };
        input.witness.push(signature.serialize());
    }
    unsigned_tx
}
