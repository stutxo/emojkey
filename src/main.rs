use std::str::{self, FromStr};

use base64::Engine;
use js_sys::wasm_bindgen::{JsCast, JsValue};
use qrcode::QrCode;
use qrcode::render::svg;

use bitcoin::{
    Address, Amount, Network, OutPoint, TapSighashType, Transaction, TxIn, TxOut,
    absolute::LockTime,
    consensus::{deserialize, encode::serialize_hex},
    key::{Keypair, Secp256k1, TapTweak},
    opcodes::all::OP_RETURN,
    script::Builder,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::{TaprootBuilder, TaprootSpendInfo},
};
use hex::FromHex;
use leptos::{
    html::ElementChild,
    mount::mount_to_body,
    prelude::{Get, OnAttribute, StyleAttribute, event_target_value, signal},
    task::spawn_local,
    view,
};
use log::info;
use rand::{Rng, rngs::ThreadRng};
use reqwasm::http::Request;
use schnorr_fun::{Schnorr, fun::Scalar, nonce};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[cfg(debug_assertions)]
const NETWORK: Network = Network::Signet;
#[cfg(debug_assertions)]
const MEMPOOL_API: &str = "https://mempool.space/signet/api";
#[cfg(debug_assertions)]
const MEMPOOL_TX: &str = "https://mempool.space/signet/tx";

#[cfg(not(debug_assertions))]
const NETWORK: Network = Network::Bitcoin;
#[cfg(not(debug_assertions))]
const MEMPOOL_API: &str = "https://mempool.space/api";
#[cfg(not(debug_assertions))]
const MEMPOOL_TX: &str = "https://mempool.space/tx";

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

fn create_emojkey(
    set_qr_code: impl Fn(String) + 'static,
    set_emoji: impl Fn(String) + 'static,
    set_emojress: impl Fn(String) + 'static,
) {
    let secp = Secp256k1::new();
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

    let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let keypair_bytes = keypair.secret_key().to_bytes();
    let public_key = keypair.public_key().to_xonly_bytes();

    let builder = TaprootBuilder::new();
    let xonly_public_key = bitcoin::XOnlyPublicKey::from_slice(public_key.as_ref()).unwrap();
    let taproot_spend_info = builder.finalize(&secp, xonly_public_key).unwrap();
    let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), NETWORK);

    info!("Address: {}", address);

    let emojis = ["🥪", "😂", "🤔", "🐱", "🚀", "👍", "💩", "🐸"];
    let mut rng = rand::thread_rng();
    let random_index = rng.gen_range(0..emojis.len());
    let random_emoji = emojis[random_index];
    let encoded_val = encode(random_emoji.chars().next().unwrap(), &keypair_bytes);

    let code = QrCode::new(address.to_string()).unwrap();
    let image = code
        .render()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#800000"))
        .light_color(svg::Color("#ffff80"))
        .build();

    let svg_data_url = format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(image)
    );

    set_qr_code(svg_data_url);
    set_emoji(encoded_val);
    set_emojress(address.to_string());
}

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    mount_to_body(move || {
        let (input, set_input) = signal("".to_string());
        let (withdraw_addr, set_withdraw_addr) = signal("".to_string());
        let (emoji, set_emoji) = signal("".to_string());
        let (emojress, set_emojress) = signal("".to_string());
        let (txid, set_txid) = signal("".to_string());
        let (emojress_2, set_emojress_2) = signal("".to_string());
        let (error, set_error) = signal("".to_string());
        let (qr_code, set_qr_code) = signal("".to_string());

        create_emojkey(set_qr_code, set_emoji, set_emojress);
        view! {

            <div
              style="
                max-width: 600px;
                margin: 0 auto;
                text-align: center;
                display: flex;
                flex-direction: column;
                align-items: center;
                padding: 1rem;
              "
            >

                <div
                  style="
                    font-size: 32px;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;

                  "
                >
                    "emojkey: "
                    {emoji}
                    <button
                    style="margin-left: 0.5em; font-size: 15px;"
                    on:click=move |_| {
                        let emoji_text = emoji.get();
                        let window = web_sys::window().unwrap();
                        let func = js_sys::Reflect::get(
                            &window,
                            &JsValue::from_str("copyToClipboard")
                        ).unwrap();
                        let func = func.dyn_into::<js_sys::Function>().unwrap();
                        js_sys::Reflect::apply(
                            &func,
                            &window,
                            &js_sys::Array::of1(&JsValue::from_str(&emoji_text))
                        ).unwrap();
                    }
                >
                    "📋"
                </button>
            </div>


            <div style="font-size: 20px; margin-top: 1rem;">
            <div
              style="
                display: inline-flex;
                flex-wrap: wrap;
                align-items: center;
                justify-content: center;
                width: 300px;
                  overflow-wrap: anywhere;
                text-align: center;
              "
            >
            <span style="margin-right: 0.5em; font-weight: bold;">
            "emojress::"
            {emojress}
        </span>
        <span
            style="


            "
        >

        </span>
            </div>

            <img
              src=move || qr_code.get()
              style="
                margin: 1rem auto;
                display: block;
                max-width: 200px;
              "
            />

            <button
                style="margin-top: 1rem;"
                on:click=move |_| {
                    create_emojkey(set_qr_code, set_emoji, set_emojress);
                }
            >
                "new emojkey 🔑"
            </button>
        </div>


            // Sweep section
            <div style="margin-top: 2em; width: 100%; display: flex; flex-direction: column; align-items: center;">
            <input
                style="width: 80%; max-width: 300px; padding: 0.5em; font-size: 1em; margin-bottom: 1em;"
                placeholder="sweep emojkey..."
                        on:input=move |ev| set_input(event_target_value(&ev))
                        value=move || input.get()

                    />
                    <input
                    placeholder="withdraw address..."
                    on:input=move |ev| set_withdraw_addr(event_target_value(&ev))
                    value=move || withdraw_addr.get()
                    style="width: 300px; padding: 0.5em; font-size: 1em;"
                />
                    <div style="margin-top: 1em;">
                        <button on:click=move |_| {
                            let secp = Secp256k1::new();
                            let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
                            let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

                            let decoded_bytes = decode_with_variation_selectors(&input.get());
                            let decoded_array: [u8; 32] = match decoded_bytes.try_into() {
                                Ok(array) => array,
                                Err(_) => {
                                    set_error("Invalid input".to_string());
                                    return;
                                }
                            };
                            let scalar = Scalar::from_bytes_mod_order(decoded_array)
                                .non_zero()
                                .expect("scalar is zero");
                            let keypair = schnorr.new_keypair(scalar);
                            let public_key = keypair.public_key().to_xonly_bytes();

                            let builder = TaprootBuilder::new();
                            let xonly_public_key = bitcoin::XOnlyPublicKey::from_slice(public_key.as_ref()).unwrap();
                            let taproot_spend_info = builder.finalize(&secp, xonly_public_key).unwrap();
                            let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), NETWORK);

                            set_emojress_2(address.to_string());

                            info!("Decoded address: {}", address);

                            spawn_local(async move {
                                let res_utxo = Request::get(&format!(
                                    "{MEMPOOL_API}/address/{}/utxo",
                                    address
                                ))
                                .send()
                                .await
                                .unwrap()
                                .text()
                                .await
                                .unwrap();

                                let utxos: Vec<Utxo> = serde_json::from_str(&res_utxo)
                                    .expect("Failed to parse JSON");


                                if utxos.is_empty() {
                                    info!("No UTXOs found, pls fund address");
                                    set_error("No UTXOs found, pls fund address".to_string());
                                    return;
                                }


                                let withdraw_address = Address::from_str(&withdraw_addr.get());

                                if withdraw_address.is_err() {
                                    set_error("Invalid withdraw address".to_string());
                                    return;
                                }

                                let inputs: Vec<TxIn> = utxos
                                    .iter()
                                    .map(|utxo| TxIn {
                                        previous_output: OutPoint::new(
                                            bitcoin::Txid::from_str(&utxo.txid)
                                                .expect("Invalid txid format"),
                                            utxo.vout,
                                        ),
                                        ..Default::default()
                                    })
                                    .collect();

                                info!("Found UTXOs: {:?}. {:?}", inputs.len(), inputs);
                                set_error("".to_string());

                                let mut prev_tx = Vec::new();
                                for input in &inputs {
                                    info!("Fetching previous tx: {:?}, {:?}",
                                          input.previous_output.txid,
                                          input.previous_output.vout);
                                    let url = format!(
                                        "{MEMPOOL_API}/tx/{}/hex",
                                        input.previous_output.txid
                                    );
                                    let response = Request::get(&url)
                                        .send()
                                        .await
                                        .unwrap()
                                        .text()
                                        .await
                                        .unwrap();

                                    let tx: Transaction = deserialize(
                                        &Vec::<u8>::from_hex(&response).unwrap()
                                    ).unwrap();

                                    let mut outpoint: Option<OutPoint> = None;
                                    for (i, out) in tx.output.iter().enumerate() {
                                        if address.script_pubkey() == out.script_pubkey {
                                            outpoint = Some(
                                                OutPoint::new(tx.compute_txid(), i as u32)
                                            );
                                            break;
                                        }
                                    }

                                    let prevout = outpoint.expect("Outpoint must exist in tx");
                                    prev_tx.push(tx.output[prevout.vout as usize].clone());
                                }

                                let total_amount = utxos.iter().map(|utxo| utxo.value).sum::<u64>();

                                let fee = 1337;
                                let spend = TxOut {
                                    value: Amount::from_sat(total_amount - fee),
                                    script_pubkey: withdraw_address.unwrap().assume_checked().script_pubkey(),
                                };



                                let op_return_script = Builder::new()
                                .push_opcode(OP_RETURN)
                                .push_slice(b"\xF0\x9F\x90\xB1")
                                .into_script();

                                let op_return = TxOut {
                                    value: Amount::from_sat(0),
                                    script_pubkey: op_return_script,
                                };

                                let mut unsigned_tx = Transaction {
                                    version: bitcoin::transaction::Version(2),
                                    lock_time: LockTime::ZERO,
                                    input: inputs,
                                    output: vec![spend, op_return],
                                };

                                let secret_key = bitcoin::secp256k1::SecretKey::from_slice(
                                    &keypair.secret_key().to_bytes()
                                ).expect("32 bytes, within curve order");
                                let keypair = Keypair::from_secret_key(&secp, &secret_key);

                                let signed_tx = key_spend(
                                    &mut unsigned_tx,
                                    keypair,
                                    prev_tx,
                                    TapSighashType::All,
                                    taproot_spend_info,
                                );

                                let serialized_tx = serialize_hex(&signed_tx);
                                info!("Hex Encoded Transaction: {}", serialized_tx);

                                let url = format!(
                                    "{MEMPOOL_API}/tx",

                                );
                                let res = Request::post(&url)
                                    .body(serialized_tx)
                                    .send()
                                    .await
                                    .unwrap()
                                    .text()
                                    .await
                                    .unwrap();



                                info!("TXID: {:?}", res);
                                let txid = format!("emojkey has been swept!: {}/{}", MEMPOOL_TX, res);
                                set_txid(txid);
                            });
                        }>
                            "🧹"
                        </button>
                    </div>
                    <div
                    style="
                        margin-top: 1em;
                        font-size: 0.85rem;    /* smaller text */
                        word-wrap: break-word; /* allow wrapping on long strings */
                        overflow-wrap: anywhere;
                        text-align: center;
                    "
                >
                    <p style="margin: 0.5em 0;">{emojress_2}</p>
                    <p style="margin: 0.5em 0;">{txid}</p>
                    <p style="margin: 0.5em 0; color: red;">{error}</p>
                </div>

                </div>
            </div>
        }
    });
}

fn key_spend(
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
