pub mod aggregate;
pub mod keygen;
pub mod round1;
pub mod round2;

#[cfg(test)]
mod pipeline_tests;

use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn version() -> String {
    "0.1.0".to_string()
}

#[wasm_bindgen]
pub fn frost_keygen(threshold: u16, num_participants: u16) -> Result<JsValue, JsValue> {
    keygen::frost_keygen_impl(threshold, num_participants)
        .and_then(|output| to_value(&output).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn frost_round1_commit(identifier_hex: &str) -> Result<JsValue, JsValue> {
    round1::frost_round1_commit_impl(identifier_hex)
        .and_then(|output| to_value(&output).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn frost_round2_sign(input: JsValue) -> Result<JsValue, JsValue> {
    let parsed = from_value::<round2::Round2Input>(input).map_err(|e| JsValue::from_str(&e.to_string()))?;

    round2::frost_round2_sign_impl(parsed)
        .and_then(|output| to_value(&output).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn frost_aggregate(input: JsValue) -> Result<JsValue, JsValue> {
    let parsed = from_value::<aggregate::AggregateInput>(input).map_err(|e| JsValue::from_str(&e.to_string()))?;

    aggregate::frost_aggregate_impl(parsed)
        .and_then(|output| to_value(&output).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}
