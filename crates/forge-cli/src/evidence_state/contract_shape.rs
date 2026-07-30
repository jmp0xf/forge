//! Detects same-major JSON content that the current typed contract cannot interpret.
//!
//! Identity verification must retain unknown content, while GC must conservatively assume that
//! such content may introduce references. The checked-in/generated schema is the single inventory
//! of fields and enum variants known by this binary, avoiding a second hand-maintained field list.

use std::sync::OnceLock;

use forge_schema::{SchemaKind, schema_for_kind};
use serde_json::{Map, Value};

const MAX_SCHEMA_WALK_DEPTH: usize = 256;

static RECEIPT_V1_SCHEMA: OnceLock<Option<Value>> = OnceLock::new();
static RECEIPT_V2_SCHEMA: OnceLock<Option<Value>> = OnceLock::new();
static EVIDENCE_V1_SCHEMA: OnceLock<Option<Value>> = OnceLock::new();
static EVIDENCE_V2_SCHEMA: OnceLock<Option<Value>> = OnceLock::new();

pub(super) fn has_unknown_contract_content(kind: SchemaKind, value: &Value) -> Result<bool, ()> {
    let schema = cached_schema(kind).ok_or(())?;
    has_unknown(value, schema, schema, 0)
}

fn cached_schema(kind: SchemaKind) -> Option<&'static Value> {
    let slot = match kind {
        SchemaKind::ReceiptV1 => &RECEIPT_V1_SCHEMA,
        SchemaKind::Receipt => &RECEIPT_V2_SCHEMA,
        SchemaKind::EvidenceV1 => &EVIDENCE_V1_SCHEMA,
        SchemaKind::Evidence => &EVIDENCE_V2_SCHEMA,
        _ => return None,
    };
    slot.get_or_init(|| serde_json::to_value(schema_for_kind(kind)).ok())
        .as_ref()
}

fn has_unknown(value: &Value, schema: &Value, root: &Value, depth: usize) -> Result<bool, ()> {
    if depth > MAX_SCHEMA_WALK_DEPTH {
        return Err(());
    }
    let schema = resolve_schema(schema, root)?;
    let Some(schema_object) = schema.as_object() else {
        return Ok(false);
    };

    for combinator in ["oneOf", "anyOf"] {
        if let Some(branches) = schema_object.get(combinator).and_then(Value::as_array) {
            let applicable = branches
                .iter()
                .filter(|branch| branch_is_applicable(value, branch, root, depth + 1))
                .collect::<Vec<_>>();
            if applicable.is_empty() {
                return Ok(true);
            }
            for branch in applicable {
                if !has_unknown(value, branch, root, depth + 1)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
    }
    if let Some(branches) = schema_object.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            if has_unknown(value, branch, root, depth + 1)? {
                return Ok(true);
            }
        }
    }

    if schema_object
        .get("const")
        .is_some_and(|expected| expected != value)
        || schema_object
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.contains(value))
    {
        return Ok(true);
    }

    match value {
        Value::Object(object) => {
            let properties = schema_object.get("properties").and_then(Value::as_object);
            for (key, member) in object {
                if let Some(member_schema) = properties.and_then(|known| known.get(key)) {
                    if has_unknown(member, member_schema, root, depth + 1)? {
                        return Ok(true);
                    }
                    continue;
                }
                match schema_object.get("additionalProperties") {
                    Some(Value::Bool(true)) => {}
                    Some(additional @ Value::Object(_)) => {
                        if has_unknown(member, additional, root, depth + 1)? {
                            return Ok(true);
                        }
                    }
                    _ => return Ok(true),
                }
            }
        }
        Value::Array(values) => {
            if let Some(items) = schema_object.get("items") {
                for member in values {
                    if has_unknown(member, items, root, depth + 1)? {
                        return Ok(true);
                    }
                }
            }
        }
        _ => {}
    }
    Ok(false)
}

fn resolve_schema<'a>(schema: &'a Value, root: &'a Value) -> Result<&'a Value, ()> {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return Ok(schema);
    };
    let pointer = reference.strip_prefix('#').ok_or(())?;
    root.pointer(pointer).ok_or(())
}

fn branch_is_applicable(value: &Value, schema: &Value, root: &Value, depth: usize) -> bool {
    if depth > MAX_SCHEMA_WALK_DEPTH {
        return false;
    }
    let Ok(schema) = resolve_schema(schema, root) else {
        return false;
    };
    let Some(schema_object) = schema.as_object() else {
        return true;
    };
    if schema_object
        .get("const")
        .is_some_and(|expected| expected != value)
        || schema_object
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.contains(value))
        || schema_object
            .get("type")
            .is_some_and(|expected| !type_matches(value, expected))
    {
        return false;
    }
    let (Value::Object(value), Some(properties)) = (
        value,
        schema_object.get("properties").and_then(Value::as_object),
    ) else {
        return true;
    };
    discriminator_properties_match(value, properties)
}

fn discriminator_properties_match(
    value: &Map<String, Value>,
    properties: &Map<String, Value>,
) -> bool {
    properties.iter().all(|(key, property)| {
        property
            .get("const")
            .is_none_or(|expected| value.get(key) == Some(expected))
    })
}

fn type_matches(value: &Value, expected: &Value) -> bool {
    match expected {
        Value::String(expected) => one_type_matches(value, expected),
        Value::Array(expected) => expected
            .iter()
            .filter_map(Value::as_str)
            .any(|expected| one_type_matches(value, expected)),
        _ => true,
    }
}

fn one_type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => true,
    }
}
