//! Bounded, exact JSON parsing shared by content identities and strict protocol readers.
//!
//! `serde_json::Value` cannot represent every RFC 8259 number without routing some tokens through
//! `f64`. That is unsafe for content identities because distinct large integers can round to the
//! same value. This module keeps numbers as normalized decimal coefficient/exponent pairs and
//! creates a separate, fail-closed `serde_json::Value` projection for the typed wire reader.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde_json::{Map, Number, Value};

/// Maximum object/array nesting accepted by the exact parser.
pub const MAX_JSON_NESTING_DEPTH: usize = 256;
const MAX_PLAIN_INTEGER_DIGITS: usize = 20;

/// A content-free failure classification for exact JSON input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExactJsonError {
    #[error("JSON input exceeds its configured byte limit")]
    TooLarge,
    #[error("JSON input is malformed or has inconsistent typed semantics")]
    Malformed,
}

/// One duplicate-free, depth-bounded JSON document with exact numeric identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactJson {
    identity: JsonValue,
    semantic: Value,
    alternate_semantic: Option<Value>,
}

impl ExactJson {
    /// Applies one semantic projection to every numeric interpretation and requires one result.
    ///
    /// The callback cannot accidentally authorize only the primary projection: when an RFC 8259
    /// number is not exactly representable by `serde_json`, the callback runs against both
    /// sentinel projections and the results must agree.
    pub fn project_consistent<T, E, F, G>(&self, mut project: F, inconsistent: G) -> Result<T, E>
    where
        T: PartialEq,
        F: FnMut(&Value) -> Result<T, E>,
        G: FnOnce() -> E,
    {
        let projected = project(&self.semantic)?;
        if let Some(alternate) = &self.alternate_semantic {
            let alternate = project(alternate)?;
            if projected != alternate {
                return Err(inconsistent());
            }
        }
        Ok(projected)
    }

    /// Deserializes both semantic projections and rejects numeric ambiguity.
    pub fn deserialize_consistent<T>(&self) -> Result<T, ExactJsonError>
    where
        T: DeserializeOwned + PartialEq,
    {
        self.project_consistent(
            |value| serde_json::from_value(value.clone()).map_err(|_| ExactJsonError::Malformed),
            || ExactJsonError::Malformed,
        )
    }

    /// Serializes the complete root object except for exactly `root.data.id`.
    pub fn canonical_without_data_id(&self) -> Result<Vec<u8>, ExactJsonError> {
        let JsonValue::Object(root) = &self.identity else {
            return Err(ExactJsonError::Malformed);
        };
        let Some(JsonValue::Object(data)) = root.get("data") else {
            return Err(ExactJsonError::Malformed);
        };
        if !matches!(data.get("id"), Some(JsonValue::String(_))) {
            return Err(ExactJsonError::Malformed);
        }

        let mut output = Vec::new();
        write_object(root, RootMember::Data, &mut output)
            .map_err(|()| ExactJsonError::Malformed)?;
        Ok(output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(CanonicalNumber),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl JsonValue {
    fn semantic_projection(&self, unrepresentable_number: u64) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(*value),
            Self::Number(value) => value.exact_serde_integer().map_or_else(
                || Value::Number(Number::from(unrepresentable_number)),
                Value::Number,
            ),
            Self::String(value) => Value::String(value.clone()),
            Self::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| value.semantic_projection(unrepresentable_number))
                    .collect(),
            ),
            Self::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| {
                        (
                            key.clone(),
                            value.semantic_projection(unrepresentable_number),
                        )
                    })
                    .collect::<Map<_, _>>(),
            ),
        }
    }

    fn has_unrepresentable_number(&self) -> bool {
        match self {
            Self::Number(value) => value.exact_serde_integer().is_none(),
            Self::Array(values) => values.iter().any(Self::has_unrepresentable_number),
            Self::Object(values) => values.values().any(Self::has_unrepresentable_number),
            Self::Null | Self::Bool(_) | Self::String(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalNumber {
    negative: bool,
    coefficient: Vec<u8>,
    exponent: DecimalExponent,
}

impl CanonicalNumber {
    fn zero() -> Self {
        Self {
            negative: false,
            coefficient: vec![b'0'],
            exponent: DecimalExponent::zero(),
        }
    }

    fn parse(
        negative: bool,
        integer: &[u8],
        fraction: &[u8],
        exponent_negative: bool,
        exponent_digits: &[u8],
    ) -> Result<Self, ()> {
        let mut coefficient = Vec::with_capacity(integer.len() + fraction.len());
        coefficient.extend_from_slice(integer);
        coefficient.extend_from_slice(fraction);

        let first_nonzero = coefficient
            .iter()
            .position(|digit| *digit != b'0')
            .unwrap_or(coefficient.len());
        if first_nonzero == coefficient.len() {
            return Ok(Self::zero());
        }
        coefficient.drain(..first_nonzero);
        let trailing_zeroes = coefficient
            .iter()
            .rev()
            .take_while(|digit| **digit == b'0')
            .count();
        coefficient.truncate(coefficient.len() - trailing_zeroes);

        let mut exponent = if exponent_digits.is_empty() {
            DecimalExponent::zero()
        } else {
            DecimalExponent::parse(exponent_negative, exponent_digits)
        };
        let adjustment = i64::try_from(trailing_zeroes).map_err(|_| ())?
            - i64::try_from(fraction.len()).map_err(|_| ())?;
        exponent.add_small(adjustment)?;

        Ok(Self {
            negative,
            coefficient,
            exponent,
        })
    }

    /// Returns a serde number only when the exact mathematical value is an in-range integer.
    fn exact_serde_integer(&self) -> Option<Number> {
        if self.coefficient == b"0" {
            return Some(Number::from(0));
        }
        let zeroes = self.exponent.small_nonnegative(MAX_PLAIN_INTEGER_DIGITS)?;
        if self.coefficient.len().checked_add(zeroes)? > MAX_PLAIN_INTEGER_DIGITS {
            return None;
        }
        let mut digits = self.coefficient.clone();
        digits.resize(digits.len() + zeroes, b'0');
        let digits = std::str::from_utf8(&digits).ok()?;
        if self.negative {
            let magnitude = digits.parse::<u64>().ok()?;
            if magnitude == (i64::MAX as u64) + 1 {
                Some(Number::from(i64::MIN))
            } else {
                i64::try_from(magnitude)
                    .ok()
                    .map(|value| Number::from(-value))
            }
        } else {
            digits.parse::<u64>().ok().map(Number::from)
        }
    }

    fn write(&self, output: &mut Vec<u8>) {
        if self.negative {
            output.push(b'-');
        }
        output.extend_from_slice(&self.coefficient);
        if let Some(zeroes) = self.exponent.small_nonnegative(MAX_PLAIN_INTEGER_DIGITS) {
            if self.coefficient.len() + zeroes <= MAX_PLAIN_INTEGER_DIGITS {
                output.resize(output.len() + zeroes, b'0');
                return;
            }
        }
        output.push(b'e');
        self.exponent.write(output);
    }
}

/// Arbitrary-precision signed decimal used only for the scientific exponent.
///
/// Its storage is bounded by the source document. Arithmetic adjusts it only by a source-length
/// quantity, so `1e999999...` never allocates memory proportional to the exponent's value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DecimalExponent {
    negative: bool,
    magnitude: Vec<u8>,
}

impl DecimalExponent {
    fn zero() -> Self {
        Self {
            negative: false,
            magnitude: vec![b'0'],
        }
    }

    fn parse(negative: bool, digits: &[u8]) -> Self {
        let first_nonzero = digits
            .iter()
            .position(|digit| *digit != b'0')
            .unwrap_or(digits.len());
        if first_nonzero == digits.len() {
            return Self::zero();
        }
        Self {
            negative,
            magnitude: digits[first_nonzero..].to_vec(),
        }
    }

    fn is_zero(&self) -> bool {
        self.magnitude == b"0"
    }

    fn add_small(&mut self, value: i64) -> Result<(), ()> {
        if value == 0 {
            return Ok(());
        }
        let other_negative = value.is_negative();
        let other = value.unsigned_abs().to_string().into_bytes();
        if self.is_zero() {
            self.negative = other_negative;
            self.magnitude = other;
            return Ok(());
        }
        if self.negative == other_negative {
            self.magnitude = add_decimal_magnitudes(&self.magnitude, &other);
            return Ok(());
        }
        match compare_decimal_magnitudes(&self.magnitude, &other) {
            Ordering::Greater => {
                self.magnitude = subtract_decimal_magnitudes(&self.magnitude, &other)?;
            }
            Ordering::Less => {
                self.magnitude = subtract_decimal_magnitudes(&other, &self.magnitude)?;
                self.negative = other_negative;
            }
            Ordering::Equal => *self = Self::zero(),
        }
        Ok(())
    }

    fn small_nonnegative(&self, limit: usize) -> Option<usize> {
        if self.negative {
            return None;
        }
        let value = std::str::from_utf8(&self.magnitude)
            .ok()?
            .parse::<usize>()
            .ok()?;
        (value <= limit).then_some(value)
    }

    fn write(&self, output: &mut Vec<u8>) {
        if self.negative {
            output.push(b'-');
        }
        output.extend_from_slice(&self.magnitude);
    }
}

fn compare_decimal_magnitudes(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn add_decimal_magnitudes(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(left.len().max(right.len()) + 1);
    let mut left = left.iter().rev();
    let mut right = right.iter().rev();
    let mut carry = 0_u8;
    loop {
        let left_digit = left.next().map(|digit| digit - b'0');
        let right_digit = right.next().map(|digit| digit - b'0');
        if left_digit.is_none() && right_digit.is_none() {
            break;
        }
        let sum = left_digit.unwrap_or(0) + right_digit.unwrap_or(0) + carry;
        output.push(b'0' + (sum % 10));
        carry = sum / 10;
    }
    if carry != 0 {
        output.push(b'0' + carry);
    }
    output.reverse();
    output
}

/// Subtracts `right` from `left`; the caller guarantees `left >= right`.
fn subtract_decimal_magnitudes(left: &[u8], right: &[u8]) -> Result<Vec<u8>, ()> {
    let mut output = Vec::with_capacity(left.len());
    let mut borrow = 0_i16;
    for offset in 0..left.len() {
        let left_digit = i16::from(left[left.len() - 1 - offset] - b'0') - borrow;
        let right_digit = right
            .len()
            .checked_sub(offset + 1)
            .map_or(0, |index| i16::from(right[index] - b'0'));
        let (digit, next_borrow) = if left_digit < right_digit {
            (left_digit + 10 - right_digit, 1)
        } else {
            (left_digit - right_digit, 0)
        };
        output.push(b'0' + u8::try_from(digit).map_err(|_| ())?);
        borrow = next_borrow;
    }
    if borrow != 0 {
        return Err(());
    }
    while output.len() > 1 && output.last() == Some(&b'0') {
        output.pop();
    }
    output.reverse();
    Ok(output)
}

/// Parses one exact JSON document without accepting duplicate decoded keys or ambiguous numbers.
pub fn parse_exact_json(bytes: &[u8], max_bytes: usize) -> Result<ExactJson, ExactJsonError> {
    if bytes.len() > max_bytes {
        return Err(ExactJsonError::TooLarge);
    }
    let mut parser = Parser { bytes, offset: 0 };
    parser.skip_whitespace();
    let identity = parser
        .parse_value(0)
        .map_err(|()| ExactJsonError::Malformed)?;
    parser.skip_whitespace();
    if parser.offset != bytes.len() {
        return Err(ExactJsonError::Malformed);
    }
    let has_unrepresentable_number = identity.has_unrepresentable_number();
    let semantic = identity.semantic_projection(0);
    let alternate_semantic = has_unrepresentable_number.then(|| identity.semantic_projection(1));
    Ok(ExactJson {
        identity,
        semantic,
        alternate_semantic,
    })
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, ()> {
        match self.peek().ok_or(())? {
            b'n' => self.parse_keyword(b"null", JsonValue::Null),
            b't' => self.parse_keyword(b"true", JsonValue::Bool(true)),
            b'f' => self.parse_keyword(b"false", JsonValue::Bool(false)),
            b'"' => self.parse_string().map(JsonValue::String),
            b'[' => self.parse_array(depth),
            b'{' => self.parse_object(depth),
            b'-' | b'0'..=b'9' => self.parse_number().map(JsonValue::Number),
            _ => Err(()),
        }
    }

    fn parse_keyword(&mut self, keyword: &[u8], value: JsonValue) -> Result<JsonValue, ()> {
        if !self.bytes[self.offset..].starts_with(keyword) {
            return Err(());
        }
        self.offset += keyword.len();
        Ok(value)
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, ()> {
        if depth >= MAX_JSON_NESTING_DEPTH {
            return Err(());
        }
        self.offset += 1;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.parse_value(depth + 1)?);
            self.skip_whitespace();
            if self.consume(b']') {
                break;
            }
            if !self.consume(b',') {
                return Err(());
            }
            self.skip_whitespace();
        }
        Ok(JsonValue::Array(values))
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, ()> {
        if depth >= MAX_JSON_NESTING_DEPTH {
            return Err(());
        }
        self.offset += 1;
        self.skip_whitespace();
        let mut values = BTreeMap::new();
        if self.consume(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(());
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(());
            }
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            if values.insert(key, value).is_some() {
                return Err(());
            }
            self.skip_whitespace();
            if self.consume(b'}') {
                break;
            }
            if !self.consume(b',') {
                return Err(());
            }
            self.skip_whitespace();
        }
        Ok(JsonValue::Object(values))
    }

    fn parse_string(&mut self) -> Result<String, ()> {
        let start = self.offset;
        self.offset += 1;
        loop {
            match self.peek().ok_or(())? {
                b'"' => {
                    self.offset += 1;
                    return serde_json::from_slice(&self.bytes[start..self.offset]).map_err(|_| ());
                }
                b'\\' => {
                    self.offset += 1;
                    match self.peek().ok_or(())? {
                        b'u' => {
                            self.offset += 1;
                            let end = self.offset.checked_add(4).ok_or(())?;
                            let digits = self.bytes.get(self.offset..end).ok_or(())?;
                            if !digits.iter().all(u8::is_ascii_hexdigit) {
                                return Err(());
                            }
                            self.offset = end;
                        }
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            self.offset += 1;
                        }
                        _ => return Err(()),
                    }
                }
                0x00..=0x1f => return Err(()),
                _ => self.offset += 1,
            }
        }
    }

    fn parse_number(&mut self) -> Result<CanonicalNumber, ()> {
        let negative = self.consume(b'-');
        let integer_start = self.offset;
        match self.peek().ok_or(())? {
            b'0' => {
                self.offset += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(());
                }
            }
            b'1'..=b'9' => {
                self.offset += 1;
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.offset += 1;
                }
            }
            _ => return Err(()),
        }
        let integer_end = self.offset;

        let mut fraction_start = self.offset;
        let mut fraction_end = self.offset;
        if self.consume(b'.') {
            fraction_start = self.offset;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
            fraction_end = self.offset;
            if fraction_start == fraction_end {
                return Err(());
            }
        }

        let mut exponent_negative = false;
        let mut exponent_start = self.offset;
        let mut exponent_end = self.offset;
        if self.peek().is_some_and(|byte| matches!(byte, b'e' | b'E')) {
            self.offset += 1;
            exponent_negative = if self.consume(b'-') {
                true
            } else {
                self.consume(b'+');
                false
            };
            exponent_start = self.offset;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
            exponent_end = self.offset;
            if exponent_start == exponent_end {
                return Err(());
            }
        }

        CanonicalNumber::parse(
            negative,
            &self.bytes[integer_start..integer_end],
            &self.bytes[fraction_start..fraction_end],
            exponent_negative,
            &self.bytes[exponent_start..exponent_end],
        )
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.offset += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() != Some(expected) {
            return false;
        }
        self.offset += 1;
        true
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }
}

#[derive(Clone, Copy)]
enum RootMember {
    Data,
    Nested,
}

fn write_json(value: &JsonValue, output: &mut Vec<u8>) -> Result<(), ()> {
    match value {
        JsonValue::Null => output.extend_from_slice(b"null"),
        JsonValue::Bool(true) => output.extend_from_slice(b"true"),
        JsonValue::Bool(false) => output.extend_from_slice(b"false"),
        JsonValue::Number(number) => number.write(output),
        JsonValue::String(value) => {
            serde_json::to_writer(output, value).map_err(|_| ())?;
        }
        JsonValue::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_json(value, output)?;
            }
            output.push(b']');
        }
        JsonValue::Object(values) => write_object(values, RootMember::Nested, output)?,
    }
    Ok(())
}

fn write_object(
    values: &BTreeMap<String, JsonValue>,
    member: RootMember,
    output: &mut Vec<u8>,
) -> Result<(), ()> {
    output.push(b'{');
    let mut first = true;
    for (key, value) in values {
        if matches!(member, RootMember::Data) && key == "data" {
            let JsonValue::Object(data) = value else {
                return Err(());
            };
            write_member_separator(&mut first, output);
            write_string(key, output)?;
            output.push(b':');
            write_data_without_id(data, output)?;
            continue;
        }
        write_member_separator(&mut first, output);
        write_string(key, output)?;
        output.push(b':');
        write_json(value, output)?;
    }
    output.push(b'}');
    Ok(())
}

fn write_data_without_id(
    values: &BTreeMap<String, JsonValue>,
    output: &mut Vec<u8>,
) -> Result<(), ()> {
    output.push(b'{');
    let mut first = true;
    for (key, value) in values {
        if key == "id" {
            continue;
        }
        write_member_separator(&mut first, output);
        write_string(key, output)?;
        output.push(b':');
        write_json(value, output)?;
    }
    output.push(b'}');
    Ok(())
}

fn write_member_separator(first: &mut bool, output: &mut Vec<u8>) {
    if *first {
        *first = false;
    } else {
        output.push(b',');
    }
}

fn write_string(value: &str, output: &mut Vec<u8>) -> Result<(), ()> {
    serde_json::to_writer(output, value).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{ExactJsonError, MAX_JSON_NESTING_DEPTH, parse_exact_json};

    const MAX_TEST_BYTES: usize = 1024 * 1024;

    fn canonical_number(token: &str) -> Result<Vec<u8>, ExactJsonError> {
        let bytes = format!("{{\"data\":{{\"id\":\"ignored\"}},\"value\":{token}}}");
        parse_exact_json(bytes.as_bytes(), MAX_TEST_BYTES)?.canonical_without_data_id()
    }

    #[test]
    fn equivalent_numbers_have_one_exact_canonical_form() -> Result<(), ExactJsonError> {
        let one = canonical_number("1")?;
        assert_eq!(one, br#"{"data":{},"value":1}"#);
        for equivalent in ["1.0", "1e0", "10e-1", "1000.000e-3"] {
            assert_eq!(one, canonical_number(equivalent)?);
        }
        assert_eq!(canonical_number("1.5")?, br#"{"data":{},"value":15e-1}"#);
        let zero = canonical_number("0")?;
        for equivalent in ["-0", "0.0", "-0e999999999999999999999"] {
            assert_eq!(zero, canonical_number(equivalent)?);
        }
        Ok(())
    }

    #[test]
    fn arbitrary_precision_numbers_are_distinct_or_equivalent_by_value()
    -> Result<(), ExactJsonError> {
        assert_ne!(
            canonical_number("184467440737095516160000000000000000001")?,
            canonical_number("184467440737095516160000000000000000002")?
        );
        assert_eq!(
            canonical_number("10e999999999999999999999999999999999999")?,
            canonical_number("1e1000000000000000000000000000000000000")?
        );
        assert_ne!(
            canonical_number("1e1000000000000000000000000000000000000")?,
            canonical_number("1e1000000000000000000000000000000000001")?
        );
        Ok(())
    }

    #[test]
    fn decoded_keys_are_unique_and_sorted_by_utf8_bytes() -> Result<(), ExactJsonError> {
        let duplicate = br#"{"data":{"id":"ignored"},"a":1,"\u0061":2}"#;
        assert!(parse_exact_json(duplicate, MAX_TEST_BYTES).is_err());

        let parsed = parse_exact_json(
            r#"{"z":0,"data":{"nested":{"id":"kept"},"id":"removed"},"é":2,"a":1}"#.as_bytes(),
            MAX_TEST_BYTES,
        )?;
        assert_eq!(
            parsed.canonical_without_data_id()?,
            "{\"a\":1,\"data\":{\"nested\":{\"id\":\"kept\"}},\"z\":0,\"é\":2}".as_bytes()
        );
        Ok(())
    }

    #[test]
    fn nesting_and_document_size_are_bounded() {
        let accepted = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_NESTING_DEPTH),
            "]".repeat(MAX_JSON_NESTING_DEPTH)
        );
        assert!(parse_exact_json(accepted.as_bytes(), accepted.len()).is_ok());
        let rejected = format!("[{accepted}]");
        assert!(parse_exact_json(rejected.as_bytes(), rejected.len()).is_err());
        assert_eq!(parse_exact_json(b"null", 3), Err(ExactJsonError::TooLarge));
    }

    #[test]
    fn malformed_number_grammar_is_rejected() {
        for token in ["-", "01", "1.", "1e", "1e+", "+1", ".1", "--1"] {
            let document = format!("{{\"data\":{{\"id\":\"ignored\"}},\"value\":{token}}}");
            assert!(
                parse_exact_json(document.as_bytes(), MAX_TEST_BYTES).is_err(),
                "{token}"
            );
        }
    }

    #[test]
    fn dual_semantic_projection_exposes_known_unrepresentable_numbers() -> Result<(), ExactJsonError>
    {
        let parsed = parse_exact_json(
            br#"{"data":{"id":"ignored"},"wide":18446744073709551616,"fraction":1.5,"integer":1e1}"#,
            MAX_TEST_BYTES,
        )?;
        let alternate = parsed
            .alternate_semantic
            .as_ref()
            .ok_or(ExactJsonError::Malformed)?;
        assert_eq!(parsed.semantic["wide"], 0);
        assert_eq!(alternate["wide"], 1);
        assert_eq!(parsed.semantic["fraction"], 0);
        assert_eq!(alternate["fraction"], 1);
        assert_eq!(parsed.semantic["integer"], 10);
        assert_eq!(alternate["integer"], 10);
        Ok(())
    }
}
