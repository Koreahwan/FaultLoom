use core::fmt;

use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalJsonError {
    Empty,
    TooLarge { maximum: usize },
    InvalidUtf8,
    Malformed,
    InvalidNumber,
    NonCanonical,
}

pub(crate) fn parse_canonical_json(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<Value, CanonicalJsonError> {
    if bytes.is_empty() {
        return Err(CanonicalJsonError::Empty);
    }
    if bytes.len() > maximum_bytes {
        return Err(CanonicalJsonError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    let text = core::str::from_utf8(bytes).map_err(|_| CanonicalJsonError::InvalidUtf8)?;
    let value: Value = serde_json::from_str(text).map_err(|_| CanonicalJsonError::Malformed)?;
    validate_numbers(&value)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| CanonicalJsonError::Malformed)?;
    if canonical != bytes {
        return Err(CanonicalJsonError::NonCanonical);
    }
    Ok(value)
}

pub(crate) fn canonical_json_bytes(
    value: &Value,
    maximum_bytes: usize,
) -> Result<Vec<u8>, CanonicalJsonError> {
    validate_numbers(value)?;
    let encoded = serde_json::to_vec(value).map_err(|_| CanonicalJsonError::Malformed)?;
    if encoded.is_empty() {
        return Err(CanonicalJsonError::Empty);
    }
    if encoded.len() > maximum_bytes {
        return Err(CanonicalJsonError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    Ok(encoded)
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("canonical JSON cannot be empty"),
            Self::TooLarge { maximum } => {
                write!(formatter, "canonical JSON exceeds {maximum} bytes")
            }
            Self::InvalidUtf8 => formatter.write_str("canonical JSON must be UTF-8"),
            Self::Malformed => formatter.write_str("canonical JSON is malformed"),
            Self::InvalidNumber => {
                formatter.write_str("canonical JSON numbers must be signed 64-bit integers")
            }
            Self::NonCanonical => formatter.write_str("JSON bytes are not canonical"),
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

fn validate_numbers(value: &Value) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => number
            .as_i64()
            .map(|_| ())
            .ok_or(CanonicalJsonError::InvalidNumber),
        Value::Array(values) => values.iter().try_for_each(validate_numbers),
        Value::Object(values) => values.values().try_for_each(validate_numbers),
    }
}
