use std::{fs, path::Path};
use serde_json::Value;

use crate::errors::{ValidateError, ValidateErrorKind};

pub fn load_json_file(path: impl AsRef<Path>) -> Result<Value, ValidateError> {
    let path = path.as_ref();
    let s = fs::read_to_string(path).map_err(|e| {
        ValidateError::new(ValidateErrorKind::Io, format!("read {}: {}", path.display(), e))
    })?;
    serde_json::from_str::<Value>(&s).map_err(|e| {
        ValidateError::new(ValidateErrorKind::JsonParse, format!("parse {}: {}", path.display(), e))
    })
}

pub fn load_policy_v13_json(path: impl AsRef<Path>) -> Result<Value, ValidateError> {
    load_json_file(path)
}

pub fn load_roles_db_json(path: impl AsRef<Path>) -> Result<Value, ValidateError> {
    load_json_file(path)
}

