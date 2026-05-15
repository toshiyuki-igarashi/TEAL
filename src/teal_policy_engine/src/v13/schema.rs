use serde_json::Value;

use crate::errors::{ValidateError, ValidateErrorKind};

pub fn validate_against_schema(instance: &Value, schema_json: &Value) -> Result<(), ValidateError> {
    let compiled = jsonschema::JSONSchema::compile(schema_json).map_err(|e| {
        ValidateError::new(ValidateErrorKind::Schema, format!("compile schema: {e}"))
    })?;

    if let Err(errors) = compiled.validate(instance) {
        // 重要：どこがダメか分かる形に整形する（JSON Pointer + message）
        let mut lines = vec![];
        for err in errors {
            lines.push(format!("{}: {}", err.instance_path, err));
        }
        return Err(ValidateError::new(
            ValidateErrorKind::Schema,
            lines.join("\n"),
        ));
    }
    Ok(())
}

