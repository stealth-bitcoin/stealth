use stealth_core::scanner::ScanTarget;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("invalid scan input: {0}")]
    InvalidInput(String),
}

/// Validate and normalize a [`ScanTarget`] before scanning.
///
/// Returns the validated target unchanged, or an error if the input
/// fails structural validation.
pub fn validate(target: ScanTarget) -> Result<ScanTarget, ValidationError> {
    match &target {
        ScanTarget::Descriptor(d) => {
            validate_descriptor_shape(d)?;
        }
        ScanTarget::Descriptors(ds) => {
            if ds.is_empty() {
                return Err(ValidationError::InvalidInput(
                    "descriptors cannot be empty".to_owned(),
                ));
            }
            for (index, descriptor) in ds.iter().enumerate() {
                if let Err(ValidationError::InvalidInput(message)) =
                    validate_descriptor_shape(descriptor)
                {
                    return Err(ValidationError::InvalidInput(format!(
                        "descriptors[{index}] {message}",
                    )));
                }
            }
        }
        ScanTarget::Utxos(utxos) => {
            if utxos.is_empty() {
                return Err(ValidationError::InvalidInput(
                    "utxos cannot be empty".to_owned(),
                ));
            }
            if utxos.iter().any(|utxo| utxo.txid.trim().is_empty()) {
                return Err(ValidationError::InvalidInput(
                    "utxos cannot contain empty txid values".to_owned(),
                ));
            }
        }
    }
    Ok(target)
}

fn validate_descriptor_shape(descriptor: &str) -> Result<(), ValidationError> {
    let trimmed = descriptor.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::InvalidInput(
            "descriptor cannot be blank".to_owned(),
        ));
    }

    let (body, checksum) = split_descriptor_checksum(trimmed)?;
    if let Some(checksum) = checksum {
        validate_descriptor_checksum_shape(checksum)?;
    }

    if body.chars().any(char::is_whitespace) {
        return Err(ValidationError::InvalidInput(
            "descriptor cannot contain whitespace".to_owned(),
        ));
    }
    if !is_supported_descriptor_prefix(body) {
        return Err(ValidationError::InvalidInput(
            "descriptor has unsupported script form".to_owned(),
        ));
    }
    if !body.ends_with(')') {
        return Err(ValidationError::InvalidInput(
            "descriptor must end with ')'".to_owned(),
        ));
    }
    if !has_balanced_parentheses(body) {
        return Err(ValidationError::InvalidInput(
            "descriptor has unbalanced parentheses".to_owned(),
        ));
    }
    if body
        .split_once('(')
        .map(|(_, inner)| inner.trim_end_matches(')').trim().is_empty())
        .unwrap_or(true)
    {
        return Err(ValidationError::InvalidInput(
            "descriptor payload cannot be empty".to_owned(),
        ));
    }

    Ok(())
}

fn split_descriptor_checksum(descriptor: &str) -> Result<(&str, Option<&str>), ValidationError> {
    let mut parts = descriptor.split('#');
    let body = parts.next().expect("split always returns first element");
    let checksum = parts.next();
    if parts.next().is_some() {
        return Err(ValidationError::InvalidInput(
            "descriptor contains multiple checksum separators ('#')".to_owned(),
        ));
    }
    Ok((body, checksum))
}

fn validate_descriptor_checksum_shape(checksum: &str) -> Result<(), ValidationError> {
    if checksum.len() != 8 || !checksum.chars().all(|char| char.is_ascii_alphanumeric()) {
        return Err(ValidationError::InvalidInput(
            "descriptor checksum must be 8 alphanumeric characters (shape only)".to_owned(),
        ));
    }
    Ok(())
}

fn is_supported_descriptor_prefix(descriptor_body: &str) -> bool {
    const SUPPORTED_PREFIXES: [&str; 6] = ["wpkh(", "tr(", "pkh(", "sh(wpkh(", "wsh(", "sh(wsh("];
    SUPPORTED_PREFIXES
        .iter()
        .any(|prefix| descriptor_body.starts_with(prefix))
}

fn has_balanced_parentheses(value: &str) -> bool {
    let mut depth = 0usize;
    for char in value.chars() {
        if char == '(' {
            depth += 1;
            continue;
        }
        if char == ')' {
            if depth == 0 {
                return false;
            }
            depth -= 1;
        }
    }
    depth == 0
}
