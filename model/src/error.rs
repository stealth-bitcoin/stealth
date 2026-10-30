use thiserror::Error;

/// Errors from the analysis pipeline.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnalysisError {
    #[error("descriptor input cannot be empty")]
    EmptyDescriptor,
    #[error(
        "descriptor `{}` failed normalization: {}",
        redact_private_keys(descriptor),
        redact_private_keys(message)
    )]
    DescriptorNormalization { descriptor: String, message: String },
    #[error("private key detected; provide the public extended key (xpub) instead")]
    PrivateKeyDetected,
    #[error("multisig SLIP-132 keys are not supported yet; provide the wallet descriptor instead")]
    MultisigKeyUnsupported,
    #[error("environment unavailable: {0}")]
    EnvironmentUnavailable(String),
    /// `detail` is the reply body, empty for Core's bare 403.
    #[error(
        "{method}: forbidden by the node (rpcwhitelist or rpcallowip){}",
        if detail.is_empty() { String::new() } else { format!(": {detail}") }
    )]
    RpcForbidden { method: String, detail: String },
    #[error("analysis execution failed: {0}")]
    Execution(String),
}

const PRIVATE_KEY_PREFIXES: [&str; 10] = [
    "xprv", "tprv", "yprv", "zprv", "uprv", "vprv", "Yprv", "Zprv", "Uprv", "Vprv",
];

/// Replace any alphanumeric run starting with an extended private key
/// prefix by a marker, so key material never reaches logs or the wire.
fn redact_private_keys(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = PRIVATE_KEY_PREFIXES
        .iter()
        .filter_map(|prefix| rest.find(prefix))
        .min()
    {
        result.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(tail.len());
        result.push_str("[redacted private key]");
        rest = &tail[end..];
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 test vector 1, chain m (private key). Safe to embed: it is
    // a published spec vector, used here only to prove redaction.
    const BIP32_VECTOR1_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jP\
                                      PqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    #[test]
    fn descriptor_normalization_display_redacts_private_keys() {
        let error = AnalysisError::DescriptorNormalization {
            descriptor: format!("wpkh({BIP32_VECTOR1_XPRV}/0/*)"),
            message: format!("RPC rejected wpkh({BIP32_VECTOR1_XPRV}/0/*)"),
        };
        let rendered = error.to_string();
        assert!(
            !rendered.contains(BIP32_VECTOR1_XPRV),
            "private key leaked: {rendered}"
        );
        assert!(rendered.contains("[redacted private key]"), "{rendered}");
    }

    #[test]
    fn descriptor_normalization_display_keeps_public_keys() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8Nqtwyb\
                    GhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let error = AnalysisError::DescriptorNormalization {
            descriptor: format!("wpkh({xpub}/0/*)"),
            message: "checksum mismatch".to_owned(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains(xpub), "{rendered}");
        assert!(!rendered.contains("[redacted private key]"), "{rendered}");
    }
}
