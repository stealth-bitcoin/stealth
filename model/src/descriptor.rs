use bitcoin::base58;

use crate::error::AnalysisError;
use crate::gateway::ResolvedDescriptor;

// BIP-32 canonical and SLIP-132 extended public key version bytes.
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
const YPUB_VERSION: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];
const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
const UPUB_VERSION: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];
const VPUB_VERSION: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

// Private counterparts (BIP-32 + SLIP-132, incl. multisig): rejected
// without echoing the input.
const PRIVATE_VERSIONS: [[u8; 4]; 10] = [
    [0x04, 0x88, 0xad, 0xe4], // xprv
    [0x04, 0x35, 0x83, 0x94], // tprv
    [0x04, 0x9d, 0x78, 0x78], // yprv
    [0x04, 0xb2, 0x43, 0x0c], // zprv
    [0x04, 0x4a, 0x4e, 0x28], // uprv
    [0x04, 0x5f, 0x18, 0xbc], // vprv
    [0x02, 0x95, 0xb0, 0x05], // Yprv
    [0x02, 0xaa, 0x7a, 0x99], // Zprv
    [0x02, 0x42, 0x85, 0xb5], // Uprv
    [0x02, 0x57, 0x50, 0x48], // Vprv
];

// SLIP-132 multisig public versions: unsupported, ask for the wallet
// descriptor instead.
const MULTISIG_VERSIONS: [[u8; 4]; 4] = [
    [0x02, 0x95, 0xb4, 0x3f], // Ypub
    [0x02, 0xaa, 0x7e, 0xd3], // Zpub
    [0x02, 0x42, 0x89, 0xef], // Upub
    [0x02, 0x57, 0x54, 0x83], // Vpub
];

// version(4) + depth(1) + fingerprint(4) + child(4) + chain code(32) + key(33)
const EXTENDED_KEY_LEN: usize = 78;

/// Expand a raw scan input into descriptor candidates.
///
/// Bare extended public keys become descriptor templates on the receive
/// chain (`/0/*`, or a derivation suffix given with the key): SLIP-132
/// keys (zpub/ypub/vpub/upub) are re-encoded with the canonical version
/// bytes and mapped to their script type, while ambiguous xpub/tpub
/// keys expand to all common script types. Private extended keys and
/// SLIP-132 multisig keys are rejected without echoing the input.
/// Anything else (descriptors, `addr(...)`, garbage) passes through
/// untouched.
pub fn expand_input(raw: &str) -> Result<Vec<String>, AnalysisError> {
    let trimmed = raw.trim();
    let (key, path) = match trimmed.split_once('/') {
        Some((key, suffix)) => (key, format!("/{suffix}")),
        None => (trimmed, "/0/*".to_owned()),
    };

    let payload = match base58::decode_check(key) {
        Ok(bytes) if bytes.len() == EXTENDED_KEY_LEN => bytes,
        _ => return Ok(vec![raw.to_owned()]),
    };

    let mut version = [0u8; 4];
    version.copy_from_slice(&payload[..4]);

    if PRIVATE_VERSIONS.contains(&version) {
        return Err(AnalysisError::PrivateKeyDetected);
    }
    if MULTISIG_VERSIONS.contains(&version) {
        return Err(AnalysisError::MultisigKeyUnsupported);
    }

    Ok(match version {
        XPUB_VERSION | TPUB_VERSION => vec![
            format!("pkh({key}{path})"),
            format!("sh(wpkh({key}{path}))"),
            format!("wpkh({key}{path})"),
            format!("tr({key}{path})"),
        ],
        ZPUB_VERSION => vec![format!("wpkh({}{path})", recode(&payload, XPUB_VERSION))],
        YPUB_VERSION => vec![format!(
            "sh(wpkh({}{path}))",
            recode(&payload, XPUB_VERSION)
        )],
        VPUB_VERSION => vec![format!("wpkh({}{path})", recode(&payload, TPUB_VERSION))],
        UPUB_VERSION => vec![format!(
            "sh(wpkh({}{path}))",
            recode(&payload, TPUB_VERSION)
        )],
        _ => vec![raw.to_owned()],
    })
}

fn recode(payload: &[u8], version: [u8; 4]) -> String {
    let mut bytes = version.to_vec();
    bytes.extend_from_slice(&payload[4..]);
    base58::encode_check(&bytes)
}

/// Trait for normalizing a raw descriptor string (e.g. via `getdescriptorinfo`).
pub trait DescriptorNormalizer {
    fn normalize(&self, descriptor: &str) -> Result<String, AnalysisError>;
}

/// Normalize raw descriptor strings: strip checksums, infer receive/change
/// pairs (`/0/*` ↔ `/1/*`), deduplicate.
///
/// When a `normalizer` is provided (typically a [`BlockchainGateway`]),
/// each candidate is passed through `getdescriptorinfo` for canonical
/// checksumming.
pub fn normalize_descriptors<N: DescriptorNormalizer + ?Sized>(
    raw_descriptors: &[String],
    derivation_range_end: u32,
    normalizer: &N,
) -> Result<Vec<ResolvedDescriptor>, AnalysisError> {
    let mut resolved = Vec::new();

    for raw in raw_descriptors {
        let without_checksum = raw
            .split('#')
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();

        if without_checksum.is_empty() {
            return Err(AnalysisError::EmptyDescriptor);
        }

        let candidates = if without_checksum.contains("/0/*") {
            vec![
                (without_checksum.clone(), false),
                (without_checksum.replace("/0/*", "/1/*"), true),
            ]
        } else if without_checksum.contains("/1/*") {
            vec![
                (without_checksum.replace("/1/*", "/0/*"), false),
                (without_checksum.clone(), true),
            ]
        } else {
            vec![(without_checksum.clone(), false)]
        };

        for (candidate, internal) in candidates {
            let normalized = normalizer
                .normalize(&candidate)
                .map_err(|error| match error {
                    AnalysisError::DescriptorNormalization { .. } => error,
                    other => AnalysisError::DescriptorNormalization {
                        descriptor: candidate.clone(),
                        message: other.to_string(),
                    },
                })?;

            let descriptor = ResolvedDescriptor {
                desc: normalized,
                internal,
                active: true,
                range_end: derivation_range_end,
            };

            if !resolved.iter().any(|item| item == &descriptor) {
                resolved.push(descriptor);
            }
        }
    }

    Ok(resolved)
}

/// Lightweight descriptor normalization that strips checksums and infers
/// receive/change pairs without calling an RPC normalizer.
///
/// Returns `(descriptor_string, is_internal)` pairs.
pub fn normalize_descriptors_raw(raw_descriptors: &[String]) -> Vec<(String, bool)> {
    let mut result = Vec::new();

    for raw in raw_descriptors {
        let without_checksum = raw
            .split('#')
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();

        if without_checksum.is_empty() {
            continue;
        }

        let candidates = if without_checksum.contains("/0/*") {
            vec![
                (without_checksum.clone(), false),
                (without_checksum.replace("/0/*", "/1/*"), true),
            ]
        } else if without_checksum.contains("/1/*") {
            vec![
                (without_checksum.replace("/1/*", "/0/*"), false),
                (without_checksum.clone(), true),
            ]
        } else {
            vec![(without_checksum, false)]
        };

        for pair in candidates {
            if !result.contains(&pair) {
                result.push(pair);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentityNormalizer;

    impl DescriptorNormalizer for IdentityNormalizer {
        fn normalize(&self, descriptor: &str) -> Result<String, AnalysisError> {
            Ok(descriptor.to_owned())
        }
    }

    #[test]
    fn normalizes_receive_and_change_pair() {
        let raw = vec!["wpkh(xpub/0/*)".to_owned()];
        let resolved = normalize_descriptors(&raw, 99, &IdentityNormalizer).unwrap();
        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().any(|d| d.internal));
        assert!(resolved.iter().any(|d| !d.internal));
    }

    // ── expand_input ────────────────────────────────────────────────────

    // BIP-32 test vector 1, chain m (public and private keys). The
    // private key is a published spec vector, embedded only to prove
    // that private inputs are rejected without being echoed.
    const BIP32_VECTOR1_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8Nqtwyb\
                                      GhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const BIP32_VECTOR1_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jP\
                                      PqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
    const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
    const YPUB_VERSION: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];
    const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
    const UPUB_VERSION: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];
    const VPUB_VERSION: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

    const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
    const TPRV_VERSION: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
    const YPRV_VERSION: [u8; 4] = [0x04, 0x9d, 0x78, 0x78];
    const ZPRV_VERSION: [u8; 4] = [0x04, 0xb2, 0x43, 0x0c];
    const UPRV_VERSION: [u8; 4] = [0x04, 0x4a, 0x4e, 0x28];
    const VPRV_VERSION: [u8; 4] = [0x04, 0x5f, 0x18, 0xbc];
    const MULTISIG_YPRV_VERSION: [u8; 4] = [0x02, 0x95, 0xb0, 0x05];
    const MULTISIG_ZPRV_VERSION: [u8; 4] = [0x02, 0xaa, 0x7a, 0x99];
    const MULTISIG_UPRV_VERSION: [u8; 4] = [0x02, 0x42, 0x85, 0xb5];
    const MULTISIG_VPRV_VERSION: [u8; 4] = [0x02, 0x57, 0x50, 0x48];

    const MULTISIG_YPUB_VERSION: [u8; 4] = [0x02, 0x95, 0xb4, 0x3f];
    const MULTISIG_ZPUB_VERSION: [u8; 4] = [0x02, 0xaa, 0x7e, 0xd3];
    const MULTISIG_UPUB_VERSION: [u8; 4] = [0x02, 0x42, 0x89, 0xef];
    const MULTISIG_VPUB_VERSION: [u8; 4] = [0x02, 0x57, 0x54, 0x83];

    fn reencode(key: &str, version: [u8; 4]) -> String {
        let payload = bitcoin::base58::decode_check(key).expect("test key must decode");
        let mut bytes = version.to_vec();
        bytes.extend_from_slice(&payload[4..]);
        bitcoin::base58::encode_check(&bytes)
    }

    fn expand_ok(input: &str) -> Vec<String> {
        expand_input(input).expect("input must expand")
    }

    #[test]
    fn reencoding_with_canonical_version_is_identity() {
        assert_eq!(
            reencode(BIP32_VECTOR1_XPUB, XPUB_VERSION),
            BIP32_VECTOR1_XPUB
        );
    }

    #[test]
    fn zpub_expands_to_wpkh_over_canonical_xpub() {
        let zpub = reencode(BIP32_VECTOR1_XPUB, ZPUB_VERSION);
        assert_eq!(
            expand_ok(&zpub),
            vec![format!("wpkh({BIP32_VECTOR1_XPUB}/0/*)")]
        );
    }

    #[test]
    fn ypub_expands_to_sh_wpkh_over_canonical_xpub() {
        let ypub = reencode(BIP32_VECTOR1_XPUB, YPUB_VERSION);
        assert_eq!(
            expand_ok(&ypub),
            vec![format!("sh(wpkh({BIP32_VECTOR1_XPUB}/0/*))")]
        );
    }

    #[test]
    fn vpub_expands_to_wpkh_over_canonical_tpub() {
        let vpub = reencode(BIP32_VECTOR1_XPUB, VPUB_VERSION);
        let tpub = reencode(BIP32_VECTOR1_XPUB, TPUB_VERSION);
        assert_eq!(expand_ok(&vpub), vec![format!("wpkh({tpub}/0/*)")]);
    }

    #[test]
    fn upub_expands_to_sh_wpkh_over_canonical_tpub() {
        let upub = reencode(BIP32_VECTOR1_XPUB, UPUB_VERSION);
        let tpub = reencode(BIP32_VECTOR1_XPUB, TPUB_VERSION);
        assert_eq!(expand_ok(&upub), vec![format!("sh(wpkh({tpub}/0/*))")]);
    }

    #[test]
    fn bare_xpub_expands_to_four_script_candidates() {
        let xpub = BIP32_VECTOR1_XPUB;
        assert_eq!(
            expand_ok(xpub),
            vec![
                format!("pkh({xpub}/0/*)"),
                format!("sh(wpkh({xpub}/0/*))"),
                format!("wpkh({xpub}/0/*)"),
                format!("tr({xpub}/0/*)"),
            ]
        );
    }

    #[test]
    fn bare_tpub_expands_to_four_script_candidates() {
        let tpub = reencode(BIP32_VECTOR1_XPUB, TPUB_VERSION);
        assert_eq!(
            expand_ok(&tpub),
            vec![
                format!("pkh({tpub}/0/*)"),
                format!("sh(wpkh({tpub}/0/*))"),
                format!("wpkh({tpub}/0/*)"),
                format!("tr({tpub}/0/*)"),
            ]
        );
    }

    #[test]
    fn xpub_with_derivation_suffix_expands_with_that_suffix() {
        let xpub = BIP32_VECTOR1_XPUB;
        assert_eq!(
            expand_ok(&format!("{xpub}/0/*")),
            vec![
                format!("pkh({xpub}/0/*)"),
                format!("sh(wpkh({xpub}/0/*))"),
                format!("wpkh({xpub}/0/*)"),
                format!("tr({xpub}/0/*)"),
            ]
        );
    }

    #[test]
    fn zpub_with_derivation_suffix_uses_given_suffix() {
        let zpub = reencode(BIP32_VECTOR1_XPUB, ZPUB_VERSION);
        assert_eq!(
            expand_ok(&format!("{zpub}/0/*")),
            vec![format!("wpkh({BIP32_VECTOR1_XPUB}/0/*)")]
        );
        assert_eq!(
            expand_ok(&format!("{zpub}/1/*")),
            vec![format!("wpkh({BIP32_VECTOR1_XPUB}/1/*)")]
        );
    }

    #[test]
    fn private_extended_keys_are_rejected_without_echoing_the_key() {
        let cases = [
            (XPRV_VERSION, "xprv"),
            (TPRV_VERSION, "tprv"),
            (YPRV_VERSION, "yprv"),
            (ZPRV_VERSION, "zprv"),
            (UPRV_VERSION, "uprv"),
            (VPRV_VERSION, "vprv"),
            (MULTISIG_YPRV_VERSION, "Yprv"),
            (MULTISIG_ZPRV_VERSION, "Zprv"),
            (MULTISIG_UPRV_VERSION, "Uprv"),
            (MULTISIG_VPRV_VERSION, "Vprv"),
        ];
        for (version, prefix) in cases {
            let key = reencode(BIP32_VECTOR1_XPRV, version);
            assert!(key.starts_with(prefix), "bad version bytes for {prefix}");
            let error = expand_input(&key).expect_err("private key must be rejected");
            assert_eq!(error, AnalysisError::PrivateKeyDetected);
            assert!(!error.to_string().contains(&key), "key echoed for {prefix}");
        }
    }

    #[test]
    fn private_key_with_derivation_suffix_is_rejected() {
        let with_path = format!("{BIP32_VECTOR1_XPRV}/0/*");
        let error = expand_input(&with_path).expect_err("private key with path must be rejected");
        assert_eq!(error, AnalysisError::PrivateKeyDetected);
        assert!(!error.to_string().contains(BIP32_VECTOR1_XPRV));
    }

    #[test]
    fn multisig_slip132_keys_are_rejected_with_guidance() {
        let cases = [
            (MULTISIG_YPUB_VERSION, "Ypub"),
            (MULTISIG_ZPUB_VERSION, "Zpub"),
            (MULTISIG_UPUB_VERSION, "Upub"),
            (MULTISIG_VPUB_VERSION, "Vpub"),
        ];
        for (version, prefix) in cases {
            let key = reencode(BIP32_VECTOR1_XPUB, version);
            assert!(key.starts_with(prefix), "bad version bytes for {prefix}");
            let error = expand_input(&key).expect_err("multisig key must be rejected");
            assert_eq!(error, AnalysisError::MultisigKeyUnsupported);
            assert!(error.to_string().contains("multisig"), "{error}");
            assert!(!error.to_string().contains(&key), "key echoed for {prefix}");
        }
    }

    #[test]
    fn descriptors_pass_through_untouched() {
        let wrapped = format!("wpkh({BIP32_VECTOR1_XPUB}/0/*)#abcd1234");
        assert_eq!(expand_ok(&wrapped), vec![wrapped.clone()]);
        assert_eq!(
            expand_ok("addr(bc1qexample)"),
            vec!["addr(bc1qexample)".to_owned()]
        );
    }

    #[test]
    fn non_key_inputs_pass_through_untouched() {
        assert_eq!(expand_ok("garbage"), vec!["garbage".to_owned()]);

        // Corrupt the checksum: still starts with "xpub" but must not expand.
        let mut corrupted = BIP32_VECTOR1_XPUB.to_owned();
        corrupted.pop();
        corrupted.push('9');
        assert_eq!(expand_ok(&corrupted), vec![corrupted.clone()]);

        // Valid base58check but not 78 bytes (a legacy address payload).
        let short = bitcoin::base58::encode_check(&[0x00; 21]);
        assert_eq!(expand_ok(&short), vec![short.clone()]);
    }
}
