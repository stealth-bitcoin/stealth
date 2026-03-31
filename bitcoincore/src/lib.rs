use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use ini::Ini;
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use stealth_model::error::AnalysisError;
use stealth_model::gateway::{
    BlockchainGateway, DecodedTransaction, DescriptorType, ResolvedDescriptor, TxInputRef,
    TxOutput, Utxo, WalletHistory, WalletTxCategory, WalletTxEntry,
};
use stealth_model::types::btc_to_amount;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinCoreConfig {
    pub network: String,
    pub datadir: Option<PathBuf>,
    pub rpchost: String,
    pub rpcport: u16,
    pub rpcuser: Option<String>,
    pub rpcpassword: Option<String>,
}

impl BitcoinCoreConfig {
    pub fn from_ini_file(path: impl AsRef<Path>) -> Result<Self, AnalysisError> {
        let path = path.as_ref();
        let ini = Ini::load_from_file(path)
            .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?;
        let section = ini.section(Some("bitcoin")).ok_or_else(|| {
            AnalysisError::EnvironmentUnavailable("missing [bitcoin] section".into())
        })?;

        let network = section
            .get("network")
            .map(|value| value.trim().to_lowercase())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "regtest".into());
        let datadir = section.get("datadir").and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else if Path::new(trimmed).is_absolute() {
                Some(PathBuf::from(trimmed))
            } else {
                Some(
                    path.parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(trimmed),
                )
            }
        });

        Ok(Self {
            rpcport: section
                .get("rpcport")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or_else(|| default_rpc_port(&network)),
            rpchost: section
                .get("rpchost")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "127.0.0.1".into()),
            rpcuser: section
                .get("rpcuser")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            rpcpassword: section
                .get("rpcpassword")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            network,
            datadir,
        })
    }

    fn cookie_credentials(&self) -> Result<(String, String), AnalysisError> {
        let datadir = self.datadir.as_ref().ok_or_else(|| {
            AnalysisError::EnvironmentUnavailable("missing datadir for cookie auth".into())
        })?;
        let mut candidates = Vec::new();
        if self.network == "mainnet" {
            candidates.push(datadir.join(".cookie"));
        } else {
            candidates.push(datadir.join(&self.network).join(".cookie"));
            candidates.push(datadir.join(".cookie"));
        }

        for candidate in candidates {
            if !candidate.exists() {
                continue;
            }
            if let Ok(creds) = read_cookie_file(&candidate) {
                return Ok(creds);
            }
        }

        Err(AnalysisError::EnvironmentUnavailable(
            "could not locate a readable Bitcoin Core cookie file".into(),
        ))
    }
}

/// Read a Bitcoin Core `.cookie` file, returning `(user, password)`.
///
/// The cookie format is a single line of `__cookie__:hex_password`.
pub fn read_cookie_file(path: &Path) -> Result<(String, String), AnalysisError> {
    let contents = fs::read_to_string(path).map_err(|e| {
        AnalysisError::EnvironmentUnavailable(format!(
            "cannot read cookie file {}: {e}",
            path.display()
        ))
    })?;
    let mut parts = contents.trim().splitn(2, ':');
    let user = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AnalysisError::EnvironmentUnavailable(format!("invalid cookie file {}", path.display()))
        })?
        .to_string();
    let pass = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AnalysisError::EnvironmentUnavailable(format!("invalid cookie file {}", path.display()))
        })?
        .to_string();
    Ok((user, pass))
}

pub struct BitcoinCoreRpc {
    config: BitcoinCoreConfig,
    client: Client,
}

impl BitcoinCoreRpc {
    pub fn new(config: BitcoinCoreConfig) -> Result<Self, AnalysisError> {
        let client = Client::builder()
            .build()
            .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?;
        Ok(Self { config, client })
    }

    /// Construct a gateway from a URL and optional credentials.
    ///
    /// This mirrors the env-var based configuration used by the HTTP
    /// API (`STEALTH_RPC_URL`, `STEALTH_RPC_USER`, `STEALTH_RPC_PASS`).
    pub fn from_url(
        url: &str,
        user: Option<String>,
        password: Option<String>,
    ) -> Result<Self, AnalysisError> {
        let (host, port) = parse_host_port_from_url(url);
        let config = BitcoinCoreConfig {
            network: infer_network_from_port(port),
            datadir: None,
            rpchost: host,
            rpcport: port,
            rpcuser: user,
            rpcpassword: password,
        };
        Self::new(config)
    }

    fn rpc_url(&self, wallet: Option<&str>) -> String {
        let base = format!("http://{}:{}", self.config.rpchost, self.config.rpcport);
        wallet
            .map(|wallet_name| format!("{base}/wallet/{}", urlencoding::encode(wallet_name)))
            .unwrap_or(base)
    }

    fn credentials(&self) -> Result<(String, String), AnalysisError> {
        if let (Some(user), Some(password)) =
            (self.config.rpcuser.clone(), self.config.rpcpassword.clone())
        {
            Ok((user, password))
        } else {
            self.config.cookie_credentials()
        }
    }

    fn call<T: DeserializeOwned>(
        &self,
        wallet: Option<&str>,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T, AnalysisError> {
        let (user, password) = self.credentials()?;
        let response = self
            .client
            .post(self.rpc_url(wallet))
            .basic_auth(user, Some(password))
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "stealth-rust",
                "method": method,
                "params": params,
            }))
            .send()
            .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?;

        if !response.status().is_success() {
            return Err(AnalysisError::EnvironmentUnavailable(format!(
                "rpc transport error: {}",
                response.status()
            )));
        }

        let envelope = response
            .json::<JsonRpcEnvelope<T>>()
            .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?;
        match (envelope.result, envelope.error) {
            (Some(result), None) => Ok(result),
            (_, Some(error)) => Err(AnalysisError::EnvironmentUnavailable(error.message)),
            _ => Err(AnalysisError::EnvironmentUnavailable(
                "rpc returned neither result nor error".into(),
            )),
        }
    }

    fn load_history_for_wallet(&self, wallet_name: &str) -> Result<WalletHistory, AnalysisError> {
        let wallet_txs = self.list_transactions(wallet_name)?;
        let utxos = self.list_unspent(wallet_name)?;
        let mut txids = wallet_txs
            .iter()
            .map(|entry| entry.txid)
            .collect::<HashSet<_>>();
        txids.extend(utxos.iter().map(|utxo| utxo.txid));

        let mut transactions = HashMap::new();
        let mut queue = txids.into_iter().collect::<Vec<_>>();
        while let Some(txid) = queue.pop() {
            if transactions.contains_key(&txid) {
                continue;
            }
            let tx = self.decode_transaction(txid)?;
            for input in &tx.vin {
                if !input.coinbase && !transactions.contains_key(&input.previous_txid) {
                    queue.push(input.previous_txid);
                }
            }
            transactions.insert(txid, tx);
        }

        Ok(WalletHistory {
            wallet_txs,
            utxos,
            transactions,
            internal_addresses: HashSet::new(),
            derived_addresses: HashSet::new(),
        })
    }

    fn list_transactions(&self, wallet_name: &str) -> Result<Vec<WalletTxEntry>, AnalysisError> {
        let entries = self.call::<Vec<ListTransactionEntry>>(
            Some(wallet_name),
            "listtransactions",
            vec![json!("*"), json!(10000), json!(0), json!(true)],
        )?;
        entries
            .into_iter()
            .map(|entry| {
                let address: Option<Address<NetworkUnchecked>> =
                    entry.address.as_deref().and_then(|s| s.parse().ok());
                Ok(WalletTxEntry {
                    txid: parse_txid(&entry.txid)?,
                    address,
                    category: match entry.category.as_deref() {
                        Some("send") => WalletTxCategory::Send,
                        Some("receive") => WalletTxCategory::Receive,
                        _ => WalletTxCategory::Unknown,
                    },
                    amount: btc_to_amount(entry.amount.abs()),
                    confirmations: entry.confirmations.unwrap_or_default(),
                    blockheight: entry.blockheight.unwrap_or_default(),
                })
            })
            .collect()
    }

    fn list_unspent(&self, wallet_name: &str) -> Result<Vec<Utxo>, AnalysisError> {
        let utxos = self.call::<Vec<ListUnspentEntry>>(
            Some(wallet_name),
            "listunspent",
            vec![json!(0), json!(9_999_999)],
        )?;
        utxos
            .into_iter()
            .map(|utxo| {
                let address: Option<Address<NetworkUnchecked>> =
                    utxo.address.as_deref().and_then(|s| s.parse().ok());
                Ok(Utxo {
                    txid: parse_txid(&utxo.txid)?,
                    vout: utxo.vout,
                    script_type: address
                        .as_ref()
                        .map(DescriptorType::infer_from_address)
                        .unwrap_or(DescriptorType::Unknown),
                    address,
                    amount: btc_to_amount(utxo.amount),
                    confirmations: utxo.confirmations.unwrap_or_default(),
                })
            })
            .collect()
    }

    fn decode_transaction(&self, txid: Txid) -> Result<DecodedTransaction, AnalysisError> {
        let tx = self.call::<RawTransaction>(
            None,
            "getrawtransaction",
            vec![json!(txid.to_string()), json!(true)],
        )?;

        Ok(DecodedTransaction {
            txid: parse_txid(&tx.txid)?,
            vin: tx
                .vin
                .into_iter()
                .map(|input| {
                    Ok(TxInputRef {
                        previous_txid: match &input.txid {
                            Some(s) => parse_txid(s)?,
                            // Bitcoin protocol: coinbase inputs reference all-zeros.
                            None => parse_txid(
                                "0000000000000000000000000000000000000000000000000000000000000000",
                            )
                            .expect("zero txid is always valid"),
                        },
                        previous_vout: input.vout.unwrap_or_default(),
                        sequence: input.sequence.unwrap_or(0xffff_ffff),
                        coinbase: input.coinbase.is_some(),
                    })
                })
                .collect::<Result<Vec<_>, AnalysisError>>()?,
            vout: tx
                .vout
                .into_iter()
                .map(|output| {
                    let address: Option<Address<NetworkUnchecked>> = output
                        .script_pub_key
                        .address
                        .or_else(|| {
                            output
                                .script_pub_key
                                .addresses
                                .and_then(|mut items| items.pop())
                        })
                        .and_then(|s| s.parse().ok());
                    TxOutput {
                        n: output.n,
                        script_type: address
                            .as_ref()
                            .map(DescriptorType::infer_from_address)
                            .or_else(|| {
                                output
                                    .script_pub_key
                                    .script_type
                                    .as_deref()
                                    .map(descriptor_type_from_script_pub_key)
                            })
                            .unwrap_or(DescriptorType::Unknown),
                        address,
                        value: btc_to_amount(output.value),
                    }
                })
                .collect(),
            version: tx.version.unwrap_or(2),
            locktime: tx.locktime.unwrap_or_default(),
            vsize: tx.vsize.unwrap_or_default(),
            confirmations: tx.confirmations.unwrap_or_default(),
        })
    }

    fn create_watch_only_wallet(&self, wallet_name: &str) -> Result<(), AnalysisError> {
        let _ = self.call::<Value>(
            None,
            "createwallet",
            vec![
                json!(wallet_name),
                json!(true),
                json!(true),
                json!(""),
                json!(false),
                json!(true),
            ],
        )?;
        Ok(())
    }

    fn unload_wallet(&self, wallet_name: &str) {
        let _ = self.call::<Value>(None, "unloadwallet", vec![json!(wallet_name)]);
    }
}

impl BlockchainGateway for BitcoinCoreRpc {
    fn normalize_descriptor(&self, descriptor: &str) -> Result<String, AnalysisError> {
        let response =
            self.call::<DescriptorInfo>(None, "getdescriptorinfo", vec![json!(descriptor)])?;
        Ok(response.descriptor)
    }

    fn derive_addresses(
        &self,
        descriptor: &ResolvedDescriptor,
    ) -> Result<Vec<Address<NetworkUnchecked>>, AnalysisError> {
        let strings: Vec<String> = self.call(
            None,
            "deriveaddresses",
            vec![json!(descriptor.desc), json!([0, descriptor.range_end])],
        )?;
        strings
            .into_iter()
            .map(|s| {
                s.parse::<Address<NetworkUnchecked>>().map_err(|e| {
                    AnalysisError::EnvironmentUnavailable(format!("invalid address '{s}': {e}"))
                })
            })
            .collect()
    }

    fn scan_descriptors(
        &self,
        descriptors: &[ResolvedDescriptor],
    ) -> Result<WalletHistory, AnalysisError> {
        let wallet_name = format!(
            "_stealth_scan_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?
                .as_millis()
        );
        self.create_watch_only_wallet(&wallet_name)?;

        // RAII guard: ensure the temporary wallet is always unloaded,
        // even if the body below returns an early error via `?`.
        let _guard = WalletGuard {
            rpc: self,
            name: &wallet_name,
        };

        let imports = descriptors
            .iter()
            .map(|descriptor| {
                let is_ranged = descriptor.desc.contains('*');
                let mut entry = json!({
                    "desc": descriptor.desc,
                    "timestamp": 0,
                    "internal": descriptor.internal,
                    "active": is_ranged && descriptor.active,
                });
                if is_ranged {
                    entry["range"] = json!([0, descriptor.range_end]);
                }
                entry
            })
            .collect::<Vec<_>>();

        let import_results = self.call::<Vec<ImportResult>>(
            Some(&wallet_name),
            "importdescriptors",
            vec![json!(imports)],
        )?;
        if import_results.iter().any(|result| !result.success) {
            let errors: Vec<_> = import_results
                .iter()
                .filter(|r| !r.success)
                .filter_map(|r| r.error.as_ref().map(|e| e.message.as_str()))
                .collect();
            return Err(AnalysisError::EnvironmentUnavailable(format!(
                "descriptor import failed: {}",
                errors.join("; ")
            )));
        }

        let mut history = self.load_history_for_wallet(&wallet_name)?;

        // Derive all addresses from every descriptor
        let mut internal_addresses = HashSet::new();
        let mut derived_addresses = HashSet::new();
        for desc in descriptors {
            if let Ok(addrs) = self.derive_addresses(desc) {
                if desc.internal {
                    internal_addresses.extend(addrs.iter().cloned());
                }
                derived_addresses.extend(addrs);
            }
        }
        history.internal_addresses = internal_addresses;
        history.derived_addresses = derived_addresses;

        Ok(history)
    }

    fn list_wallet_descriptors(
        &self,
        wallet_name: &str,
    ) -> Result<Vec<ResolvedDescriptor>, AnalysisError> {
        let response =
            self.call::<ListDescriptorsResponse>(Some(wallet_name), "listdescriptors", Vec::new())?;
        Ok(response
            .descriptors
            .into_iter()
            .map(|descriptor| ResolvedDescriptor {
                desc: descriptor.desc,
                internal: descriptor.internal.unwrap_or(false),
                active: descriptor.active.unwrap_or(true),
                range_end: descriptor
                    .range
                    .map(|range| match range {
                        DescriptorRange::Single(value) => value,
                        DescriptorRange::Pair([_, end]) => end,
                    })
                    .unwrap_or(999),
            })
            .collect())
    }

    fn scan_wallet(&self, wallet_name: &str) -> Result<WalletHistory, AnalysisError> {
        let mut history = self.load_history_for_wallet(wallet_name)?;

        // Derive ALL addresses from every descriptor (both external and
        // internal chains) so that `is_ours()` in TxGraph recognises
        // every derived address — matching the Python reference which
        // calls `derive_all_addresses(descriptors)` before building the
        // TxGraph.
        if let Ok(descriptors) = self.list_wallet_descriptors(wallet_name) {
            let mut internal_addresses = HashSet::new();
            let mut derived_addresses = HashSet::new();
            for desc in &descriptors {
                if let Ok(addrs) = self.derive_addresses(desc) {
                    if desc.internal {
                        internal_addresses.extend(addrs.iter().cloned());
                    }
                    derived_addresses.extend(addrs);
                }
            }
            history.internal_addresses = internal_addresses;
            history.derived_addresses = derived_addresses;
        }

        Ok(history)
    }

    fn known_wallet_txids(&self, wallet_names: &[String]) -> Result<HashSet<Txid>, AnalysisError> {
        let mut txids = HashSet::new();
        for wallet_name in wallet_names {
            txids.extend(
                self.list_transactions(wallet_name)?
                    .into_iter()
                    .map(|entry| entry.txid),
            );
        }
        Ok(txids)
    }

    fn get_transaction(&self, txid: Txid) -> Result<DecodedTransaction, AnalysisError> {
        self.decode_transaction(txid)
    }
}

/// RAII guard that calls `unloadwallet` when dropped, ensuring cleanup
/// even when an early `?` return skips the normal unload path.
struct WalletGuard<'a> {
    rpc: &'a BitcoinCoreRpc,
    name: &'a str,
}

impl Drop for WalletGuard<'_> {
    fn drop(&mut self) {
        self.rpc.unload_wallet(self.name);
    }
}

fn parse_txid(s: &str) -> Result<Txid, AnalysisError> {
    s.parse::<Txid>()
        .map_err(|e| AnalysisError::EnvironmentUnavailable(format!("invalid txid '{s}': {e}")))
}

fn default_rpc_port(network: &str) -> u16 {
    match network {
        "mainnet" => 8332,
        "testnet" => 18332,
        "signet" => 38332,
        _ => 18443,
    }
}

fn descriptor_type_from_script_pub_key(script_type: &str) -> DescriptorType {
    match script_type {
        "witness_v0_keyhash" => DescriptorType::P2wpkh,
        "witness_v1_taproot" => DescriptorType::P2tr,
        "scripthash" => DescriptorType::P2sh,
        "pubkeyhash" => DescriptorType::P2pkh,
        _ => DescriptorType::Unknown,
    }
}

fn parse_host_port_from_url(url: &str) -> (String, u16) {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    match authority.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().unwrap_or(8332);
            (host.to_owned(), port)
        }
        None => (authority.to_owned(), 8332),
    }
}

fn infer_network_from_port(port: u16) -> String {
    match port {
        8332 => "mainnet",
        18332 => "testnet",
        38332 => "signet",
        18443 => "regtest",
        _ => "regtest",
    }
    .to_owned()
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct DescriptorInfo {
    descriptor: String,
}

#[derive(Debug, Deserialize)]
struct ImportResult {
    success: bool,
    #[serde(default)]
    error: Option<ImportError>,
}

#[derive(Debug, Deserialize)]
struct ImportError {
    #[serde(default)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct ListDescriptorsResponse {
    descriptors: Vec<DescriptorRecord>,
}

#[derive(Debug, Deserialize)]
struct DescriptorRecord {
    desc: String,
    internal: Option<bool>,
    active: Option<bool>,
    range: Option<DescriptorRange>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DescriptorRange {
    Single(u32),
    Pair([u32; 2]),
}

#[derive(Debug, Deserialize)]
struct ListTransactionEntry {
    txid: String,
    address: Option<String>,
    category: Option<String>,
    amount: f64,
    confirmations: Option<u32>,
    blockheight: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ListUnspentEntry {
    txid: String,
    vout: u32,
    address: Option<String>,
    amount: f64,
    confirmations: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawTransaction {
    txid: String,
    vin: Vec<RawVin>,
    vout: Vec<RawVout>,
    version: Option<i32>,
    locktime: Option<u32>,
    vsize: Option<u32>,
    confirmations: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawVin {
    txid: Option<String>,
    vout: Option<u32>,
    coinbase: Option<String>,
    sequence: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawVout {
    value: f64,
    n: u32,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: RawScriptPubKey,
}

#[derive(Debug, Deserialize)]
struct RawScriptPubKey {
    address: Option<String>,
    addresses: Option<Vec<String>>,
    #[serde(rename = "type")]
    script_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::default_rpc_port;

    #[test]
    fn network_defaults_match_bitcoin_core_ports() {
        assert_eq!(default_rpc_port("regtest"), 18443);
        assert_eq!(default_rpc_port("testnet"), 18332);
        assert_eq!(default_rpc_port("signet"), 38332);
        assert_eq!(default_rpc_port("mainnet"), 8332);
    }
}
