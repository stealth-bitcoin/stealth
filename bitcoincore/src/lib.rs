use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use ini::Ini;
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use stealth_model::config::AnalysisConfig;
use stealth_model::error::AnalysisError;
use stealth_model::gateway::{
    BlockchainGateway, DecodedTransaction, DescriptorType, ResolvedDescriptor, TxFetchResults,
    TxInputRef, TxOutput, Utxo, WalletHistory, WalletTxCategory, WalletTxEntry,
};
use stealth_model::progress::{ScanPhase, ScanProgress};
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
    max_ancestor_depth: u32,
    tx_page_size: usize,
    // Progress sinks keyed by installing thread: a scan runs synchronously
    // on the thread that installed its sink, so concurrent scans through a
    // shared gateway never observe each other's sink.
    progress_sinks: Mutex<HashMap<ThreadId, ScanProgress>>,
}

impl BitcoinCoreRpc {
    pub fn new(config: BitcoinCoreConfig) -> Result<Self, AnalysisError> {
        // No timeout: descriptor imports block on Core's synchronous rescan.
        let client = Client::builder()
            .timeout(None)
            .build()
            .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?;
        Ok(Self {
            config,
            client,
            max_ancestor_depth: AnalysisConfig::default().max_ancestor_depth,
            tx_page_size: DEFAULT_TX_PAGE_SIZE,
            progress_sinks: Mutex::new(HashMap::new()),
        })
    }

    pub fn with_max_ancestor_depth(mut self, depth: u32) -> Self {
        self.max_ancestor_depth = depth;
        self
    }

    pub fn with_tx_page_size(mut self, size: usize) -> Self {
        self.tx_page_size = size;
        self
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

    fn call_batch<T: DeserializeOwned>(
        &self,
        method: &str,
        params_list: &[Vec<Value>],
    ) -> Result<Vec<Result<T, AnalysisError>>, AnalysisError> {
        let (user, password) = self.credentials()?;
        let batch: Vec<Value> = params_list
            .iter()
            .enumerate()
            .map(|(id, params)| {
                json!({ "jsonrpc": "1.0", "id": id, "method": method, "params": params })
            })
            .collect();
        let response = self
            .client
            .post(self.rpc_url(None))
            .basic_auth(user, Some(password))
            .json(&batch)
            .send()
            .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?;

        if !response.status().is_success() {
            return Err(AnalysisError::EnvironmentUnavailable(format!(
                "rpc transport error: {}",
                response.status()
            )));
        }

        let mut envelopes = response
            .json::<Vec<JsonRpcBatchEnvelope<T>>>()
            .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?;
        if envelopes.len() != params_list.len() {
            return Err(AnalysisError::EnvironmentUnavailable(format!(
                "rpc batch returned {} responses for {} requests",
                envelopes.len(),
                params_list.len()
            )));
        }
        envelopes.sort_by_key(|envelope| envelope.id);
        Ok(envelopes
            .into_iter()
            .map(|envelope| match (envelope.result, envelope.error) {
                (Some(result), None) => Ok(result),
                (_, Some(error)) => Err(AnalysisError::EnvironmentUnavailable(error.message)),
                _ => Err(AnalysisError::EnvironmentUnavailable(
                    "rpc returned neither result nor error".into(),
                )),
            })
            .collect())
    }

    fn decode_transactions(&self, txids: &[Txid]) -> Result<TxFetchResults, AnalysisError> {
        let mut out = Vec::with_capacity(txids.len());
        for chunk in txids.chunks(RPC_BATCH_SIZE) {
            let params: Vec<Vec<Value>> = chunk
                .iter()
                .map(|txid| vec![json!(txid.to_string()), json!(true)])
                .collect();
            let results = self.call_batch::<RawTransaction>("getrawtransaction", &params)?;
            for (txid, result) in chunk.iter().zip(results) {
                out.push((*txid, result.and_then(Self::convert_raw_transaction)));
            }
        }
        Ok(out)
    }

    fn load_history_for_wallet(&self, wallet_name: &str) -> Result<WalletHistory, AnalysisError> {
        let wallet_txs = self.list_transactions(wallet_name)?;
        let utxos = self.list_unspent(wallet_name)?;
        let mut txids = wallet_txs
            .iter()
            .map(|entry| entry.txid)
            .collect::<HashSet<_>>();
        txids.extend(utxos.iter().map(|utxo| utxo.txid));

        // Level-order, batched, bounded by max_ancestor_depth (depth 0 is
        // the wallet's own transactions; those must resolve, ancestors may
        // be skipped on error).
        let mut transactions = HashMap::new();
        let mut frontier: Vec<Txid> = txids.into_iter().collect();
        let mut depth = 0u32;
        loop {
            frontier.retain(|txid| !transactions.contains_key(txid));
            if frontier.is_empty() {
                break;
            }
            let mut next = HashSet::new();
            for (txid, fetched) in self.decode_transactions(&frontier)? {
                let tx = match fetched {
                    Ok(tx) => tx,
                    Err(error) if depth == 0 => return Err(error),
                    Err(_) => continue,
                };
                if depth < self.max_ancestor_depth {
                    for input in tx.vin.iter().filter(|input| !input.coinbase) {
                        next.insert(input.previous_txid);
                    }
                }
                transactions.insert(txid, tx);
            }
            if depth >= self.max_ancestor_depth {
                break;
            }
            frontier = next.into_iter().collect();
            depth += 1;
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
        // A block landing mid-pagination shifts the skip windows; refetch once.
        let tip = self.block_count()?;
        let mut entries = self.fetch_transaction_pages(wallet_name)?;
        if self.block_count()? != tip {
            entries = self.fetch_transaction_pages(wallet_name)?;
        }
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

    fn fetch_transaction_pages(
        &self,
        wallet_name: &str,
    ) -> Result<Vec<ListTransactionEntry>, AnalysisError> {
        // A page size of 0 would never terminate the loop.
        let page_size = self.tx_page_size.max(1);
        let mut pages = Vec::new();
        let mut skip = 0usize;
        loop {
            let page = self.call::<Vec<ListTransactionEntry>>(
                Some(wallet_name),
                "listtransactions",
                vec![json!("*"), json!(page_size), json!(skip), json!(true)],
            )?;
            let page_len = page.len();
            pages.push(page);
            if page_len < page_size {
                break;
            }
            skip += page_len;
        }
        // skip walks newest-to-oldest; reverse to keep global oldest-first order.
        pages.reverse();
        Ok(pages.into_iter().flatten().collect())
    }

    fn block_count(&self) -> Result<u64, AnalysisError> {
        self.call::<u64>(None, "getblockcount", Vec::new())
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
        Self::convert_raw_transaction(tx)
    }

    fn convert_raw_transaction(tx: RawTransaction) -> Result<DecodedTransaction, AnalysisError> {
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

    // unloadwallet fails while a rescan is running, so the guard aborts first.
    fn abort_rescan(&self, wallet_name: &str) {
        let _ = self.call::<Value>(Some(wallet_name), "abortrescan", Vec::new());
    }

    // Take-on-use keeps the per-thread map self-cleaning.
    fn take_progress_sink(&self) -> Option<ScanProgress> {
        self.progress_sinks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&thread::current().id())
    }
}

/// Background thread that polls `getwalletinfo` on the temporary scan
/// wallet while `importdescriptors` blocks on Core's synchronous rescan,
/// forwarding `scanning.progress` into the sink. It also honours a
/// cancellation request on the sink by issuing `abortrescan` once.
/// Dropping the poller stops the thread.
struct RescanPoller {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RescanPoller {
    const POLL_INTERVAL: Duration = Duration::from_millis(250);
    const POLLS_PER_FETCH: u32 = 4;

    fn start(rpc: &BitcoinCoreRpc, wallet_name: &str, sink: ScanProgress) -> Option<Self> {
        let (user, password) = rpc.credentials().ok()?;
        let client = rpc.client.clone();
        let url = rpc.rpc_url(Some(wallet_name));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_signal = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let mut abort_sent = false;
            let mut ticks = 0u32;
            while !stop_signal.load(Ordering::Relaxed) {
                if sink.cancel_requested() && !abort_sent {
                    abort_sent = true;
                    let _ = rpc_call_raw(&client, &url, &user, &password, "abortrescan");
                }
                // ~1s between getwalletinfo fetches, in short sleeps so a
                // finished import releases this thread quickly.
                if ticks.is_multiple_of(Self::POLLS_PER_FETCH) {
                    if let Some(progress) = fetch_scanning_progress(&client, &url, &user, &password)
                    {
                        sink.set_rescan_progress(progress);
                    }
                }
                ticks = ticks.wrapping_add(1);
                thread::sleep(Self::POLL_INTERVAL);
            }
        });

        Some(Self {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for RescanPoller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn rpc_call_raw(
    client: &Client,
    url: &str,
    user: &str,
    password: &str,
    method: &str,
) -> Option<Value> {
    let response = client
        .post(url)
        .basic_auth(user, Some(password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "stealth-progress",
            "method": method,
            "params": [],
        }))
        .send()
        .ok()?;
    response.json::<Value>().ok()
}

// `getwalletinfo.scanning` is `false` when idle or
// `{ "duration": .., "progress": .. }` during a rescan.
fn fetch_scanning_progress(client: &Client, url: &str, user: &str, password: &str) -> Option<f32> {
    let envelope = rpc_call_raw(client, url, user, password, "getwalletinfo")?;
    envelope["result"]["scanning"]["progress"]
        .as_f64()
        .map(|progress| progress as f32)
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
        // Core rejects a range argument for un-ranged descriptors.
        let mut params = vec![json!(descriptor.desc)];
        if descriptor.desc.contains('*') {
            params.push(json!([0, descriptor.range_end]));
        }
        let strings: Vec<String> = self.call(None, "deriveaddresses", params)?;
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
        let sink = self.take_progress_sink();
        let wallet_name = scan_wallet_name(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| AnalysisError::EnvironmentUnavailable(error.to_string()))?
                .as_millis(),
        );
        self.create_watch_only_wallet(&wallet_name)?;

        // RAII guard: ensure the temporary wallet is always unloaded,
        // even if the body below returns an early error via `?`.
        let _guard = WalletGuard {
            rpc: self,
            name: &wallet_name,
        };

        if let Some(sink) = &sink {
            sink.set_wallet_name(&wallet_name);
        }

        let imports = descriptors
            .iter()
            .map(|descriptor| {
                let is_ranged = descriptor.desc.contains('*');
                let mut entry = json!({
                    "desc": descriptor.desc,
                    "timestamp": descriptor.rescan_since.unwrap_or(0),
                    "internal": descriptor.internal,
                    "active": is_ranged && descriptor.active,
                });
                if is_ranged {
                    entry["range"] = json!([0, descriptor.range_end]);
                }
                entry
            })
            .collect::<Vec<_>>();

        let import_results = {
            let _poller = sink.as_ref().and_then(|sink| {
                sink.set_phase(ScanPhase::Rescanning);
                RescanPoller::start(self, &wallet_name, sink.clone())
            });
            self.call::<Vec<ImportResult>>(
                Some(&wallet_name),
                "importdescriptors",
                vec![json!(imports)],
            )?
        };
        if let Some(sink) = &sink {
            sink.set_phase(ScanPhase::LoadingHistory);
        }
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
            let addrs = self.derive_addresses(desc)?;
            if desc.internal {
                internal_addresses.extend(addrs.iter().cloned());
            }
            derived_addresses.extend(addrs);
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
                rescan_since: None,
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
        // every derived address.
        let descriptors = self.list_wallet_descriptors(wallet_name)?;
        let mut internal_addresses = HashSet::new();
        let mut derived_addresses = HashSet::new();
        for desc in &descriptors {
            let addrs = self.derive_addresses(desc)?;
            if desc.internal {
                internal_addresses.extend(addrs.iter().cloned());
            }
            derived_addresses.extend(addrs);
        }
        history.internal_addresses = internal_addresses;
        history.derived_addresses = derived_addresses;

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

    fn get_transactions(&self, txids: &[Txid]) -> Result<TxFetchResults, AnalysisError> {
        self.decode_transactions(txids)
    }

    fn set_progress_sink(&self, sink: ScanProgress) {
        self.progress_sinks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(thread::current().id(), sink);
    }

    fn cancel_rescan(&self, wallet_name: &str) {
        self.abort_rescan(wallet_name);
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
        self.rpc.abort_rescan(self.name);
        self.rpc.unload_wallet(self.name);
    }
}

// The pid disambiguates CLI and API scans hitting the same node.
fn scan_wallet_name(timestamp_millis: u128) -> String {
    static SCAN_WALLET_COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = SCAN_WALLET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("_stealth_scan_{timestamp_millis}_{pid}_{sequence}")
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

const RPC_BATCH_SIZE: usize = 100;
const DEFAULT_TX_PAGE_SIZE: usize = 1000;

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcBatchEnvelope<T> {
    id: u64,
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
    use super::{default_rpc_port, scan_wallet_name};

    #[test]
    fn network_defaults_match_bitcoin_core_ports() {
        assert_eq!(default_rpc_port("regtest"), 18443);
        assert_eq!(default_rpc_port("testnet"), 18332);
        assert_eq!(default_rpc_port("signet"), 38332);
        assert_eq!(default_rpc_port("mainnet"), 8332);
    }

    #[test]
    fn scan_wallet_names_differ_for_same_timestamp() {
        let first = scan_wallet_name(1_700_000_000_000);
        let second = scan_wallet_name(1_700_000_000_000);
        let pid = std::process::id();
        assert!(
            first.starts_with(&format!("_stealth_scan_1700000000000_{pid}_")),
            "name must embed the process id to avoid cross-process collisions, got: {first}"
        );
        assert_ne!(
            first, second,
            "concurrent scans in the same millisecond must not collide"
        );
    }
}
