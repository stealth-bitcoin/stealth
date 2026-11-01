use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::{env, fs, thread};

use stealth_bitcoincore::{read_cookie_file, BitcoinCoreRpc, RpcAuth};
use stealth_engine::engine::{
    AnalysisEngine, AskToGoOn, EngineSettings, HistoryLimit, ScanTarget, UtxoInput,
    DEFAULT_MAX_WALLET_TXS,
};
use stealth_engine::error::{AnalysisError, HistoryOf};
use stealth_engine::types::{Finding, Summary};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return ExitCode::SUCCESS;
    }

    if args[0] != "scan" {
        eprintln!(
            "error: unknown command '{}' (try 'stealth-cli --help')",
            args[0]
        );
        return ExitCode::from(2);
    }

    match run_scan(&args[1..]) {
        Ok(clean) => {
            if clean {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_scan(args: &[String]) -> Result<bool, String> {
    let opts = parse_scan_args(args)?;
    let gateway = opts.build_gateway()?;
    let target = opts.scan_target()?;

    // Ctrl-C at the question answers no; an inherited SIG_IGN stays and means no question.
    let interrupts = Arc::new(Interrupts::default());
    let handler = Arc::clone(&interrupts);
    let interruptible = install_interrupt_handler(sigint_ignored(), move || {
        ctrlc::set_handler(move || {
            if handler.interrupt() {
                die_by_interrupt();
            }
        })
        .is_ok()
    });

    let ask = should_ask(
        io::stdin().is_terminal(),
        io::stderr().is_terminal(),
        interruptible,
    )
    .then(|| {
        terminal_ask(
            || io::stdin().lock(),
            io::stderr,
            Arc::clone(&interrupts),
            in_the_foreground,
            discard_typed_ahead,
        )
    });
    let mut settings = opts.engine_settings()?;
    settings.history_limit = opts.history_limit(ask);
    let engine = AnalysisEngine::new(&gateway, settings);
    let report = match engine.analyze(target) {
        Ok(report) => report,
        // The wallet is unloaded by now; dying by the signal stops an enclosing shell loop.
        Err(error) if interrupts.answered_the_question() => {
            eprintln!("error: {}", scan_error(error));
            die_by_interrupt();
        }
        Err(error) => return Err(scan_error(error)),
    };

    match opts.format.as_deref() {
        Some("text") | None => print_text_report(&report),
        Some("json") => {
            let json = serde_json::to_string_pretty(&report)
                .map_err(|e| format!("serialization failed: {e}"))?;
            println!("{json}");
        }
        Some(other) => return Err(format!("unsupported format '{other}' (use json or text)")),
    }

    Ok(scan_succeeded(&report.summary))
}

/// The CLI reads its outputs from a file; "pasted" is the web and API's word.
const UTXO_FILE_HISTORY: &str = "the history of the addresses of the outputs in the UTXO file";

/// A stop at the history limit says how to scan anyway.
fn scan_error(error: AnalysisError) -> String {
    match error {
        AnalysisError::HistoryTooLarge {
            of,
            tx_count,
            limit,
        } => {
            let whose = match of {
                HistoryOf::Wallet => "this scan's history",
                HistoryOf::PastedAddresses => UTXO_FILE_HISTORY,
            };
            format!(
                "{whose} holds {tx_count} transactions, more than the limit of {limit}; \
                 loading it can take long and put a heavy load on the node; to scan it \
                 anyway, pass --no-limits, or --max-txs with at least {tx_count}, higher if \
                 the history may grow"
            )
        }
        other => other.to_string(),
    }
}

/// Ends the process by SIGINT, as an unhandled Ctrl-C would, so a shell sees
/// the signal (bash stops a loop only then); elsewhere it exits with 130.
fn die_by_interrupt() -> ! {
    #[cfg(unix)]
    {
        use nix::sys::signal::{raise, signal, SigHandler, Signal};
        // SAFETY: SIG_DFL installs no handler code, so nothing runs in signal context.
        let _ = unsafe { signal(Signal::SIGINT, SigHandler::SigDfl) };
        let _ = raise(Signal::SIGINT);
    }
    std::process::exit(130)
}

/// Installs the Ctrl-C handler unless SIGINT was ignored; says whether one is in place.
fn install_interrupt_handler(sigint_ignored: bool, install: impl FnOnce() -> bool) -> bool {
    !sigint_ignored && install()
}

/// The question is asked only where someone can both read it and answer it,
/// with Ctrl-C there to answer no.
fn should_ask(stdin_is_terminal: bool, stderr_is_terminal: bool, interruptible: bool) -> bool {
    stdin_is_terminal && stderr_is_terminal && interruptible
}

/// Whether SIGINT was ignored when the process started.
#[cfg(unix)]
fn sigint_ignored() -> bool {
    // nix only swaps a disposition; libc reads it without changing it.
    let mut current = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
    // SAFETY: a null new action makes sigaction only write the current one.
    let read = unsafe { libc::sigaction(libc::SIGINT, std::ptr::null(), current.as_mut_ptr()) };
    // SAFETY: zeroed is a valid sigaction, filled in by the call when it succeeds.
    read == 0 && unsafe { current.assume_init() }.sa_sigaction == libc::SIG_IGN
}

#[cfg(not(unix))]
fn sigint_ignored() -> bool {
    false
}

/// Whether this process is the terminal's foreground job; without a
/// controlling terminal it is not.
#[cfg(unix)]
fn in_the_foreground() -> bool {
    use nix::unistd::{getpgrp, tcgetpgrp};
    tcgetpgrp(io::stdin()).is_ok_and(|foreground| foreground == getpgrp())
}

#[cfg(not(unix))]
fn in_the_foreground() -> bool {
    true
}

/// Drops what was typed on the terminal and not read yet.
#[cfg(unix)]
fn discard_typed_ahead() {
    use nix::sys::termios::{tcflush, FlushArg};
    let _ = tcflush(io::stdin(), FlushArg::TCIFLUSH);
}

#[cfg(not(unix))]
fn discard_typed_ahead() {}

/// Asks on `output` whether to load a history above the limit.
fn show_question(of: HistoryOf, tx_count: u64, limit: u64, output: &mut impl Write) {
    let whose = match of {
        HistoryOf::Wallet => "This scan's history",
        HistoryOf::PastedAddresses => {
            "The history of the addresses of the outputs in the UTXO file"
        }
    };
    let _ = write!(
        output,
        "{whose} holds {tx_count} transactions, more than the limit of {limit}. \
         Loading it can take long and put a heavy load on the node. Go on? [y/N] "
    );
    let _ = output.flush();
}

/// Only a yes goes on.
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

enum Reply {
    Answered { go_on: bool, line_ended: bool },
    Interrupted,
}

/// Where the scan is, for Ctrl-C.
#[derive(Debug, Default)]
enum Moment {
    #[default]
    Scanning,
    Asking(mpsc::Sender<Reply>),
}

/// Ctrl-C answers no while the question waits, else exits; the first of answer and interrupt wins.
#[derive(Debug, Default)]
struct Interrupts {
    moment: Mutex<Moment>,
    answered_no: AtomicBool,
}

impl Interrupts {
    /// Whether the process should exit now.
    fn interrupt(&self) -> bool {
        let mut moment = self.moment();
        match std::mem::take(&mut *moment) {
            Moment::Asking(reply) => {
                // Stored before the reply, so whoever reads the reply sees it.
                self.answered_no.store(true, Ordering::Release);
                let _ = reply.send(Reply::Interrupted);
                false
            }
            Moment::Scanning => true,
        }
    }

    /// Whether a Ctrl-C answered the question.
    fn answered_the_question(&self) -> bool {
        self.answered_no.load(Ordering::Acquire)
    }

    fn begin_asking(&self, reply: mpsc::Sender<Reply>) {
        *self.moment() = Moment::Asking(reply);
    }

    /// Takes the question for the typed answer, unless an interrupt answered
    /// first; says whether it did.
    fn answer(&self) -> bool {
        matches!(std::mem::take(&mut *self.moment()), Moment::Asking(_))
    }

    #[cfg(test)]
    fn waiting_for_an_answer(&self) -> bool {
        matches!(*self.moment(), Moment::Asking(_))
    }

    fn moment(&self) -> MutexGuard<'_, Moment> {
        self.moment
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// An asker that writes the question to `output()` and reads the answer from
/// `input()`, or takes an interrupt as a no.
fn terminal_ask<R: BufRead, W: Write>(
    input: impl Fn() -> R + Send + Sync + 'static,
    output: impl Fn() -> W + Send + Sync + 'static,
    interrupts: Arc<Interrupts>,
    in_the_foreground: impl Fn() -> bool + Send + Sync + 'static,
    discard_typed_ahead: impl Fn() + Send + Sync + 'static,
) -> AskToGoOn {
    let input = Arc::new(input);
    Arc::new(move |of, tx_count, limit| {
        // Checked after the rescan: a background job reading the terminal gets SIGTTIN.
        if !in_the_foreground() {
            return false;
        }
        // Keys pressed during the long rescan must not answer a question not yet asked.
        discard_typed_ahead();
        let (reply, answer) = mpsc::channel();
        interrupts.begin_asking(reply.clone());
        show_question(of, tx_count, limit, &mut output());
        let (input, reader) = (Arc::clone(&input), Arc::clone(&interrupts));
        // Read apart so an interrupt can answer instead; a read left blocked ends with the process.
        thread::spawn(move || {
            let mut line = String::new();
            let _ = input().read_line(&mut line);
            let go_on = is_yes(&line);
            if reader.answer() {
                let line_ended = line.ends_with('\n');
                let _ = reply.send(Reply::Answered { go_on, line_ended });
            }
        });
        let (go_on, line_ended) = match answer.recv() {
            Ok(Reply::Answered { go_on, line_ended }) => (go_on, line_ended),
            _ => (false, false),
        };
        // A Ctrl-C or Ctrl-D ends no line, so the error would follow the question.
        if !line_ended {
            let _ = writeln!(output());
        }
        go_on
    })
}

/// Nothing was analyzed and nothing was reported. Findings alongside zero
/// analyzed transactions would make the empty-scan notice a contradiction, so
/// the findings take precedence.
fn is_empty_report(summary: &Summary) -> bool {
    summary.analyzed_nothing && summary.findings == 0 && summary.warnings == 0
}

/// Exit 0 only when there is nothing to report: a clean history, or a scan
/// that analyzed nothing and found nothing.
fn scan_succeeded(summary: &Summary) -> bool {
    if summary.findings > 0 || summary.warnings > 0 {
        return false;
    }
    summary.clean || summary.analyzed_nothing
}

/// Worst first; the engine's order within one severity.
fn by_severity(list: &[Finding]) -> Vec<&Finding> {
    let mut sorted: Vec<&Finding> = list.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
    sorted
}

// Explicit user/pass wins; a cookie goes to the gateway as a path.
fn select_rpc_auth(
    user: Option<String>,
    pass: Option<String>,
    cookie: Option<PathBuf>,
) -> Result<RpcAuth, String> {
    match (user, pass, cookie) {
        (Some(user), Some(pass), _) => Ok(RpcAuth::UserPass(user, pass)),
        (_, _, Some(cookie_path)) => {
            // Fail up front on an unreadable cookie; the gateway reads its own copy.
            read_cookie_file(&cookie_path).map_err(|e| e.to_string())?;
            Ok(RpcAuth::CookieFile(cookie_path))
        }
        _ => Ok(RpcAuth::None),
    }
}

#[derive(Debug, Default)]
struct ScanOpts {
    descriptor: Option<String>,
    descriptors_file: Option<PathBuf>,
    utxos_file: Option<PathBuf>,
    rpc_url: Option<String>,
    rpc_user: Option<String>,
    rpc_cookie: Option<PathBuf>,
    format: Option<String>,
    cache_wallet: bool,
    max_txs: Option<u64>,
    no_limits: bool,
}

impl ScanOpts {
    fn build_gateway(&self) -> Result<BitcoinCoreRpc, String> {
        let url = self
            .rpc_url
            .clone()
            .or_else(|| env::var("STEALTH_RPC_URL").ok())
            .ok_or("--rpc-url or STEALTH_RPC_URL is required")?;

        let auth = select_rpc_auth(
            self.rpc_user
                .clone()
                .or_else(|| env::var("STEALTH_RPC_USER").ok()),
            env::var("STEALTH_RPC_PASS").ok(),
            self.rpc_cookie
                .clone()
                .or_else(|| env::var_os("STEALTH_RPC_COOKIE").map(PathBuf::from)),
        )?;
        BitcoinCoreRpc::from_url_auth(&url, auth).map_err(|e| e.to_string())
    }

    fn scan_target(&self) -> Result<ScanTarget, String> {
        if self.descriptor.is_some()
            && (self.descriptors_file.is_some() || self.utxos_file.is_some())
        {
            return Err("--descriptor cannot be combined with other inputs".to_owned());
        }

        // --utxos may be combined with --descriptors: the descriptors act
        // as ownership context so the scan recognises the user's inputs.
        if let Some(path) = &self.utxos_file {
            let utxos: Vec<UtxoInput> = read_json(path)?;
            return Ok(ScanTarget::Utxos(utxos));
        }
        if let Some(path) = &self.descriptors_file {
            let descriptors: Vec<String> = read_json(path)?;
            return Ok(ScanTarget::Descriptors(descriptors));
        }
        if let Some(d) = &self.descriptor {
            return Ok(ScanTarget::Descriptor(d.clone()));
        }

        Err("one input is required: --descriptor, --descriptors, or --utxos".to_owned())
    }

    fn engine_settings(&self) -> Result<EngineSettings, String> {
        Ok(EngineSettings {
            ownership_descriptors: self.ownership_descriptors()?,
            persist_scan_wallet: self.cache_wallet,
            history_limit: self.history_limit(None),
            ..EngineSettings::default()
        })
    }

    /// In a terminal a history above the limit is asked about; elsewhere it stops the scan.
    /// `ask` decides above the limit; without it the scan stops there.
    fn history_limit(&self, ask: Option<AskToGoOn>) -> HistoryLimit {
        if self.no_limits {
            return HistoryLimit::unlimited();
        }
        HistoryLimit {
            ask,
            ..HistoryLimit::at_most(self.max_txs.unwrap_or(DEFAULT_MAX_WALLET_TXS))
        }
    }

    fn ownership_descriptors(&self) -> Result<Vec<String>, String> {
        match (&self.utxos_file, &self.descriptors_file) {
            (Some(_), Some(path)) => read_json(path),
            _ => Ok(Vec::new()),
        }
    }
}

fn parse_scan_args(args: &[String]) -> Result<ScanOpts, String> {
    let mut opts = ScanOpts::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--descriptor" => {
                opts.descriptor = Some(take_value(args, &mut i, "--descriptor")?);
            }
            "--descriptors" => {
                opts.descriptors_file =
                    Some(PathBuf::from(take_value(args, &mut i, "--descriptors")?));
            }
            "--utxos" => {
                opts.utxos_file = Some(PathBuf::from(take_value(args, &mut i, "--utxos")?));
            }
            "--rpc-url" => {
                opts.rpc_url = Some(take_value(args, &mut i, "--rpc-url")?);
            }
            "--rpc-user" => {
                opts.rpc_user = Some(take_value(args, &mut i, "--rpc-user")?);
            }
            "--rpc-cookie" => {
                opts.rpc_cookie = Some(PathBuf::from(take_value(args, &mut i, "--rpc-cookie")?));
            }
            "--format" => {
                opts.format = Some(take_value(args, &mut i, "--format")?);
            }
            "--cache-wallet" => {
                opts.cache_wallet = true;
            }
            "--max-txs" => {
                let value = take_value(args, &mut i, "--max-txs")?;
                let max_txs = value
                    .parse()
                    .map_err(|_| format!("--max-txs takes a whole number, not '{value}'"))?;
                opts.max_txs = Some(max_txs);
            }
            "--no-limits" => {
                opts.no_limits = true;
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
        i += 1;
    }

    if opts.max_txs.is_some() && opts.no_limits {
        return Err("--max-txs cannot be combined with --no-limits".to_owned());
    }
    Ok(opts)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("invalid JSON in {}: {e}", path.display()))
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    let value = args
        .get(*i)
        .ok_or_else(|| format!("{flag} requires a value"))?;

    if value.starts_with('-') {
        return Err(format!("{flag} requires a value"));
    }

    Ok(value.clone())
}

fn print_text_report(report: &stealth_engine::Report) {
    print!("{}", text_report(report));
}

fn text_report(report: &stealth_engine::Report) -> String {
    let mut lines = vec![format!(
        "Scanned {} transactions, {} addresses, {} current UTXOs\n",
        report.stats.transactions_analyzed, report.stats.addresses_seen, report.stats.utxos_current,
    )];

    let unserved = report.stats.addresses_without_history;
    if unserved > 0 {
        lines.push(format!(
            "The node could not serve the chain history of {unserved} address{}; \
             the counts for {} cover only the outputs you pasted.\n",
            if unserved == 1 { "" } else { "es" },
            if unserved == 1 { "it" } else { "them" },
        ));
    }

    let stats = &report.stats;
    let conflicted: Vec<String> = stats
        .conflicted_txids
        .iter()
        .map(ToString::to_string)
        .collect();
    left_out_note(
        &mut lines,
        &conflicted,
        &LeftOutReason {
            settled: true,
            one: "Core reports as conflicted: it, or a transaction it depends on, conflicts \
                  with another one",
            many: "Core reports as conflicted: each, or a transaction it depends on, conflicts \
                   with another one",
            before_one: Some("it became conflicted"),
            if_broadcast: true,
            before_many: Some("they became conflicted"),
            unless_one: None,
            unless_many: None,
            comes_back_one: Some("It can only come back if a reorg removes the conflicting block"),
            comes_back_many: Some(
                "They can only come back if a reorg removes the block or blocks holding the conflicting transactions",
            ),
        },
    );
    let in_mempool_conflict: Vec<String> = stats
        .mempool_conflicted_txids
        .iter()
        .map(|r| {
            format!(
                "{}: it, or a transaction it depends on, conflicts with {}, which is in the mempool and not confirmed yet",
                r.txid, r.conflicts_with
            )
        })
        .collect();
    // The conflicting side counts the mempool txs, not the txs left out.
    let one_conflict = stats
        .mempool_conflicted_txids
        .iter()
        .map(|c| c.conflicts_with)
        .collect::<std::collections::HashSet<_>>()
        .len()
        == 1;
    left_out_note(
        &mut lines,
        &in_mempool_conflict,
        &LeftOutReason {
            settled: false,
            one: "that conflicts, or depends on one that conflicts, with a transaction in the mempool",
            many: if one_conflict {
                "that conflict, or depend on ones that conflict, with a transaction in the mempool"
            } else {
                "that conflict, or depend on ones that conflict, with transactions in the mempool"
            },
            before_one: Some("the conflicting one reached the mempool"),
            if_broadcast: true,
            before_many: Some(if one_conflict {
                "the conflicting one reached the mempool"
            } else {
                "the conflicting ones reached the mempool"
            }),
            unless_one: None,
            unless_many: None,
            comes_back_one: None,
            comes_back_many: None,
        },
    );
    let abandoned: Vec<String> = stats
        .abandoned_txids
        .iter()
        .map(ToString::to_string)
        .collect();
    left_out_note(
        &mut lines,
        &abandoned,
        &LeftOutReason {
            settled: false,
            // Core abandons the descendants of a coinbase a reorg removed.
            one: "that was abandoned in the wallet, by hand or by Core after a reorg removed a \
                  coinbase it depends on",
            many: "that were abandoned in the wallet, by hand or by Core after a reorg removed a \
                   coinbase they depend on",
            before_one: Some("it was abandoned"),
            if_broadcast: true,
            before_many: Some("they were abandoned"),
            unless_one: Some("it depends on a coinbase a reorg removed"),
            unless_many: Some("they depend on a coinbase a reorg removed"),
            comes_back_one: None,
            comes_back_many: None,
        },
    );

    let unavailable: Vec<String> = stats
        .unavailable_txids
        .iter()
        .map(ToString::to_string)
        .collect();
    left_out_note(
        &mut lines,
        &unavailable,
        &LeftOutReason {
            settled: false,
            one: "that is unconfirmed and that this node does not have (it may have been \
                  replaced or double-spent, expired or been evicted from the mempool, never been \
                  broadcast, or depend on a transaction that was)",
            many: "that are unconfirmed and that this node does not have (they may have been \
                   replaced or double-spent, expired or been evicted from the mempool, never been \
                   broadcast, or depend on a transaction that was)",
            before_one: None,
            if_broadcast: false,
            before_many: None,
            unless_one: Some(
                "it or a transaction it depends on has a conflicting transaction mined",
            ),
            unless_many: Some(
                "they or a transaction they depend on has a conflicting transaction mined",
            ),
            comes_back_one: None,
            comes_back_many: None,
        },
    );

    let orphaned: Vec<String> = stats
        .orphaned_txids
        .iter()
        .map(ToString::to_string)
        .collect();
    left_out_note(
        &mut lines,
        &orphaned,
        &LeftOutReason {
            settled: false,
            one: "that is a coinbase from a block no longer in the chain",
            many: "that are coinbases from blocks no longer in the chain",
            before_one: None,
            if_broadcast: false,
            before_many: None,
            unless_one: None,
            unless_many: None,
            comes_back_one: Some("It can only come back if a reorg restores that block"),
            comes_back_many: Some("They can only come back if a reorg restores those blocks"),
        },
    );

    // The notes say why nothing was analyzed; the empty-scan hint would contradict them.
    let any_left_out = !(conflicted.is_empty()
        && in_mempool_conflict.is_empty()
        && abandoned.is_empty()
        && unavailable.is_empty()
        && orphaned.is_empty());
    if is_empty_report(&report.summary) && any_left_out {
        lines.push("Nothing else was left to analyze.".to_owned());
        return lines.join("\n") + "\n";
    }

    if is_empty_report(&report.summary) {
        lines.push("No transactions found for this input.".to_owned());
        lines.push(
            "Nothing was analyzed — this can mean an unused address, purely off-chain \
             (e.g. Lightning) history, or a node still catching up to the chain tip."
                .to_owned(),
        );
        return lines.join("\n") + "\n";
    }

    if report.summary.clean {
        lines.push("No privacy issues found.".to_owned());
        return lines.join("\n") + "\n";
    }

    if !report.findings.is_empty() {
        lines.push(format!("Findings ({}):", report.findings.len()));
        lines.extend(by_severity(&report.findings).into_iter().map(finding_line));
        lines.push(String::new());
    }
    if !report.warnings.is_empty() {
        lines.push(format!("Warnings ({}):", report.warnings.len()));
        lines.extend(by_severity(&report.warnings).into_iter().map(finding_line));
    }
    lines.join("\n") + "\n"
}

/// Why a note's txs were left out, for one and for several: what follows
/// "Left out N transaction(s)", and what they may have been seen before.
struct LeftOutReason {
    /// Out of the history for good; otherwise the tx may still confirm.
    settled: bool,
    one: &'static str,
    many: &'static str,
    /// What the network may have seen the tx before, when it was broadcast.
    before_one: Option<&'static str>,
    /// The tx may never have been broadcast, so its being seen is conditional.
    if_broadcast: bool,
    before_many: Option<&'static str>,
    /// What would stop a tx that may still confirm from confirming.
    unless_one: Option<&'static str>,
    unless_many: Option<&'static str>,
    /// How a tx that cannot confirm as it stands could come back.
    comes_back_one: Option<&'static str>,
    comes_back_many: Option<&'static str>,
}

/// A note naming the wallet txs a scan left out, one per line, and why.
fn left_out_note(lines: &mut Vec<String>, items: &[String], reason: &LeftOutReason) {
    if items.is_empty() {
        return;
    }
    let (count, why, part, may, before, comes_back, unless, them) = if items.len() == 1 {
        (
            "1 transaction".to_owned(),
            reason.one,
            "it is",
            "It",
            reason.before_one,
            reason.comes_back_one,
            reason.unless_one,
            "it",
        )
    } else {
        let count = format!("{} transactions", items.len());
        (
            count,
            reason.many,
            "they are",
            "They",
            reason.before_many,
            reason.comes_back_many,
            reason.unless_many,
            "them",
        )
    };
    let standing = if reason.settled {
        let comes_back = comes_back.map_or(String::new(), |c| format!(" {c}."));
        format!(", so {part} not part of the wallet's history.{comes_back}")
    } else if let Some(comes_back) = comes_back {
        format!(". {comes_back}; until then {part} not part of the history the wallet sees.")
    } else {
        let unless = unless.map_or(String::new(), |unless| format!(", unless {unless}"));
        format!(
            ". {may} may still confirm{unless}; until then {part} not part of the history the \
             wallet sees."
        )
    };
    let seen = before.map_or(String::new(), |before| {
        if reason.if_broadcast {
            let (it, was) = if items.len() == 1 {
                ("it", "was")
            } else {
                ("they", "were")
            };
            format!(
                " If {it} {was} broadcast, {it} may have been seen by the network before {before};"
            )
        } else {
            format!(" {may} may still have been seen by the network before {before};")
        }
    });
    lines.push(format!(
        "Left out {count} {why}{standing}{seen} Stealth does not analyze {them}."
    ));
    lines.extend(items.iter().map(|item| format!("  {item}")));
    lines.push(String::new());
}

fn finding_line(f: &Finding) -> String {
    format!(
        "  [{severity}] {vtype}: {desc}",
        severity = f.severity,
        vtype = f.vulnerability_type,
        desc = f.description,
    )
}

fn print_usage() {
    eprint!("{}", usage());
}

fn usage() -> String {
    [
        "stealth-cli – Bitcoin UTXO privacy vulnerability scanner\n",
        "USAGE:",
        "  stealth-cli scan [OPTIONS]\n",
        "SCAN INPUT (one required, mutually exclusive):",
        "  --descriptor <DESC>      Output descriptor OR bare extended public key",
        "                           A multipath descriptor (/<0;1>/*) is scanned",
        "                           as all of its paths",
        "  --descriptors <FILE>     JSON array of descriptors",
        "  --utxos <FILE>           JSON array of {txid,vout,...}",
        "                           May be combined with --descriptors, which then",
        "                           act as ownership context for the analysis\n",
        "DESCRIPTOR OPTIONS:",
        "  --cache-wallet           Keep a persistent watch-only wallet keyed to",
        "                           the descriptors so repeat scans skip the full",
        "                           rescan (default: off, wallet is discarded).",
        "                           Trade-off: this writes the viewing key (xpub)",
        "                           into Core's wallet DB in plaintext and leaves a",
        "                           durable _stealth_cache_<hash> wallet revealing",
        "                           the descriptors were scanned. Use only on a",
        "                           node you trust.\n",
        "HISTORY LIMIT:",
        "  --max-txs <N>            Stop before loading a history of more than N",
        "                           transactions (default: 5000): this scan's history,",
        "                           or in UTXO mode, the history of the addresses of",
        "                           the outputs in the UTXO file. Loading a large",
        "                           history can take long and put a heavy load on the",
        "                           node. The scan asks whether to go on instead of",
        "                           stopping, but only when run in the foreground",
        "                           with stdin and stderr on a terminal and Ctrl-C",
        "                           not ignored; Ctrl-C there counts as no.",
        "  --no-limits              Lift the limit\n",
        "RPC CONNECTION:",
        "  --rpc-url <URL>          bitcoind RPC endpoint",
        "  --rpc-user <USER>        RPC username",
        "  --rpc-cookie <PATH>      Path to .cookie file (recommended)\n",
        "  Env vars: STEALTH_RPC_URL, STEALTH_RPC_USER,",
        "            STEALTH_RPC_PASS, STEALTH_RPC_COOKIE\n",
        "OUTPUT:",
        "  --format <text|json>     Output format (default: text)\n",
        "EXIT CODES:",
        "  0  scan completed, no findings",
        "  1  scan completed, findings present",
        "  2  error",
    ]
    .join("\n")
        + "\n"
}

#[cfg(test)]
mod tests;
