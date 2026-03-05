"""
bitcoin_rpc.py — Thin wrapper around bitcoin-cli for Python tests.
Connection settings are read from config.ini in the same directory.
"""

import json
import subprocess
import os
import configparser

# ── Load config ──────────────────────────────────────────────────────────────

def _load_config():
    cfg = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
    cfg.read(config_path)
    return cfg["bitcoin"] if "bitcoin" in cfg else {}

def _build_base_args(section):
    cli_bin = section.get("cli", "bitcoin-cli")
    network = section.get("network", "regtest").strip().lower()

    args = [cli_bin]

    # Datadir — resolve relative paths from this file's directory
    datadir = section.get("datadir", "").strip()
    if datadir:
        if not os.path.isabs(datadir):
            datadir = os.path.join(os.path.dirname(os.path.abspath(__file__)), datadir)
        args.append(f"-datadir={datadir}")

    network_flags = {
        "regtest": "-regtest",
        "testnet": "-testnet",
        "signet":  "-signet",
    }
    if network in network_flags:
        args.append(network_flags[network])

    for key, flag in [("rpchost", "-rpcconnect"), ("rpcport", "-rpcport"),
                      ("rpcuser", "-rpcuser"), ("rpcpassword", "-rpcpassword")]:
        value = section.get(key, "").strip()
        if value:
            args.append(f"{flag}={value}")

    return args

_cfg = _load_config()
_BASE_ARGS = _build_base_args(_cfg)

def cli(*args, wallet=None):
    """Call bitcoin-cli [network] [wallet] <args> and return parsed JSON or string."""
    cmd = list(_BASE_ARGS)
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(str(a) for a in args)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"bitcoin-cli error: {result.stderr.strip()}\n  cmd: {' '.join(cmd)}")

    output = result.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output


def mine_blocks(n=1):
    """Mine n blocks on regtest using generatetoaddress."""
    miner_addr = cli("getnewaddress", "", "bech32", wallet="miner")
    cli("generatetoaddress", n, miner_addr)
    return int(cli("getblockcount"))


def get_tx(txid):
    """Get decoded transaction."""
    return cli("getrawtransaction", txid, "true")


def get_utxos(wallet_name, min_conf=0):
    """List unspent outputs for a wallet."""
    return cli("listunspent", min_conf, wallet=wallet_name)


def get_balance(wallet_name):
    """Get wallet balance."""
    return float(cli("getbalance", wallet=wallet_name))


def send_raw(hex_tx):
    """Broadcast a raw transaction."""
    return cli("sendrawtransaction", hex_tx)


def create_funded_psbt(wallet_name, inputs, outputs, options=None):
    """Create a funded PSBT."""
    args = ["walletcreatefundedpsbt", json.dumps(inputs), json.dumps(outputs), 0]
    if options:
        args.append(json.dumps(options))
    return cli(*args, wallet=wallet_name)


def process_psbt(wallet_name, psbt):
    """Sign a PSBT."""
    return cli("walletprocesspsbt", psbt, wallet=wallet_name)


def finalize_psbt(psbt):
    """Finalize a PSBT."""
    return cli("finalizepsbt", psbt)


def create_raw_tx(inputs, outputs):
    """Create a raw transaction."""
    return cli("createrawtransaction", json.dumps(inputs), json.dumps(outputs))


def sign_raw_tx(wallet_name, hex_tx):
    """Sign a raw transaction."""
    return cli("signrawtransactionwithwallet", hex_tx, wallet=wallet_name)


def get_block_count():
    """Get current block height."""
    return int(cli("getblockcount"))


def get_new_address(wallet_name, addr_type="bech32"):
    """Get a new address."""
    return cli("getnewaddress", "", addr_type, wallet=wallet_name)


def send_to_address(wallet_name, address, amount):
    """Send BTC to an address."""
    return cli("sendtoaddress", address, f"{amount:.8f}", wallet=wallet_name)


