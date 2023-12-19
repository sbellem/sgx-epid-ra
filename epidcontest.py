import base64
import json
import os
import subprocess

import requests

import eth_abi
from web3 import Web3

DEFAULT_LOGBOOK_MESSAGE = "pour tea in kettle; heat kettle in tee; 🍵"


def _normalize_report_items(report):
    report["version"] = str(report["version"])
    report["advisoryIDs"] = json.dumps(report["advisoryIDs"], separators=(",", ":"))
    report["isvEnclaveQuoteBody"] = base64.b64decode(report["isvEnclaveQuoteBody"])
    return (v.encode() if k != "isvEnclaveQuoteBody" else v for k, v in report.items())


def encode_ias_response(ias_response):
    report = ias_response.json()
    signature = ias_response.headers["X-IASReport-Signature"]
    items = tuple(_normalize_report_items(report))
    abidata = eth_abi.encode(
        [
            "bytes",
            "bytes",
            "bytes",
            "bytes",
            "bytes",
            "bytes",
            "bytes",
            "bytes",
            "bytes",
        ],
        items,
    )
    decoded_signature = base64.b64decode(signature.encode())
    return eth_abi.encode(["bytes", "bytes"], (abidata, decoded_signature)).hex()


def hexlify_report_data(address, message, *, fillchar=" "):
    HEX_MSG_LEN = 88

    if len(fillchar) != 1:
        raise ValueError("fillchar must only be one character")

    if address.startswith("0x"):
        address = address[2:]

    if len(address) != 40:
        raise ValueError("address is incorrect")

    hex_msg = message.encode().hex()
    if len(hex_msg) > HEX_MSG_LEN:
        raise ValueError(f"hex message must be {HEX_MSG_LEN} characters at most")

    hex_fillchar = fillchar.encode().hex()
    return address + hex_fillchar * ((HEX_MSG_LEN - len(hex_msg)) // 2) + hex_msg


def gen_quote(address, message):
    report_data = hexlify_report_data(address, message)

    subprocess.run(["sh", "run-client", "-q", "--debug", "--report-data", report_data])

    with open("quote.txt") as f:
        quote = f.read()

    return {"isvEnclaveQuote": quote}


def send_quote_to_ias(quote):
    IAS_URL = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report"
    headers = {
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": os.environ["IAS_PRIMARY_KEY"],
    }
    return requests.post(IAS_URL, json=quote, headers=headers)


def connect_to_network():
    try:
        infura_api_key = os.environ["INFURA_API_KEY"]
    except KeyError:
        raise

    infura_url = f"https://optimism-mainnet.infura.io/v3/{infura_api_key}"

    w3 = Web3(Web3.HTTPProvider(infura_url))

    return w3


def connect_to_contract(w3=None):
    CONTRACT_ADDRESS = "0x490A428b0301D61DB6eD45eddc55d615F2EA9F75"

    # with open("epid_contest_contract_abi.json") as f:
    # abi = json.load(f)
    with open("epid_contest_contract_abi.txt") as f:
        abi = f.read()

    if not w3:
        w3 = connect_to_network()

    epid_contest_contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi.strip())

    return epid_contest_contract


def verify_epid(*, quote=None, ias_response=None, attestation=None, contract=None):
    if quote:
        ias_response = send_quote_to_ias(quote)
    if ias_response:
        attestation = encode_ias_response(ias_response)

    if not attestation:
        raise Exception("Missing argument! Pass quote, ias_response or attestation.")

    if not contract:
        w3 = connect_to_network()
        contract = connect_to_contract(w3)

    return contract.functions.verify_epid(bytes.fromhex(attestation)).call()


def instantiate_eth_account(private_key, *, w3=None):
    if not w3:
        w3 = connect_to_network()

    return w3.eth.account.from_key(private_key)


def gen_enter_contest_tx(address, message, from_address):
    quote = gen_quote(address, message)
    ias_response = send_quote_to_ias(quote)
    attestation = encode_ias_response(ias_response)

    w3 = connect_to_network()
    contract = connect_to_contract(w3)

    tx = contract.functions.enter_contest(bytes.fromhex(attestation)).build_transaction(
        {
            "from": from_address,
            "nonce": w3.eth.get_transaction_count(from_address),
        }
    )
    return tx


def sign_tx(*, w3=None, private_key=None):
    if not w3:
        w3 = connect_to_network()

    if not private_key:
        private_key = os.environ["ETH_PRIVATE_KEY"]

    account = w3.eth.account.from_key(private_key)
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=account.key)

    return signed_tx


def enter_contest(
    *,
    address=None,
    message=None,
    quote=None,
    ias_response=None,
    attestation=None,
    w3=None,
    contract=None,
    account=None,
):
    if address and message:
        quote = gen_quote(address, message)

    if quote:
        ias_response = send_quote_to_ias(quote)

    if ias_response:
        attestation = encode_ias_response(ias_response)

    if not attestation:
        raise Exception("Missing argument! Pass quote, ias_response or attestation.")

    if not w3:
        w3 = connect_to_network()

    if not contract:
        contract = connect_to_contract(w3)

    if not account:
        private_key = os.environ["ETH_PRIVATE_KEY"]
        w3.eth.account.from_key(private_key)

    tx = contract.functions.enter_contest(bytes.fromhex(attestation)).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
        }
    )
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=account.key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return tx_hash
