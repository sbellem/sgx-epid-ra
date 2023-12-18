import base64
import json
import os
import subprocess

import requests

import eth_abi
from web3 import Web3


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


def hexlify_report_data(address, message):
    if address.startswith("0x"):
        address = address[2:]

    if len(address) != 40:
        raise ValueError("address is incorrect")

    if len(message) > 44:
        raise ValueError("message must be 44 characters at most")

    return address + message.encode().hex()


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


def enter_contest(quote):
    # account =
    tx = epid_contest_contract.functions.enter_contest(
        bytes.fromhex(attestation)
    ).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
        }
    )
    raise NotImplementedError
