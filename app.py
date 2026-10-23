"""Interactive RSA encryption and digital-signature demo.

This is intentionally small and educational. It uses RSA-OAEP for encryption
and RSA-PSS for signatures, with SHA-256 and a 2048-bit key.
"""

import base64
import hashlib
import hmac
import json
import secrets
from math import gcd
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

E = 65537
KEY_BITS = 2048
HASH = hashlib.sha256
H_LEN = HASH().digest_size


def int_to_bytes(value, length=None):
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def bytes_to_int(value):
    return int.from_bytes(value, "big")


def mgf1(seed, length):
    output = bytearray()
    for counter in range((length + H_LEN - 1) // H_LEN):
        output.extend(HASH(seed + counter.to_bytes(4, "big")).digest())
    return bytes(output[:length])


def is_probable_prime(number, rounds=32):
    if number < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if number in small_primes:
        return True
    if any(number % prime == 0 for prime in small_primes):
        return False
    odd_part, power = number - 1, 0
    while odd_part % 2 == 0:
        odd_part //= 2
        power += 1
    for _ in range(rounds):
        base = secrets.randbelow(number - 3) + 2
        value = pow(base, odd_part, number)
        if value in (1, number - 1):
            continue
        for _ in range(power - 1):
            value = pow(value, 2, number)
            if value == number - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def generate_keypair():
    half = KEY_BITS // 2
    while True:
        p, q = generate_prime(half), generate_prime(half)
        if p == q:
            continue
        modulus = p * q
        if modulus.bit_length() != KEY_BITS:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(E, phi) == 1:
            private_exponent = pow(E, -1, phi)
            return {"n": modulus, "e": E, "d": private_exponent}


def key_summary(keys):
    return {"bits": keys["n"].bit_length(), "e": keys["e"]}


def encrypt(message, keys):
    data = message.encode("utf-8")
    modulus_bytes = (keys["n"].bit_length() + 7) // 8
    if len(data) > modulus_bytes - 2 * H_LEN - 2:
        raise ValueError("Message is too long for 2048-bit RSA-OAEP (maximum is 190 UTF-8 bytes).")
    label_hash = HASH(b"").digest()
    padding = b"\x00" * (modulus_bytes - len(data) - 2 * H_LEN - 2)
    data_block = label_hash + padding + b"\x01" + data
    seed = secrets.token_bytes(H_LEN)
    masked_data = bytes(a ^ b for a, b in zip(data_block, mgf1(seed, modulus_bytes - H_LEN - 1)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, mgf1(masked_data, H_LEN)))
    encoded = b"\x00" + masked_seed + masked_data
    cipher_number = pow(bytes_to_int(encoded), keys["e"], keys["n"])
    return base64.b64encode(int_to_bytes(cipher_number, modulus_bytes)).decode()


def decrypt(ciphertext, keys):
    try:
        raw = base64.b64decode(ciphertext, validate=True)
        modulus_bytes = (keys["n"].bit_length() + 7) // 8
        if len(raw) != modulus_bytes or bytes_to_int(raw) >= keys["n"]:
            raise ValueError
        encoded = int_to_bytes(pow(bytes_to_int(raw), keys["d"], keys["n"]), modulus_bytes)
        if encoded[0] != 0:
            raise ValueError
        masked_seed, masked_data = encoded[1:1 + H_LEN], encoded[1 + H_LEN:]
        seed = bytes(a ^ b for a, b in zip(masked_seed, mgf1(masked_data, H_LEN)))
        data_block = bytes(a ^ b for a, b in zip(masked_data, mgf1(seed, modulus_bytes - H_LEN - 1)))
        if not hmac.compare_digest(data_block[:H_LEN], HASH(b"").digest()):
            raise ValueError
        separator = data_block.find(b"\x01", H_LEN)
        if separator < 0 or any(data_block[H_LEN:separator]):
            raise ValueError
        return data_block[separator + 1:].decode("utf-8")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        raise ValueError("Decryption failed: ciphertext is invalid or was changed.")


def sign(message, keys):
    modulus_bytes = (keys["n"].bit_length() + 7) // 8
    em_bits = keys["n"].bit_length() - 1
    em_len = (em_bits + 7) // 8
    salt = secrets.token_bytes(H_LEN)
    message_hash = HASH(message.encode("utf-8")).digest()
    digest = HASH(b"\x00" * 8 + message_hash + salt).digest()
    padding = b"\x00" * (em_len - H_LEN - len(salt) - 2) + b"\x01"
    masked_data = bytes(a ^ b for a, b in zip(padding + salt, mgf1(digest, em_len - H_LEN - 1)))
    masked_data = bytes([masked_data[0] & (0xFF >> (8 * em_len - em_bits))]) + masked_data[1:]
    encoded = masked_data + digest + b"\xbc"
    signature = pow(bytes_to_int(encoded), keys["d"], keys["n"])
    return base64.b64encode(int_to_bytes(signature, modulus_bytes)).decode()


def verify(message, signature, keys):
    try:
        raw = base64.b64decode(signature, validate=True)
        modulus_bytes = (keys["n"].bit_length() + 7) // 8
        em_bits = keys["n"].bit_length() - 1
        em_len = (em_bits + 7) // 8
        if len(raw) != modulus_bytes or bytes_to_int(raw) >= keys["n"]:
            return False
        encoded = int_to_bytes(pow(bytes_to_int(raw), keys["e"], keys["n"]), modulus_bytes)[-em_len:]
        if encoded[-1] != 0xBC:
            return False
        masked_data, digest = encoded[:em_len - H_LEN - 1], encoded[em_len - H_LEN - 1:-1]
        unused_bits = 8 * em_len - em_bits
        if masked_data[0] & ((0xFF << (8 - unused_bits)) & 0xFF):
            return False
        padding_salt = bytes(a ^ b for a, b in zip(masked_data, mgf1(digest, em_len - H_LEN - 1)))
        padding_salt = bytes([padding_salt[0] & (0xFF >> (8 * em_len - em_bits))]) + padding_salt[1:]
        separator = em_len - H_LEN - H_LEN - 2
        if padding_salt[:separator] != b"\x00" * separator or padding_salt[separator] != 1:
            return False
        salt = padding_salt[separator + 1:]
        expected = HASH(b"\x00" * 8 + HASH(message.encode("utf-8")).digest() + salt).digest()
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError, base64.binascii.Error):
        return False


KEYS = generate_keypair()


@app.get("/")
def home():
    return render_template_string(PAGE, key=key_summary(KEYS))


@app.post("/api/encrypt")
def api_encrypt():
    try:
        message = request.json.get("message", "")
        return jsonify(ciphertext=encrypt(message, KEYS))
    except ValueError as error:
        return jsonify(error=str(error)), 400


@app.post("/api/decrypt")
def api_decrypt():
    try:
        return jsonify(message=decrypt(request.json.get("ciphertext", ""), KEYS))
    except ValueError as error:
        return jsonify(error=str(error)), 400


@app.post("/api/sign")
def api_sign():
    return jsonify(signature=sign(request.json.get("message", ""), KEYS))


@app.post("/api/verify")
def api_verify():
    body = request.json
    return jsonify(valid=verify(body.get("message", ""), body.get("signature", ""), KEYS))


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RSA Lab</title><style>
:root{font-family:Inter,system-ui,sans-serif;color:#172033;background:#f5f7fb}*{box-sizing:border-box}body{margin:0}.wrap{max-width:1050px;margin:0 auto;padding:42px 20px}.hero{display:flex;justify-content:space-between;gap:24px;align-items:end;margin-bottom:28px}.eyebrow{color:#6256d9;font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}.hero h1{font-size:clamp(32px,6vw,58px);line-height:1;margin:8px 0 10px;letter-spacing:-.04em}.hero p{max-width:620px;color:#667085;line-height:1.6;margin:0}.badge{background:#fff;border:1px solid #e2e7f0;border-radius:16px;padding:15px 18px;white-space:nowrap;box-shadow:0 8px 24px #1e27400d}.badge b{display:block;font-size:20px}.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:20px}.card{background:#fff;border:1px solid #e2e7f0;border-radius:18px;padding:22px;box-shadow:0 10px 30px #1e27400b}.card h2{font-size:18px;margin:0 0 7px}.hint{font-size:13px;color:#778196;margin:0 0 15px}.full{grid-column:1/-1}textarea,input{width:100%;border:1px solid #dbe1eb;border-radius:11px;padding:13px;font:inherit;resize:vertical;outline:none}textarea:focus,input:focus{border-color:#6256d9;box-shadow:0 0 0 3px #6256d91a}textarea{min-height:112px}label{display:block;font-size:12px;font-weight:700;color:#667085;margin:14px 0 6px}.actions{display:flex;flex-wrap:wrap;gap:9px;margin-top:13px}button{border:0;border-radius:10px;padding:11px 15px;background:#6256d9;color:#fff;font-weight:750;cursor:pointer}button.secondary{background:#eef0ff;color:#4d43b5}button.ghost{background:#f2f4f7;color:#4b5565}.result{margin-top:14px;padding:13px;border-radius:10px;background:#f7f8fb;min-height:46px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}.ok{border-left:4px solid #16a36a;background:#effbf5}.bad{border-left:4px solid #dc4b5d;background:#fff3f4}.keybox{background:#172033;color:#dce5ff;border-radius:12px;padding:14px;font:12px ui-monospace,monospace;line-height:1.7;word-break:break-word}.flow{display:flex;gap:8px;align-items:center;color:#8a93a5;font-size:13px;margin:12px 0}.flow span{background:#f0f1ff;color:#5147bd;padding:8px 10px;border-radius:8px;font-weight:700}@media(max-width:760px){.grid{grid-template-columns:1fr}.full{grid-column:auto}.hero{display:block}.badge{display:inline-block;margin-top:18px}}
</style></head><body><main class="wrap"><section class="hero"><div><div class="eyebrow">Public-key cryptography lab</div><h1>RSA, made visible.</h1><p>Encrypt a message with the public key, decrypt it with the private key, then sign and verify its authenticity. Try changing a single character to see verification fail.</p></div><div class="badge"><b>{{ key.bits }}-bit RSA</b>e = {{ key.e }} · SHA-256</div></section>
<div class="grid"><section class="card"><h2>1. Encrypt & decrypt</h2><p class="hint">RSA-OAEP keeps the message confidential. The ciphertext changes each time because OAEP uses randomness.</p><textarea id="message">Meet me at 10:00 AM.</textarea><div class="actions"><button onclick="encryptMessage()">Encrypt with public key</button><button class="secondary" onclick="decryptMessage()">Decrypt with private key</button></div><div id="cipher" class="result">Ciphertext will appear here.</div><div id="plain" class="result">Decrypted message will appear here.</div></section>
<section class="card"><h2>2. Sign & verify</h2><p class="hint">RSA-PSS binds the signature to the exact message. The public key can validate it, but cannot create it.</p><label for="signMessage">Message to sign</label><textarea id="signMessage">This document is authentic.</textarea><div class="actions"><button onclick="signMessage()">Sign with private key</button><button class="secondary" onclick="verifyMessage()">Verify with public key</button><button class="ghost" onclick="tamper()">Modify message</button></div><div id="signature" class="result">Signature will appear here.</div><div id="verification" class="result">Verification result will appear here.</div></section>
<section class="card full"><h2>What the keys do</h2><div class="flow"><span>Public key (n, e)</span> → encrypt / verify <b>·</b> <span>Private key (n, d)</span> → decrypt / sign</div><div class="keybox">Key pair generated when the server starts. Private exponent d is kept server-side and never sent to the browser.</div></section></div></main><script>
async function call(path, body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return await r.json()}
function show(id,text,kind=''){const e=document.getElementById(id);e.textContent=text;e.className='result '+kind}
async function encryptMessage(){const d=await call('/api/encrypt',{message:document.getElementById('message').value});show('cipher',d.ciphertext||d.error,d.error?'bad':'');if(d.ciphertext)show('plain','Ready to decrypt.');}
async function decryptMessage(){const c=document.getElementById('cipher').textContent;if(!c||c.includes('appear'))return show('plain','Encrypt a message first.','bad');const d=await call('/api/decrypt',{ciphertext:c});show('plain',d.message||d.error,d.error?'bad':'ok')}
async function signMessage(){const d=await call('/api/sign',{message:document.getElementById('signMessage').value});show('signature',d.signature);show('verification','Signature created. Click Verify.');}
async function verifyMessage(){const s=document.getElementById('signature').textContent;if(!s||s.includes('appear'))return show('verification','Sign a message first.','bad');const d=await call('/api/verify',{message:document.getElementById('signMessage').value,signature:s});show('verification',d.valid?'✓ Valid signature — message is unchanged and authentic.':'✕ Invalid signature — message or signature does not match.',d.valid?'ok':'bad')}
function tamper(){const e=document.getElementById('signMessage');e.value+=' [modified]';show('verification','Message modified. Verify again to see the signature rejected.','bad')}
</script></body></html>'''


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
