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


ALICE_KEYS = generate_keypair()
BOB_KEYS = generate_keypair()


@app.get("/")
def home():
    return render_template_string(PAGE, alice=key_summary(ALICE_KEYS), bob=key_summary(BOB_KEYS))


@app.post("/api/encrypt")
def api_encrypt():
    try:
        message = request.json.get("message", "")
        return jsonify(ciphertext=encrypt(message, BOB_KEYS))
    except ValueError as error:
        return jsonify(error=str(error)), 400


@app.post("/api/decrypt")
def api_decrypt():
    try:
        return jsonify(message=decrypt(request.json.get("ciphertext", ""), BOB_KEYS))
    except ValueError as error:
        return jsonify(error=str(error)), 400


@app.post("/api/sign")
def api_sign():
    return jsonify(signature=sign(request.json.get("message", ""), ALICE_KEYS))


@app.post("/api/verify")
def api_verify():
    body = request.json
    return jsonify(valid=verify(body.get("message", ""), body.get("signature", ""), ALICE_KEYS))


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Alice & Bob · RSA Lab</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#172033;background:#f6f8fc}*{box-sizing:border-box}body{margin:0}.wrap{max-width:1120px;margin:0 auto;padding:34px 20px 54px}.hero{display:flex;justify-content:space-between;gap:28px;align-items:flex-end;margin-bottom:24px}.eyebrow{color:#6657d9;font-size:12px;font-weight:850;letter-spacing:.16em;text-transform:uppercase}.hero h1{font-size:clamp(36px,6vw,64px);line-height:.98;margin:9px 0 13px;letter-spacing:-.055em}.hero p{max-width:650px;color:#667085;line-height:1.6;margin:0}.security{display:flex;gap:8px;align-items:center;background:#fff;border:1px solid #e3e8f0;border-radius:15px;padding:13px 16px;box-shadow:0 10px 25px #18223a0b;white-space:nowrap}.lock{display:grid;place-items:center;background:#e9f8ef;color:#14834e;border-radius:10px;width:34px;height:34px;font-size:18px}.security b{display:block;font-size:13px}.security small{color:#7b8494}.story{display:grid;grid-template-columns:1fr 46px 1fr;gap:14px;align-items:stretch;margin:20px 0 24px}.person{border-radius:20px;padding:21px;color:#fff;position:relative;overflow:hidden;box-shadow:0 14px 30px #18223a12}.person:after{content:'';position:absolute;width:160px;height:160px;border-radius:50%;right:-55px;bottom:-75px;background:#ffffff1c}.alice{background:linear-gradient(135deg,#6758dc,#8878ec)}.bob{background:linear-gradient(135deg,#e47c41,#f0a24d)}.avatar{display:flex;align-items:center;gap:10px}.avatar-icon{display:grid;place-items:center;width:43px;height:43px;border-radius:13px;background:#ffffff2b;font-size:22px}.person h2{margin:0;font-size:21px}.person p{margin:13px 0 19px;color:#ffffffd9;font-size:13px;line-height:1.5;max-width:270px}.key-pill{display:inline-block;background:#ffffff26;border:1px solid #ffffff3d;border-radius:9px;padding:8px 10px;font-size:12px;font-weight:750}.arrow{display:grid;place-items:center;color:#8b94a5;font-size:26px}.arrow small{display:block;font-size:10px;letter-spacing:.08em;text-transform:uppercase;writing-mode:vertical-rl}.panel-grid{display:grid;grid-template-columns:1.08fr .92fr;gap:20px}.card{background:#fff;border:1px solid #e1e7f0;border-radius:19px;padding:23px;box-shadow:0 12px 30px #18223a0b}.card-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:17px}.step{display:grid;place-items:center;flex:none;width:30px;height:30px;border-radius:9px;background:#f0efff;color:#5b4dcd;font-size:13px;font-weight:850}.card h2{font-size:19px;line-height:1.1;margin:0 0 5px}.hint{font-size:13px;color:#788396;line-height:1.5;margin:0}.label{font-size:11px;font-weight:850;color:#6a7485;letter-spacing:.08em;text-transform:uppercase;margin:13px 0 7px}textarea{width:100%;min-height:107px;border:1px solid #dbe2ec;border-radius:12px;padding:13px;font:inherit;line-height:1.5;resize:vertical;outline:none}textarea:focus{border-color:#6657d9;box-shadow:0 0 0 3px #6657d91a}.actions{display:flex;flex-wrap:wrap;gap:9px;margin-top:13px}button{border:0;border-radius:10px;padding:11px 14px;background:#6657d9;color:#fff;font-weight:800;cursor:pointer;transition:transform .15s,box-shadow .15s}button:hover{transform:translateY(-1px);box-shadow:0 7px 15px #6657d933}button.secondary{background:#eef0ff;color:#5144b7}button.warn{background:#fff0ea;color:#b95432}.result{margin-top:14px;padding:13px;border-radius:11px;background:#f7f8fb;min-height:45px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;line-height:1.5}.result-title{display:block;color:#7b8494;font-size:10px;font-weight:850;letter-spacing:.08em;text-transform:uppercase;margin-bottom:5px}.ok{border-left:4px solid #19a263;background:#effbf5}.bad{border-left:4px solid #dc4b5d;background:#fff3f4}.explain{grid-column:1/-1;background:#1d2639;color:#eaf0ff;border-radius:19px;padding:20px 23px;display:grid;grid-template-columns:1fr 1fr;gap:22px}.explain h2{margin:0 0 8px;font-size:17px}.explain p{color:#b9c4da;line-height:1.55;font-size:13px;margin:0}.route{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-top:12px}.route span{background:#ffffff12;border:1px solid #ffffff20;padding:7px 9px;border-radius:8px;font-size:11px;font-weight:750}.route i{font-style:normal;color:#aab5cb}.note{font-size:11px;color:#8f9bb2;margin-top:11px}@media(max-width:790px){.hero{display:block}.security{display:inline-flex;margin-top:18px}.story{grid-template-columns:1fr}.arrow{transform:rotate(90deg);height:20px}.arrow small{writing-mode:horizontal-tb}.panel-grid{grid-template-columns:1fr}.explain{grid-template-columns:1fr}}
</style></head><body><main class="wrap"><section class="hero"><div><div class="eyebrow">A two-person RSA story</div><h1>Alice sends.<br>Bob verifies.</h1><p>Follow one message through RSA: Alice encrypts it for Bob, signs it with her private key, and Bob uses the right keys to decrypt and verify it.</p></div><div class="security"><div class="lock">✓</div><div><b>{{ alice.bits }}-bit RSA · SHA-256</b><small>Two independent key pairs generated on startup</small></div></div></section>
<section class="story"><article class="person alice"><div class="avatar"><div class="avatar-icon">A</div><h2>Alice · sender</h2></div><p>She writes the message and proves that it came from her.</p><span class="key-pill">Signs with Alice’s private key</span></article><div class="arrow">→<small>secure channel</small></div><article class="person bob"><div class="avatar"><div class="avatar-icon">B</div><h2>Bob · recipient</h2></div><p>He receives the ciphertext and checks Alice’s signature.</p><span class="key-pill">Decrypts with Bob’s private key</span></article></section>
<div class="panel-grid"><section class="card"><div class="card-head"><div class="step">01</div><div><h2>Alice encrypts for Bob</h2><p class="hint">Bob’s public key locks the message. Only Bob’s private key can unlock it.</p></div></div><div class="label">Alice’s message to Bob</div><textarea id="message">Meet me at 10:00 AM.</textarea><div class="actions"><button onclick="encryptMessage()">Alice encrypts →</button><button class="secondary" onclick="decryptMessage()">← Bob decrypts</button></div><div id="cipher" class="result"><span class="result-title">Encrypted message</span>Encrypt the message to create ciphertext.</div><div id="plain" class="result"><span class="result-title">Bob’s result</span>Bob’s decrypted message will appear here.</div></section>
<section class="card"><div class="card-head"><div class="step">02</div><div><h2>Bob verifies Alice</h2><p class="hint">Alice’s public key checks that the message is authentic and unchanged.</p></div></div><div class="label">Message Alice signs</div><textarea id="signMessage">This document is authentic.</textarea><div class="actions"><button onclick="signMessage()">Alice signs</button><button class="secondary" onclick="verifyMessage()">Bob verifies</button><button class="warn" onclick="tamper()">Tamper message</button></div><div id="signature" class="result"><span class="result-title">Alice’s digital signature</span>Sign the message to create a signature.</div><div id="verification" class="result"><span class="result-title">Bob’s verification</span>Waiting for Bob to verify.</div></section>
<section class="explain"><div><h2>Which key is used where?</h2><p>Public keys can be shared. Private keys stay secret. Bob’s keys protect confidentiality; Alice’s keys prove identity.</p><div class="route"><span>Bob public key</span><i>→ encrypt</i><span>Bob private key</span><i>→ decrypt</i></div><div class="route"><span>Alice private key</span><i>→ sign</i><span>Alice public key</span><i>→ verify</i></div></div><div><h2>Try the failure case</h2><p>Sign the message, then click <b>Tamper message</b> and verify again. Bob will reject it because the message no longer matches Alice’s signature.</p><div class="note">Private keys remain on the server and are never shown in the browser.</div></div></section></div></main><script>
let lastCiphertext='';
let lastSignature='';
async function call(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return await r.json()}
function show(id,text,kind=''){const e=document.getElementById(id);const title=document.createElement('span');title.className='result-title';title.textContent=id==='cipher'?'Encrypted message':id==='plain'?'Bob’s result':id==='signature'?'Alice’s digital signature':'Bob’s verification';e.replaceChildren(title,document.createTextNode(text));e.className='result '+kind}
async function encryptMessage(){const d=await call('/api/encrypt',{message:document.getElementById('message').value});if(d.ciphertext)lastCiphertext=d.ciphertext;show('cipher',d.ciphertext||d.error,d.error?'bad':'');if(d.ciphertext)show('plain','Ciphertext ready for Bob to decrypt.');}
async function decryptMessage(){if(!lastCiphertext)return show('plain','Alice must encrypt a message first.','bad');const d=await call('/api/decrypt',{ciphertext:lastCiphertext});show('plain',d.message||d.error,d.error?'bad':'ok')}
async function signMessage(){const d=await call('/api/sign',{message:document.getElementById('signMessage').value});if(d.signature)lastSignature=d.signature;show('signature',d.signature||'Unable to create signature.',d.signature?'':'bad');if(d.signature)show('verification','Alice signed the message. Bob can now verify it.');}
async function verifyMessage(){if(!lastSignature)return show('verification','Alice must sign the message first.','bad');const d=await call('/api/verify',{message:document.getElementById('signMessage').value,signature:lastSignature});show('verification',d.valid?'✓ Bob accepts it: Alice’s signature is valid.':'✕ Bob rejects it: the message or signature does not match.',d.valid?'ok':'bad')}
function tamper(){const e=document.getElementById('signMessage');e.value+=' [modified]';show('verification','Message changed after Alice signed it. Bob should verify again and reject it.','bad')}
</script></body></html>'''


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
