# RSA Encryption, Decryption & Digital Signature Demo

Small local Flask application that demonstrates an Alice-and-Bob exchange:

- RSA-2048 key-pair generation
- RSA-OAEP encryption/decryption using SHA-256
- RSA-PSS digital signatures using SHA-256
- Rejection of a modified message or invalid signature

Alice encrypts using Bob's public key, Bob decrypts using Bob's private key,
Alice signs using Alice's private key, and Bob verifies using Alice's public key.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

The key pair is generated when the server starts. The private exponent stays on
the server. This is an educational project; production systems should use a
well-reviewed cryptography library and key storage strategy.
