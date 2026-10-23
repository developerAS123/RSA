# RSA Encryption, Decryption & Digital Signature Demo

Small local Flask application that demonstrates:

- RSA-2048 key-pair generation
- RSA-OAEP encryption/decryption using SHA-256
- RSA-PSS digital signatures using SHA-256
- Rejection of a modified message or invalid signature

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
