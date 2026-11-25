"""
Vercel Serverless Function: POST /api/decrypt
Body JSON: {
  "encrypted_aes_key": "...",
  "nonce": "...",
  "ciphertext": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----..."
}
Returns: { "message": "decrypted plaintext" }
"""
from http.server import BaseHTTPRequestHandler
import json
import base64

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))

            encrypted_aes_key = base64.b64decode(body.get("encrypted_aes_key", ""))
            nonce = base64.b64decode(body.get("nonce", ""))
            ciphertext = base64.b64decode(body.get("ciphertext", ""))
            private_key_pem = body.get("private_key", "").strip()

            if not all([encrypted_aes_key, nonce, ciphertext, private_key_pem]):
                return self._respond(400, json.dumps({"error": "All fields are required: encrypted_aes_key, nonce, ciphertext, private_key."}))

            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

            self._respond(200, json.dumps({"message": plaintext}))
        except Exception as e:
            self._respond(500, json.dumps({"error": str(e)}))

    def do_OPTIONS(self):
        self._respond(204, "")

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        pass
