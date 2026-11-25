"""
Vercel Serverless Function: POST /api/encrypt
Body JSON: { "message": "...", "public_key": "-----BEGIN PUBLIC KEY-----..." }
Returns:   { "encrypted_aes_key": "...", "nonce": "...", "ciphertext": "..." }
"""
from http.server import BaseHTTPRequestHandler
import json
import base64
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            message = body.get("message", "").strip()
            public_key_pem = body.get("public_key", "").strip()

            if not message:
                return self._respond(400, json.dumps({"error": "message is required."}))
            if not public_key_pem:
                return self._respond(400, json.dumps({"error": "public_key is required."}))

            public_key = serialization.load_pem_public_key(public_key_pem.encode())

            aes_key = AESGCM.generate_key(bit_length=256)
            nonce = os.urandom(12)
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(nonce, message.encode("utf-8"), None)

            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            result = {
                "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }
            self._respond(200, json.dumps(result))
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
