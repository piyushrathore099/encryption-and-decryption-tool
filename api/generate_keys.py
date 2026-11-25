"""
Vercel Serverless Function: POST /api/generate-keys
Generates a fresh RSA-2048 key pair and returns them as PEM strings.
The user is responsible for saving and managing their keys.
"""
from http.server import BaseHTTPRequestHandler
import json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            body = json.dumps({"private_key": private_pem, "public_key": public_pem})
            self._respond(200, body)
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
