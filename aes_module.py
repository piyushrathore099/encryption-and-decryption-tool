"""
AES + RSA Hybrid Encryption Module
Combines the speed of AES (symmetric encryption) with the security of RSA (asymmetric encryption).
"""

import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
ENCRYPTED_DATA_FILE = "encrypted_message.json"


def generate_rsa_keys(private_key_path: str = PRIVATE_KEY_FILE, public_key_path: str = PUBLIC_KEY_FILE) -> None:
    """
    Generates a 2048-bit RSA private and public key pair and saves them as PEM files.
    """
    print("Generating RSA 2048-bit key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize and save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    # Serialize and save public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    print(f"Keys successfully generated:\n - Private: {private_key_path}\n - Public:  {public_key_path}")


def encrypt_message(message: str, public_key_path: str = PUBLIC_KEY_FILE, output_path: str = ENCRYPTED_DATA_FILE) -> None:
    """
    Hybrid Encryption:
    1. Encrypts the message using a newly generated 256-bit AES key (AES-GCM).
    2. Encrypts the AES key using the recipient's RSA public key (RSA-OAEP).
    3. Saves the encrypted bundle (ciphertext, nonce, encrypted AES key) to a JSON file.
    """
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key file '{public_key_path}' not found. Please generate keys first.")

    # 1. Load RSA Public Key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # 2. Generate a random 256-bit AES key and a 96-bit nonce
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    # 3. Encrypt the plaintext message with AES-GCM
    plaintext_bytes = message.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # 4. Encrypt the AES key with RSA-OAEP
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 5. Bundle and encode with Base64 for safe JSON storage
    payload = {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)

    print(f"Message encrypted successfully and saved to '{output_path}'.")


def decrypt_message(private_key_path: str = PRIVATE_KEY_FILE, input_path: str = ENCRYPTED_DATA_FILE) -> str:
    """
    Hybrid Decryption:
    1. Reads the encrypted bundle from JSON.
    2. Decrypts the AES key using the RSA private key (RSA-OAEP).
    3. Decrypts the ciphertext using the decrypted AES key and nonce (AES-GCM).
    4. Prints and returns the plaintext string.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Encrypted message file '{input_path}' not found.")

    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key file '{private_key_path}' not found.")

    # 1. Read JSON bundle
    with open(input_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    encrypted_aes_key = base64.b64decode(payload["encrypted_aes_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    # 2. Load RSA Private Key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 3. Decrypt AES Key using RSA-OAEP
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Decrypt ciphertext using AES-GCM
    aesgcm = AESGCM(aes_key)
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    decrypted_message = decrypted_bytes.decode("utf-8")

    print("\n--- Decrypted Message ---")
    print(decrypted_message)
    print("-------------------------\n")

    return decrypted_message
