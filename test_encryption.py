"""
Automated unit test for aes_module
"""

import os
from aes_module import generate_rsa_keys, encrypt_message, decrypt_message


def run_test():
    print("--- Starting Hybrid Encryption Test ---")
    
    test_private = "test_private.pem"
    test_public = "test_public.pem"
    test_data = "test_encrypted.json"
    
    test_message = "Secret Agent Message 007: Antigravity Cryptography Test!"

    try:
        # Step 1: Generate keys
        print("\n[Step 1] Generating test RSA keys...")
        generate_rsa_keys(test_private, test_public)
        assert os.path.exists(test_private), "Private key was not created!"
        assert os.path.exists(test_public), "Public key was not created!"

        # Step 2: Encrypt message
        print("\n[Step 2] Encrypting test message...")
        encrypt_message(test_message, public_key_path=test_public, output_path=test_data)
        assert os.path.exists(test_data), "Encrypted payload was not created!"

        # Step 3: Decrypt message
        print("\n[Step 3] Decrypting test message...")
        decrypted = decrypt_message(private_key_path=test_private, input_path=test_data)
        assert decrypted == test_message, f"Decrypted text '{decrypted}' does not match original '{test_message}'!"

        print("\n[SUCCESS] All encryption and decryption checks passed successfully!")

    finally:
        # Clean up test artifacts
        for f in (test_private, test_public, test_data):
            if os.path.exists(f):
                os.remove(f)
        print("Test cleanup completed.")


if __name__ == "__main__":
    run_test()
