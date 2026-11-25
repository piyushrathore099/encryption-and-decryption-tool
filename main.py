import os
from aes_module import generate_rsa_keys, encrypt_message, decrypt_message


def main():
    print("=" * 45)
    print("   ENCRYPTION AND DECRYPTION SYSTEM (AES + RSA)")
    print("=" * 45)

    # Generate RSA keys if they do not exist
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        print("RSA key pair not detected. Generating keys for initial setup...")
        generate_rsa_keys()

    while True:
        print("\nMenu Options:")
        print("1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Generate RSA Keys")
        print("4. Exit")

        choice = input("\nEnter your choice (1-4): ").strip()

        if choice == "1":
            message = input("Enter message to encrypt: ")
            if not message:
                print("Warning: Message cannot be empty.")
                continue

            try:
                encrypt_message(message)
            except Exception as e:
                print("Encryption error:", e)

        elif choice == "2":
            try:
                decrypt_message()
            except FileNotFoundError:
                print("No encrypted message found. Encrypt a message first.")
            except Exception as e:
                print("Decryption error:", e)

        elif choice == "3":
            confirm = input(
                "WARNING: Re-generating keys will make any previously encrypted messages unreadable. Continue? (y/n): "
            ).strip().lower()
            if confirm in ("y", "yes"):
                try:
                    generate_rsa_keys()
                except Exception as e:
                    print("Key generation error:", e)
            else:
                print("Key generation cancelled.")

        elif choice == "4":
            print("\nThank you for using our project!")
            break

        else:
            print("Invalid choice! Please select 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
