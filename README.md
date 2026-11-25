# Hybrid AES + RSA Encryption & Decryption System

A secure, production-grade Python CLI application demonstrating **Hybrid Cryptography**: combining high-speed symmetric encryption (**AES-256 GCM**) with robust asymmetric encryption (**RSA-2048 OAEP**).

---

## 🔐 How It Works

1. **Key Generation**: Generates a 2048-bit RSA key pair (`private_key.pem` and `public_key.pem`).
2. **Encryption**:
   - Generates a random 256-bit AES key and a 96-bit nonce.
   - Encrypts the plaintext message using **AES-256-GCM** (providing confidentiality and AEAD integrity).
   - Encrypts the AES key using the RSA public key (**RSA-OAEP** with SHA-256).
   - Bundles the ciphertext, nonce, and encrypted AES key into a JSON file (`encrypted_message.json`).
3. **Decryption**:
   - Uses the RSA private key to decrypt the AES key.
   - Uses the decrypted AES key and nonce to decrypt and verify the message.

---

## 📁 Repository Structure

```
encryption-decryption-system/
├── main.py               # Interactive CLI interface
├── aes_module.py         # Hybrid AES & RSA cryptography implementation
├── test_encryption.py    # Automated test script for verification
├── requirements.txt      # Project dependencies
├── .gitignore            # Excludes keys (*.pem) and temporary files
└── README.md             # Project documentation
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.8 or higher
- Git

### 2. Installation

Clone your repository and navigate into the folder:
```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

Create and activate a virtual environment (optional but recommended):
```bash
# On Linux/macOS:
python3 -m venv venv
source venv/bin/activate

# On Windows:
python -m venv venv
venv\Scripts\activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 💻 Usage

Run the main application:
```bash
python main.py
```

### Menu Options:
1. **Encrypt Message**: Type any plaintext message to encrypt and save it to `encrypted_message.json`.
2. **Decrypt Message**: Decrypts the stored message and prints the plaintext.
3. **Generate RSA Keys**: Generates a new 2048-bit RSA key pair (with overwrite warning).
4. **Exit**: Quits the application.

---

## 🧪 Running Tests

To run the automated verification test:
```bash
python test_encryption.py
```

---

## 📤 How to Push to GitHub

1. Initialize Git in the project directory:
   ```bash
   git init
   ```
2. Add files to staging:
   ```bash
   git add .
   ```
3. Commit the changes:
   ```bash
   git commit -m "Initial commit: Hybrid AES + RSA Encryption System"
   ```
4. Create a new repository on [GitHub](https://github.com/new).
5. Link and push to GitHub:
   ```bash
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo-name>.git
   git push -u origin main
   ```

> ⚠️ **Security Note**: Never commit `private_key.pem` to a public repository. The included `.gitignore` file automatically protects your keys.
