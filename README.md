# Secure File Transfer System

A robust and secure file transfer application utilizing **Hybrid Cryptography** (AES-256 and RSA-2048) to ensure end-to-end data confidentiality and integrity.

## 🚀 Overview

This system provides a web-based interface for securely transferring files between a sender and a receiver. It combines the speed of symmetric encryption (AES) with the security of asymmetric encryption (RSA) for key exchange, ensuring that files remain protected even if intercepted during transit.

## 🛡️ Security Features

- **Hybrid Cryptography**: 
  - **AES-256 (CBC Mode)**: Used for encrypting the actual file data.
  - **RSA-2048**: Used for securely exchanging the AES session key between the sender and receiver.
- **Dynamic Key Generation**: A new AES session key is generated for every transfer.
- **Integrity Verification**: Uses SHA-256 hashing to ensure the file has not been tampered with during transfer.
- **Public/Private Key Pair**: The receiver generates an RSA key pair; the public key is shared with the sender, while the private key remains secure on the receiver's end.

## 🛠️ Technology Stack

- **Backend**: Python, Flask
- **Cryptography**: PyCryptodome
- **Networking**: Ngrok (for public access/tunnelling)
- **Frontend**: HTML5, Vanilla CSS, JavaScript

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/prapulreddy7/Secure-File-Transfer-System-using-Cryptography-AES-256-and-RSA-2048-Integration-.git
   cd Secure-File-Transfer-System-using-Hybrid-Cryptography-AES-RSA--main
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional) Install Ngrok**:
   If you want to access the system over the internet, install `pyngrok`:
   ```bash
   pip install pyngrok
   ```

## 🚀 Usage

### Running Locally
To start the Flask application locally:
```bash
python main.py
```
Access the app at `http://127.0.0.1:5000`.

### Running with Ngrok (Public Access)
To expose the application to the internet:
```bash
python run_ngrok.py
```
This will provide a public URL that you can share with the sender/receiver.

## 📂 Project Structure

- `core/`: Contains the cryptographic logic (`crypto.py`, `keygen.py`).
- `web/`: Contains the Flask application and web routes.
- `templates/`: HTML templates for the UI.
- `main.py`: Entry point for the local application.
- `run_ngrok.py`: Entry point for the application with Ngrok integration.

## 📝 License

This project is open-source and available under the MIT License.
