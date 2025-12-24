
🔐 AES Secure File Storage System
📌 Description
AES Secure File Storage System is a Python-based application that encrypts and decrypts files using AES-256 encryption. It protects sensitive data from unauthorized access and verifies file integrity to detect tampering.

🛠 Tools Used
Python 3
cryptography (AES-GCM, PBKDF2)
hashlib
argparse
JSON

⚙️ Working
User provides a file and password
Password is converted into a 256-bit key using PBKDF2
File is encrypted using AES-256-GCM
Encrypted file (.enc) and metadata are generated
Decryption restores the original file
SHA-256 hash verifies integrity

▶️ Usage
pip install cryptography
python aes_secure_storage.py encrypt file.txt
python aes_secure_storage.py decrypt file.txt.enc
python aes_secure_storage.py verify file.txt.enc

✅ Features
Strong AES-256 encryption
Password-based key generation
Integrity & tamper detection
Simple CLI interface
Cross-platform support

📌 Conclusion
This project demonstrates secure file encryption using modern cryptographic standards and highlights the importance of data confidentiality and integrity in cybersecurity.
