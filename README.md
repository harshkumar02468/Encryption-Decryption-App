#CryptoVault Pro - Advanced File Encryption Suite

CryptoVault Pro is a secure file encryption/decryption application featuring military-grade cryptographic operations wrapped in an intuitive graphical interface.

Key Features:

AES-256 Encryption with CFB mode for maximum security

PBKDF2 key derivation (SHA-512, 100,000 iterations)

Secure salt and IV generation for each encryption operation

Three key strength options (256-bit, 384-bit, 512-bit)

Modern GUI with light/dark theme support

Comprehensive key management with copy/paste functionality

Detailed logging with color-coded status messages

Cross-platform Python implementation

Technical Highlights:

Uses Python's cryptography library for core operations

Implements proper cryptographic best practices:

Unique salt per encryption

Random initialization vectors

Key derivation with high iteration count

Tkinter-based interface with ttk widgets for native look

Theme system supporting light/dark modes

Base64-encoded keys for easy sharing/storage

Usage:

Encrypt files with automatically generated keys

Securely store the key and salt values

Decrypt files using the original key and salt

