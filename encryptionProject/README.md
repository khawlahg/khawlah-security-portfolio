# 🔐 AI Crypto Analysis Tool

A modern, interactive desktop application for encryption, decryption, hashing, and AI-powered cryptographic analysis. Built with Python and Tkinter, featuring a sleek dark-themed UI.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Tkinter](https://img.shields.io/badge/Tkinter-8.6+-orange.svg)

## ✨ Features

### 🔒 Encryption & Decryption
- **AES-256** (Advanced Encryption Standard) - Industry standard symmetric encryption
- **DES** (Data Encryption Standard) - Legacy symmetric encryption (educational purposes)
- **RSA-2048** (Rivest–Shamir–Adleman) - Asymmetric encryption with public/private key pairs
- Support for both encryption and decryption modes
- Chunking support for RSA (handles text of any length)

### #️⃣ Hashing
- **SHA-256** one-way hashing
- Hash verification functionality
- Copy-to-clipboard integration

### 🤖 AI-Powered Analysis
- **Machine Learning Classification** using Random Forest algorithm
- Automatically identifies encryption algorithms from ciphertext
- Confidence scoring for predictions
- Statistical feature extraction (entropy, byte frequency, encoding detection)
- Trained on 2000+ synthetic samples with 95%+ accuracy

### 🎨 Modern UI
- Dark professional theme with custom color palette
- Tabbed interface for organized workflow
- Custom rounded buttons with hover effects
- Syntax-highlighting style text areas
- Responsive layout with scrollable panels
- Real-time status bar updates

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Dependencies

pip install rsa pycryptodome scikit-learn numpy
