# 🔍 OSINT Reconnaissance Framework

A web-based intelligence gathering tool designed for educational purposes and authorized security research. This framework automates the collection of publicly available information about target domains from multiple open sources.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-Educational-orange.svg)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Modules](#modules)
- [Technical Stack](#technical-stack)
- [Security Considerations](#security-considerations)
- [Ethical Usage](#ethical-usage)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Future Enhancements](#future-enhancements)
- [Disclaimer](#disclaimer)
- [License](#license)

## 🎯 Overview

The OSINT Reconnaissance Framework aggregates intelligence from various public sources including WHOIS records, DNS infrastructure, GitHub repositories, breach databases, search engines, and web archives. Results are presented through a modern, interactive dashboard with exportable JSON reports.

**Key Highlights:**
- 🛡️ **Legal & Ethical**: Only queries publicly available data sources
- 📊 **Visual Reports**: Modern dark-themed web interface with organized cards
- 🔧 **Educational**: Clean, well-documented code perfect for learning OSINT
- 📱 **Responsive**: Works on desktop and mobile devices
- ⚡ **Fast**: Asynchronous module execution for quick results

## ✨ Features

### Core Modules
- **WHOIS Intelligence**: Domain registration details, registrar info, name servers, contact data
- **DNS Reconnaissance**: A, MX, NS, TXT, SOA records and subdomain enumeration
- **GitHub OSINT**: Code mentions, related repositories, developer profiles
- **Breach Database**: Email compromise checking against known data breaches
- **Search Intelligence**: Google Dork generation and robots.txt analysis
- **Archive Lookup**: Historical website snapshots from Wayback Machine

### Reporting
- **Unified Dashboard**: All results in one organized view
- **Export Options**: Download reports as JSON
- **Real-time Status**: Live scan progress with visual indicators
- **Module Cards**: Clean, color-coded result sections

### User Interface
- **Simple Input**: Single domain entry field
- **One-Click Scan**: Initiate full reconnaissance instantly
- **Collapsible Sections**: Organized, easy-to-navigate results
- **Cyberpunk Design**: Modern dark theme with gradient accents


## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Download
```bash
# If using git
git clone https://github.com/yourusername/osint-framework.git
cd osint-framework

# Or download and extract the ZIP file
