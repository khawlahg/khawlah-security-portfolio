# 🔍 PE Malware Static Analyzer

A lightweight, web-based static analysis tool for Windows Portable Executable (PE) files. Designed for cybersecurity students and beginners in malware analysis to safely examine executable files without running them.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Detection Capabilities](#detection-capabilities)
- [Risk Scoring](#risk-scoring)
- [API Reference](#api-reference)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

The PE Malware Static Analyzer is an intermediate-level cybersecurity project that demonstrates practical malware detection techniques. It analyzes Windows executables (.exe, .dll) to identify suspicious indicators commonly associated with malicious software.

**Key Highlights:**
- 🛡️ **Safe Analysis**: Files are analyzed statically without execution
- 📊 **Visual Reports**: Modern web interface with risk visualization
- 🔧 **Educational**: Clean, well-documented code for learning
- 📱 **Responsive**: Works on desktop and mobile devices

## ✨ Features

### Core Analysis
- **PE Header Parsing**: Extracts metadata (entry point, compilation time, sections)
- **Import Table Analysis**: Detects suspicious Windows API calls
- **Section Entropy Analysis**: Identifies packed/encrypted sections
- **String Extraction**: Finds URLs, IPs, PowerShell commands, registry keys

### Reporting
- **Risk Score**: 0-100 scoring system with severity levels
- **Visual Dashboard**: Interactive cards and charts
- **Export Options**: Download reports as TXT or JSON
- **Behavior Detection**: Identifies potential malicious capabilities

### User Interface
- **Drag & Drop Upload**: Simple file upload interface
- **Real-time Analysis**: Instant results after upload
- **Collapsible Sections**: Organized, easy-to-navigate results
- **Modern Design**: Clean, professional styling

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Download
```bash
# If using git
git clone https://github.com/yourusername/pe-malware-analyzer.git
cd pe-malware-analyzer

# Or download and extract the ZIP file
