# 🛡️ IDS Rule Optimization Framework

A web-based framework for optimizing Intrusion Detection System (IDS) rules using evolutionary algorithms and heuristic search methods. Designed for cybersecurity students and researchers to understand automated security rule optimization.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-Educational-orange.svg)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Algorithms](#algorithms)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Methodology](#methodology)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Future Enhancements](#future-enhancements)
- [License](#license)

## 🎯 Overview

The IDS Rule Optimization Framework demonstrates how computational intelligence can improve cybersecurity detection systems. It compares four approaches for finding optimal detection thresholds:

**Key Highlights:**
- 🧬 **Evolutionary Optimization**: Genetic Algorithm with selection, crossover, mutation
- 🔍 **Heuristic Search**: A* and Greedy search strategies
- 📊 **Visual Analytics**: Interactive Plotly charts for fitness evolution
- 🎓 **Educational**: Clean, well-documented implementations of AI algorithms
- ⚡ **Real-time Processing**: Web interface with live optimization progress

## ✨ Features

### Core Algorithms
- **Genetic Algorithm**: Population-based evolutionary optimization
- **Greedy Search**: Local improvement through parameter adjustment
- **A* Search**: Heuristic-guided threshold exploration
- **Fixed Baseline**: Expert-defined thresholds for comparison

### Detection Metrics
- **True Positives (TP)**: Correctly identified intrusions
- **True Negatives (TN)**: Correctly identified normal traffic
- **False Positives (FP)**: Normal traffic flagged as intrusion
- **False Negatives (FN)**: Missed intrusions
- **Fitness Score**: Detection Rate - False Positive Rate

### Visualization
- **Fitness Evolution**: Track GA convergence over generations
- **Performance Comparison**: Bar charts across all methods
- **Interactive Charts**: Plotly.js with zoom and pan capabilities
- **Export Reports**: Downloadable JSON and text reports

## 🧬 Algorithms

| Method | Strategy | Best For |
|--------|----------|----------|
| **Fixed** | Manual thresholds [5, 1000, 300] | Baseline comparison |
| **Greedy** | Hill-climbing with step size 0.05 | Quick local optimization |
| **A\*** | Heuristic: 1 - fitness, cost = changes | Informed exploration |
| **Genetic Algorithm** | Population=50, Generations=30, Mutation=0.1 | Global optimization |

### Fitness Function
fitness = detection_rate - false_positive_rate
plain
Copy
Maximizes detection while minimizing false alarms.

## 📸 Screenshots

*Note: Add your own screenshots showing:*
- Dataset upload interface with preview
- GA fitness evolution curve over generations
- Performance comparison bar chart
- Threshold configuration results

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Step 1: Clone or Download
git clone https://github.com/yourusername/ids-optimization-framework.git
cd ids-optimization-framework
### Step 2: Create Project Structure
ids_framework/
├── app.py
├── requirements.txt
├── templates/
│   ├── index.html
│   └── results.html
├── uploads/
└── results/
### Step 3: Install Dependencies
Create requirements.txt:

Flask==2.3.0
pandas==2.0.0
numpy==1.24.0
plotly==5.14.0
matplotlib==3.7.0
Then run:

pip install -r requirements.txt
### Step 4: Run the Application

python app.py
### Step 5: Access the Interface
Open browser and navigate to:

http://localhost:5000
## 💻 Usage
### Option 1: Use Sample Dataset
Click "Generate Sample Dataset"
System creates 1000 synthetic records (30% intrusion traffic)
Click "Analyze" to run all algorithms
### Option 2: Upload Custom Dataset
Prepare CSV with columns:
failed_logins: Number of failed login attempts
packet_rate: Packets per second
session_time: Session duration in seconds
label: 0 = normal, 1 = intrusion
Upload via drag-and-drop or file selector
Run analysis
Interpreting Results
Best Fitness: Closer to 1.0 is better (max 1.0)
Detection Rate: Percentage of intrusions caught
False Positive Rate: Percentage of normal traffic misclassified
Optimal Thresholds: Values for [failed_logins, packet_rate, session_time]
### 📁 Project Structure

ids_optimization/
├── app.py                 # Main Flask application with algorithms
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates
│   ├── index.html        # Upload and configuration interface
│   └── results.html      # Results dashboard with charts
├── uploads/              # Uploaded CSV datasets
└── results/              # Generated JSON reports and text files
🔌 API Reference
Endpoints
Table
Endpoint	Method	Description
/	GET	Main interface
/sample_dataset	GET	Generate synthetic dataset
/upload	POST	Upload CSV file
/analyze	POST	Run optimization algorithms
/results/<id>	GET	View results page
/download_report/<id>	GET	Download text report
Request/Response Examples
Generate Sample Dataset:

GET /sample_dataset
Response:
JSON

{
  "filename": "sample_ids_dataset_20240115_143022.csv",
  "rows": 1000,
  "preview": [...]
}
Run Analysis:

POST /analyze
Content-Type: application/json

{
  "filename": "sample_ids_dataset_20240115_143022.csv",
  "use_sample": true
}
Response:
JSON
Copy
{
  "result_id": "uuid",
  "timestamp": "2024-01-15T14:30:00",
  "dataset_info": {...},
  "results": {
    "fixed": {...},
    "greedy": {...},
    "astar": {...},
    "ga": {...}
  },
  "charts": {...}
}
### 🔬 Methodology
Synthetic Data Generation
Normal traffic:
Failed logins: 0-3 (Gaussian noise)
Packet rate: 100-600 pps
Session time: 30-300 seconds
Intrusion traffic:
Failed logins: 5-15 (brute force)
Packet rate: 800-2000 pps (DDoS)
Session time: Very short (1-10s) or very long (400-600s)
Detection Rules
plain
Copy
IF (failed_logins > threshold[0]) OR 
   (packet_rate > threshold[1]) OR 
   (session_time > threshold[2]) 
THEN intrusion
Genetic Algorithm Parameters
Population Size: 50 individuals
Generations: 30
Crossover Rate: 0.8 (single-point)
Mutation Rate: 0.1 (Gaussian noise)
Selection: Tournament (size 3)
Bounds: Failed logins [1-15], Packet rate [100-2000], Session time [50-600]
### ⚠️ Limitations
Table
Limitation	Details	Mitigation
Synthetic Data	Generated data may not reflect real network patterns	Upload real IDS logs
Single Rule Type	Only threshold-based rules supported	Extend with signature rules
Binary Classification	Only normal vs intrusion	Extend with attack types
Local Optima	Greedy may get stuck	Use GA for global search
Computation Time	GA takes 30+ generations	Reduce population size
### 🐛 Troubleshooting
Table
Issue	Solution
ModuleNotFoundError	Run pip install -r requirements.txt
CSV upload fails	Check columns: failed_logins, packet_rate, session_time, label
Charts not displaying	Ensure Plotly CDN is accessible
GA convergence too slow	Reduce generations to 20 or population to 30
Memory error	Reduce dataset size below 10,000 rows
Port 5000 in use	Change port: app.run(port=5001)
### 🔮 Future Enhancements
[ ] Multi-objective optimization (detection vs performance)
[ ] Support for SNORT/Suricata rule syntax
[ ] Real-time network data integration
[ ] Deep learning classifier comparison
[ ] Distributed GA using multiprocessing
[ ] Rule complexity penalty in fitness
[ ] Cross-validation for threshold stability
[ ] Export rules to IDS configuration files

Version: 1.0.0
Last Updated: March 2025
Status: Student Project / Educational Tool
