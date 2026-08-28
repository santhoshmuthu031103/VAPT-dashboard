# VAPT Dashboard

A comprehensive Vulnerability Assessment and Penetration Testing (VAPT) platform designed to provide a unified interface for multiple security scanning tools.

## Features

* **Unified Dashboard**: Single pane of glass for all your security scanning needs.
* **Integrated Tools**: Seamlessly integrates with industry-standard tools:
  * Nmap (Network Discovery & Port Scanning)
  * OWASP ZAP (Dynamic Application Security Testing)
  * Nuclei (Fast and customizable vulnerability scanner)
  * Nikto (Web server scanner)
  * Gobuster (Directory/File & DNS busting)
  * SQLMap (Automatic SQL injection and database takeover)
  * OpenVAS/GVM (Comprehensive vulnerability scanning)
* **Target Management**: Group and manage targets efficiently.
* **Interactive Scanners**: Run scans on-demand and view real-time results.
* **Scheduling**: Schedule recurring scans for continuous monitoring.
* **Reporting**: Generate comprehensive VAPT reports.

## Tech Stack

* **Frontend**: React, Vite
* **Backend**: FastAPI (Python)
* **API Communication**: REST API

## Development Setup

### Prerequisites
* Node.js and npm
* Python 3.8+
* Security tools installed locally (nmap, nuclei, nikto, gobuster, sqlmap, zap)

### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev --host
   ```

### Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the backend development server (Uvicorn):
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

## Disclaimer

This tool is designed for educational and professional security testing purposes only. Users must ensure they have explicit permission to scan any targets. The developers are not responsible for any misuse or damage caused by this software.
