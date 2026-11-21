# NIDS-LAB
### Network Intrusion Detection System

NIDS-LAB is a Python-based Network Intrusion Detection System designed to analyze network traffic and identify suspicious activities using PCAP (Packet Capture) files.

The project uses Flask to provide a web-based dashboard and Scapy for network packet analysis.

## Features

- Upload and analyze PCAP files
- Inspect captured network packets
- Identify network protocols
- Detect suspicious network activity using detection rules
- View analysis statistics on a web dashboard

## Technologies Used

- Python
- Flask
- Scapy
- HTML
- CSS

## Project Structure

```text
NIDS-LAB/
├── app.py
├── detector.py
├── requirements.txt
├── README.md
├── templates/
│   └── index.html
├── static/
│   └── style.css
├── data/
└── uploads/
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/NIDS-LAB.git
cd NIDS-LAB
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

### 3. Activate the virtual environment

**macOS / Linux:**

```bash
source venv/bin/activate
```

**Windows:**

```bash
venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
python3 app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## Project Objective

The objective of NIDS-LAB is to explore network security, packet analysis, and intrusion detection through a practical Python-based application.

## Future Development

- Improved intrusion detection rules
- User authentication and individual dashboards
- Analysis history and security reports
- Advanced threat detection
- Live network traffic monitoring
- Secure cloud deployment

## Disclaimer

This project is intended for educational and authorized cybersecurity testing. Only analyze network traffic that you own or have permission to inspect.

## Author

Developed as a practical cybersecurity and network security project.

**Project:** NIDS-LAB  
**Version:** 1.0
