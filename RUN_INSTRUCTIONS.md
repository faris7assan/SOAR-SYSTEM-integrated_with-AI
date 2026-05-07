# AegisNDR - Enterprise Dashboard & Engine

This document explains how to set up and run the AegisNDR platform locally.

## 1. Prerequisites
- **Python 3.14+** (already installed on this machine).
- **Administrative Privileges** (required for live packet capture, not needed for Mock mode).

## 2. Installation
Run the following command to install all necessary dependencies:

```powershell
& "C:\Users\Hassan\AppData\Local\Programs\Python\Python314\python.exe" -m pip install pysimplegui scapy fastapi uvicorn[standard] PyJWT pydantic numpy matplotlib pandas aiofiles aiohttp
```

*(Note: Dependencies have already been installed for you in the current environment.)*

## 3. Running the Dashboard (GUI)
The most intuitive way to use the system is via the integrated desktop GUI.

```powershell
& "C:\Users\Hassan\AppData\Local\Programs\Python\Python314\python.exe" "e:/Hassan INFO/Projects/AegisNDR enterprise platform/aegis-ndr/aegis-ndr/main.py" --gui
```

### Dashboard Features:
- **🚀 Start/Stop Engine**: Control the core detection pipeline.
- **📊 Live Metrics**: Real-time stats on packets, flows, alerts, and attack chains.
- **🚨 Alerts Table**: View detailed security findings with severity and scoring.
- **📡 Flows Table**: Monitor active network sessions.
- **⚔️ Simulation**: Trigger a mock attack to test detection logic (requires Mock Mode).
- **📋 System Logs**: Integrated console view for debugging and auditing.

## 4. Command Line Usage (CLI)
You can also run the engine without the GUI using the following flags:

- **Mock Mode (Recommended for testing)**:
  ```powershell
  & "C:\Users\Hassan\AppData\Local\Programs\Python\Python314\python.exe" "e:/Hassan INFO/Projects/AegisNDR enterprise platform/aegis-ndr/aegis-ndr/main.py" --mock
  ```
- **Live Capture (Requires root/admin)**:
  ```powershell
  & "C:\Users\Hassan\AppData\Local\Programs\Python\Python314\python.exe" "e:/Hassan INFO/Projects/AegisNDR enterprise platform/aegis-ndr/aegis-ndr/main.py" --interface eth0
  ```
- **Simulation**:
  ```powershell
  & "C:\Users\Hassan\AppData\Local\Programs\Python\Python314\python.exe" "e:/Hassan INFO/Projects/AegisNDR enterprise platform/aegis-ndr/aegis-ndr/main.py" --mock --simulate
  ```

## 5. API Documentation
When the engine is running, the REST API documentation is available at:
`http://localhost:8000/docs`

---
*Created by AegisNDR AI Assistant*
