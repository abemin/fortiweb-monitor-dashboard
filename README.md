# FortiWeb Analytics Dashboard

A comprehensive, real-time, and historical analytics dashboard for **Fortinet FortiWeb** WAF appliances.

This application connects to the FortiWeb REST API to pull system statistics, traffic throughput, and threat intelligence data. It stores historical data in a local SQLite database and visualizes it using interactive charts.

---

## 🚀 Features

### 📊 Live Dashboard
* **Real-time Metrics:** Monitors CPU, Memory, Disk usage, Total Concurrent Connections, and Connections Per Second (CPS).
* **Live Throughput Chart:** Auto-scaling line chart (Kbps/Mbps) updating every 5 seconds.
* **Interface Monitor:** Visual status for Management ports, Data ports, LACP (LAG), and VLAN interfaces using color-coded indicators.
* **Threat Intelligence:** Aggregated top attack countries and attack types (Last 5 minutes window).
* **Live Policy Monitor:** Filterable list of active traffic policies with throughput and connection stats.

### 🕰️ Historical Analysis
* **Data Recording:** Background job logs system stats every 60 seconds into a persistent SQLite database.
* **Smart Timeline:** "Gap-filling" logic ensures charts display the full selected time range (5m, 1h, 24h) even if data points are sparse.
* **Visualizations:**
    1.  **System Performance:** CPU & Memory usage.
    2.  **System Throughput:** Inbound vs. Outbound traffic (Kbps/Mbps).
    3.  **Connection Metrics:** Concurrent Connections vs. CPS.
* **Policy Drill-down:** Filter historical data by specific Traffic Policies.
* **Exports:**
    * 📷 **Image Export:** Download individual charts as PNG.
    * 📄 **CSV Export:** Download raw data tables with separate Date/Time columns.

---

## 🛠️ Prerequisites

1.  **FortiWeb Device:** Network access to the FortiWeb Management Interface.
2.  **API Access:** An Administrator REST API Token from FortiWeb.
    * *Go to System > Admin > Administrators > Create New > Type: REST API Admin.*
3.  **Docker & Docker Compose** (Recommended) **OR** Python 3.9+.

---

## 🐳 Deployment (Docker) - Recommended

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/abemin/fortiweb-monitor-dashboard.git
    cd fortiweb-monitor-dashboard
    ```

2.  **Create the `.env` file:**
    ```bash
    echo "FW_IP=192.168.1.99:8443" > .env
    echo "FW_TOKEN=your_api_token_here" >> .env
    ```

3.  **Build and Run:**
    ```bash
    docker-compose up --build -d
    ```

4.  **Access the Dashboard:**
    Open your browser and navigate to `http://localhost:9000`.

---

## 🐍 Manual Installation (Python)

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Set Environment Variables (Linux/Mac):**
    ```bash
    export FW_IP="192.168.1.99:8443"
    export FW_TOKEN="your_token"
    ```
    *(For Windows PowerShell: `$env:FW_IP="..."; $env:FW_TOKEN="..."`)*

3.  **Run the Application:**
    ```bash
    python app.py
    ```

---

## 📂 Project Structure

```text
.
├── app.py                # Main Flask Backend & Scheduler Logic
├── requirements.txt      # Python dependencies
├── Dockerfile            # Docker image definition
├── docker-compose.yml    # Container orchestration config
├── stats.db              # SQLite Database (Auto-created)
├── templates/
│   └── index.html        # Frontend Dashboard (HTML/JS/CSS)
└── README.md             # Project Documentation
```

## 🌍 Timezone Configuration
The application is strictly configured for Malaysia Time (MYT / UTC+8) to align database logging and frontend display.

To change this to your local timezone:

Backend (app.py): Search for hours=8 and change the offset.

Frontend (index.html): Search for Asia/Kuala_Lumpur and replace it with your IANA timezone string (e.g., America/New_York).

## 📝 License
This project is open-source. Feel free to modify and distribute it for your own monitoring needs.


## Screenshots

![Alt text](/screenshots/SCR-20251229-pnxq.png)

![Alt text](/screenshots/SCR-20251229-poad.png)
