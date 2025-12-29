import os
import sqlite3
import requests
import urllib3
import time
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, render_template, request, Response
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
import csv
import io

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# --- CONFIG ---
FW_IP = os.getenv("FW_IP", "")
FW_TOKEN = os.getenv("FW_TOKEN", "")
DB_FILE = "stats.db"

# Endpoints
EP_STATUS = "/api/v2.0/system/status.monitor" 

def get_headers():
    return {
        "Authorization": FW_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS system_stats 
                 (timestamp TEXT, cpu INTEGER, memory INTEGER, disk INTEGER, 
                  tcp_conns INTEGER, tcp_cps INTEGER, t_in INTEGER, t_out INTEGER)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS policy_stats 
                 (timestamp TEXT, policy_name TEXT, 
                  tcp_conns INTEGER, tcp_cps INTEGER, t_in INTEGER, t_out INTEGER)''')

    # Threat Events Table
    c.execute('''CREATE TABLE IF NOT EXISTS threat_events 
                 (timestamp TEXT, category TEXT, name TEXT, count INTEGER)''')
    
    conn.commit()
    conn.close()

# --- LOGGING TASK ---
def log_data_task():
    if not FW_IP: return

    url = f"https://{FW_IP}{EP_STATUS}?interval=1"
    try:
        resp = requests.get(url, headers=get_headers(), verify=False, timeout=10)
        if resp.status_code != 200: return
        data = resp.json().get('results', {})
        
        # ISO FORMAT WITH MYT OFFSET (+08:00)
        tz_myt = timezone(timedelta(hours=8))
        timestamp = datetime.now(tz_myt).isoformat() 

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        # 1. System Stats
        c.execute("INSERT INTO system_stats VALUES (?,?,?,?,?,?,?,?)", 
                  (timestamp, data.get('cpu',0), data.get('memory',0), data.get('log_disk',0),
                   data.get('tcp_concurrent_connection',0), data.get('tcp_connection_per_second',0),
                   data.get('throughput_in',0), data.get('throughput_out',0)))

        # 2. Policy Stats
        policies = data.get('policy', [])
        for p in policies:
            info = p.get('info', {})
            if info.get('throughput_in',0) > 0 or info.get('tcp_concurrent_connection',0) > 0:
                c.execute("INSERT INTO policy_stats VALUES (?,?,?,?,?,?)",
                          (timestamp, p.get('name'), 
                           info.get('tcp_concurrent_connection',0), info.get('tcp_connection_per_second',0),
                           info.get('throughput_in',0), info.get('throughput_out',0)))
        
        # 3. Threat Stats
        for item in data.get('threat_by_countries', []):
            count = int(item.get('count', 0))
            if count > 0:
                c.execute("INSERT INTO threat_events VALUES (?,?,?,?)", (timestamp, 'country', item.get('country'), count))
        
        for item in data.get('threat_by_attack_type', []):
            count = int(item.get('count', 0))
            if count > 0:
                c.execute("INSERT INTO threat_events VALUES (?,?,?,?)", (timestamp, 'type', item.get('type'), count))

        conn.commit()
        conn.close()
        print(f"[{timestamp}] Logged.")

    except Exception as e:
        print(f"Logging failed: {e}")

# Start Scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=log_data_task, trigger="interval", seconds=60)
scheduler.start()
init_db()

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/monitor')
def proxy_monitor():
    if not FW_IP: return jsonify({"error": "Config missing"}), 500
    try:
        url = f"https://{FW_IP}/api/v2.0/system/network.interface"
        return jsonify(requests.get(url, headers=get_headers(), verify=False).json())
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/status')
def proxy_status():
    if not FW_IP: return jsonify({"error": "Config missing"}), 500
    try:
        url = f"https://{FW_IP}/api/v2.0/system/status.monitor?interval=1"
        return jsonify(requests.get(url, headers=get_headers(), verify=False).json())
    except Exception as e: return jsonify({"error": str(e)}), 500

# THREATS AGGREGATION
@app.route('/api/threats/recent')
def get_recent_threats():
    tz_myt = timezone(timedelta(hours=8))
    start_time = (datetime.now(tz_myt) - timedelta(minutes=5)).isoformat()
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT name, SUM(count) as total FROM threat_events WHERE category='country' AND timestamp > ? GROUP BY name ORDER BY total DESC", (start_time,))
    countries = [{"country": r[0], "count": r[1]} for r in c.fetchall()]
    
    c.execute("SELECT name, SUM(count) as total FROM threat_events WHERE category='type' AND timestamp > ? GROUP BY name ORDER BY total DESC", (start_time,))
    attacks = [{"type": r[0], "count": r[1]} for r in c.fetchall()]
    
    conn.close()
    return jsonify({"threat_by_countries": countries, "threat_by_attack_type": attacks})

@app.route('/api/history')
def get_history():
    time_range = request.args.get('range', '5m')
    policy_filter = request.args.get('policy', 'Total System')

    tz_myt = timezone(timedelta(hours=8))
    now = datetime.now(tz_myt)
    
    if time_range == '5m': start_time = now - timedelta(minutes=5)
    elif time_range == '1h': start_time = now - timedelta(hours=1)
    elif time_range == '24h': start_time = now - timedelta(hours=24)
    else: start_time = now - timedelta(minutes=5)
    
    start_iso = start_time.isoformat()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    results = []
    if policy_filter == 'Total System':
        c.execute("SELECT * FROM system_stats WHERE timestamp > ? ORDER BY timestamp ASC", (start_iso,))
        rows = c.fetchall()
        for r in rows:
            results.append({
                "time": r[0], "cpu": r[1], "mem": r[2], "disk": r[3],
                "tcp_conns": r[4], "tcp_cps": r[5], "t_in": r[6], "t_out": r[7]
            })
    else:
        c.execute("SELECT timestamp, tcp_conns, tcp_cps, t_in, t_out FROM policy_stats WHERE policy_name = ? AND timestamp > ? ORDER BY timestamp ASC", (policy_filter, start_iso))
        rows = c.fetchall()
        for r in rows:
            results.append({
                "time": r[0], "tcp_conns": r[1], "tcp_cps": r[2], "t_in": r[3], "t_out": r[4]
            })
            
    conn.close()
    return jsonify(results)

@app.route('/api/policies')
def get_policies_list():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT DISTINCT policy_name FROM policy_stats")
    rows = c.fetchall()
    conn.close()
    return jsonify([r[0] for r in rows])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)