import os 
import sqlite3
import random
import time
import threading
import eventlet eventlet.monkey_patch() 
from datetime import datetime
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# Database setup
DATABASE = 'database.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            dest_ip TEXT,
            event_type TEXT,
            severity TEXT,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Simulated data generation
def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"

event_types = [
    ("Port Scan", "high"),
    ("Malware", "high"),
    ("Brute Force", "medium"),
    ("SQL Injection", "medium"),
    ("Phishing", "low"),
    ("DDoS", "high"),
    ("Unauthorized Access", "high"),
    ("Policy Violation", "low")
]

def generate_alert():
    event, sev = random.choice(event_types)
    return {
        'source_ip': random_ip(),
        'dest_ip': random_ip(),
        'event_type': event,
        'severity': sev,
        'description': f"Simulated {event} detected from {random_ip()} to {random_ip()}"
    }

def insert_alert(alert):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO alerts (source_ip, dest_ip, event_type, severity, description)
        VALUES (?, ?, ?, ?, ?)
    ''', (alert['source_ip'], alert['dest_ip'], alert['event_type'], alert['severity'], alert['description']))
    conn.commit()
    alert_id = c.lastrowid
    conn.close()
    return alert_id

def get_recent_alerts(limit=20):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        SELECT id, timestamp, source_ip, dest_ip, event_type, severity, description
        FROM alerts ORDER BY timestamp DESC LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'id': r[0], 'timestamp': r[1], 'source_ip': r[2], 'dest_ip': r[3],
             'event_type': r[4], 'severity': r[5], 'description': r[6]} for r in rows]

def get_chart_data():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # 1. Events per minute (last 30 minutes)
    c.execute('''
        SELECT strftime('%H:%M', timestamp) as minute, COUNT(*)
        FROM alerts
        WHERE timestamp >= datetime('now', '-30 minutes')
        GROUP BY minute
        ORDER BY minute
    ''')
    events_per_min = c.fetchall()
    minutes = [row[0] for row in events_per_min]
    counts = [row[1] for row in events_per_min]

    # 2. Severity distribution
    c.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
    sev_counts = dict(c.fetchall())
    for sev in ['low', 'medium', 'high']:
        sev_counts.setdefault(sev, 0)

    # 3. Top event types
    c.execute('''
        SELECT event_type, COUNT(*) as cnt
        FROM alerts
        GROUP BY event_type
        ORDER BY cnt DESC
        LIMIT 5
    ''')
    top_events = c.fetchall()
    event_labels = [row[0] for row in top_events]
    event_data = [row[1] for row in top_events]

    conn.close()
    return {
        'line_labels': minutes,
        'line_data': counts,
        'pie_labels': list(sev_counts.keys()),
        'pie_data': list(sev_counts.values()),
        'bar_labels': event_labels,
        'bar_data': event_data
    }

# Background task that generates alerts and pushes chart data every 5 seconds
def background_loop():
    last_chart_emit = time.time()
    while True:
        time.sleep(random.uniform(2, 5))
        alert = generate_alert()
        alert_id = insert_alert(alert)
        alert['id'] = alert_id
        alert['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        socketio.emit('new_alert', alert)

        if time.time() - last_chart_emit >= 5:
            chart_data = get_chart_data()
            socketio.emit('chart_update', chart_data)
            last_chart_emit = time.time()

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    recent = get_recent_alerts(20)
    chart = get_chart_data()
    emit('initial_data', {'alerts': recent, 'chart': chart})

if __name__ == '__main__':
    thread = threading.Thread(target=background_loop, daemon=True)
    thread.start()
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
