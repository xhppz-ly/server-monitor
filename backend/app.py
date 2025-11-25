import sqlite3
import paramiko
import time
import threading
import json
import os
import datetime # 确保导入了 datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)

# --- 配置与加密 ---
DATA_DIR = 'data'
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)
DB_FILE = os.path.join(DATA_DIR, 'monitor_v2.db')

KEY_FILE = os.path.join(DATA_DIR, 'secret.key')
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(Fernet.generate_key())
with open(KEY_FILE, 'rb') as key_file:
    CIPHER_SUITE = Fernet(key_file.read())

def encrypt_pwd(pwd):
    return CIPHER_SUITE.encrypt(pwd.encode()).decode()

def decrypt_pwd(enc_pwd):
    return CIPHER_SUITE.decrypt(enc_pwd.encode()).decode()

# --- 数据库初始化 ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS hosts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip TEXT, username TEXT, password TEXT, port INTEGER, 
                  name TEXT, description TEXT,
                  cpu_threshold INTEGER DEFAULT 80,
                  mem_threshold INTEGER DEFAULT 80,
                  disk_threshold INTEGER DEFAULT 90)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS metrics
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  host_id INTEGER, 
                  cpu REAL, 
                  memory_usage REAL, memory_total REAL, memory_used REAL,
                  disk_usage REAL,
                  net_up REAL, net_down REAL,
                  load_1 REAL, load_5 REAL, load_15 REAL,
                  uptime TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  host_id INTEGER, type TEXT, message TEXT, level TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

# --- Agent 脚本 ---
AGENT_SCRIPT = r"""
import json, os, time
def get_data():
    data = {}
    try:
        cpu_cmd = os.popen("top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'")
        try: data['cpu'] = float(cpu_cmd.read().strip())
        except: data['cpu'] = 0.0

        mem_info = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split()
                mem_info[parts[0].rstrip(':')] = int(parts[1])
        total_mem = mem_info.get('MemTotal', 1) / 1024
        avail_mem = mem_info.get('MemAvailable', 0) / 1024
        data['mem_total'] = round(total_mem, 1)
        data['mem_used'] = round(total_mem - avail_mem, 1)
        data['mem_rate'] = round((data['mem_used'] / total_mem) * 100, 1)

        with open('/proc/loadavg', 'r') as f:
            loads = f.read().split()
            data['load_1'] = float(loads[0])
            data['load_5'] = float(loads[1])
            data['load_15'] = float(loads[2])

        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            data['uptime'] = f"{days}天 {hours}小时 {minutes}分"

        disk = os.statvfs('/')
        disk_total = (disk.f_blocks * disk.f_frsize)
        disk_free = (disk.f_bfree * disk.f_frsize)
        data['disk_usage'] = round(((disk_total - disk_free) / disk_total) * 100, 1)

        def get_net_bytes():
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' in line:
                        parts = line.split(':')
                        if parts[0].strip() != 'lo':
                            nums = parts[1].split()
                            return int(nums[0]), int(nums[8])
            return 0, 0
        
        r1, t1 = get_net_bytes()
        time.sleep(0.5)
        r2, t2 = get_net_bytes()
        data['net_down'] = round((r2 - r1) / 1024 / 1024 * 2, 2)
        data['net_up'] = round((t2 - t1) / 1024 / 1024 * 2, 2)

        print(json.dumps(data))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
get_data()
"""

# --- 采集与告警逻辑 ---
def collect_data(host):
    host_id, ip, username, enc_pwd, port, _, _, cpu_thr, mem_thr, disk_thr = host
    password = decrypt_pwd(enc_pwd)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=10)
        stdin, stdout, stderr = ssh.exec_command('python3 -c "{}"'.format(AGENT_SCRIPT.replace('"', '\\"')))
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        ssh.close()

        if not output or "error" in output:
            print(f"Error collecting from {ip}: {error or output}")
            return

        metrics = json.loads(output)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''INSERT INTO metrics 
                     (host_id, cpu, memory_usage, memory_total, memory_used, 
                      disk_usage, net_up, net_down, load_1, load_5, load_15, uptime)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (host_id, metrics['cpu'], metrics['mem_rate'], metrics['mem_total'], metrics['mem_used'],
                   metrics['disk_usage'], metrics['net_up'], metrics['net_down'], 
                   metrics['load_1'], metrics['load_5'], metrics['load_15'], metrics['uptime']))
        check_alerts(c, host_id, ip, metrics, cpu_thr, mem_thr, disk_thr)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Connection failed {ip}: {str(e)}")
        log_alert(host_id, 'Offline', f'主机 {ip} 连接失败: {str(e)}', 'danger')

def check_alerts(cursor, host_id, ip, m, cpu_thr, mem_thr, disk_thr):
    if m['cpu'] > cpu_thr:
        log_alert_db(cursor, host_id, 'CPU', f'{ip} CPU使用率过高: {m["cpu"]}% > {cpu_thr}%', 'danger')
    if m['mem_rate'] > mem_thr:
        log_alert_db(cursor, host_id, 'Memory', f'{ip} 内存不足: {m["mem_rate"]}% > {mem_thr}%', 'warning')
    if m['disk_usage'] > disk_thr:
        log_alert_db(cursor, host_id, 'Disk', f'{ip} 磁盘空间不足: {m["disk_usage"]}%', 'danger')

def log_alert(host_id, type, msg, level):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    log_alert_db(c, host_id, type, msg, level)
    conn.commit()
    conn.close()

def log_alert_db(cursor, host_id, type, msg, level):
    cursor.execute("INSERT INTO alerts (host_id, type, message, level) VALUES (?, ?, ?, ?)",
                   (host_id, type, msg, level))

def background_task():
    while True:
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT * FROM hosts")
            hosts = c.fetchall()
            conn.close()
            threads = []
            for host in hosts:
                t = threading.Thread(target=collect_data, args=(host,))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
        except Exception as e:
            print(e)
        time.sleep(10)

threading.Thread(target=background_task, daemon=True).start()

# --- API 接口 ---
@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    query = '''
        SELECT h.id, h.ip, h.name, h.description, 
               m.cpu, m.memory_usage, m.disk_usage, m.net_up, m.net_down, m.uptime, m.timestamp
        FROM hosts h
        LEFT JOIN (
            SELECT *, ROW_NUMBER() OVER (PARTITION BY host_id ORDER BY id DESC) as rn
            FROM metrics
        ) m ON h.id = m.host_id AND m.rn = 1
    '''
    c.execute(query)
    rows = c.fetchall()
    conn.close()
    
    data = []
    for r in rows:
        is_online = False
        if r[10]:
            try:
                # 数据库存的是 UTC，判断在线状态要对比 UTC 时间
                last_time = datetime.datetime.strptime(r[10], '%Y-%m-%d %H:%M:%S')
                # datetime.datetime.utcnow() 获取当前的 UTC 时间
                if (datetime.datetime.utcnow() - last_time).total_seconds() < 40:
                    is_online = True
            except:
                is_online = False
        
        data.append({
            "id": r[0], "ip": r[1], "name": r[2], "desc": r[3],
            "cpu": r[4] or 0, "mem": r[5] or 0, "disk": r[6] or 0,
            "net_up": r[7] or 0, "net_down": r[8] or 0, "uptime": r[9] or "N/A",
            "online": is_online
        })
    return jsonify(data)

@app.route('/api/hosts', methods=['POST'])
def add_host():
    data = request.json
    enc_pwd = encrypt_pwd(data['password'])
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''INSERT INTO hosts (ip, username, password, port, name, description, cpu_threshold, mem_threshold, disk_threshold) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (data['ip'], data['username'], enc_pwd, data.get('port', 22), 
               data.get('name', data['ip']), data.get('desc', ''), 
               data.get('cpu_thr', 80), data.get('mem_thr', 80), data.get('disk_thr', 90)))
    conn.commit()
    conn.close()
    return jsonify({"message": "Host added"})

@app.route('/api/hosts/<int:host_id>', methods=['DELETE'])
def delete_host(host_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM hosts WHERE id=?", (host_id,))
    c.execute("DELETE FROM metrics WHERE host_id=?", (host_id,))
    c.execute("DELETE FROM alerts WHERE host_id=?", (host_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted"})

@app.route('/api/overview', methods=['GET'])
def get_overview():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT count(*) FROM hosts")
    total_hosts = c.fetchone()[0]
    
    # 同样对告警时间进行 UTC+8 处理
    c.execute("SELECT type, message, level, timestamp FROM alerts ORDER BY id DESC LIMIT 10")
    alerts = []
    for r in c.fetchall():
        time_str = r[3]
        try:
            dt_utc = datetime.datetime.strptime(r[3], '%Y-%m-%d %H:%M:%S')
            dt_local = dt_utc + datetime.timedelta(hours=8)
            time_str = dt_local.strftime('%Y-%m-%d %H:%M:%S')
        except: pass
        alerts.append({"type": r[0], "msg": r[1], "level": r[2], "time": time_str})
        
    conn.close()
    return jsonify({
        "total_hosts": total_hosts,
        "alerts": alerts
    })

# --- 核心修改：历史数据时区修正 ---
@app.route('/api/history/<int:host_id>', methods=['GET'])
def get_history(host_id):
    limit = request.args.get('limit', 60)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''SELECT timestamp, cpu, memory_usage, disk_usage, net_up, net_down 
                 FROM metrics WHERE host_id=? ORDER BY id DESC LIMIT ?''', (host_id, limit))
    rows = c.fetchall()
    conn.close()
    
    data = []
    for r in reversed(rows):
        # 数据库中存储的是 UTC 时间
        # 这里的逻辑是手动 +8 小时，变成北京时间
        time_str = r[0][11:19] # 默认取后半截
        try:
            dt_utc = datetime.datetime.strptime(r[0], '%Y-%m-%d %H:%M:%S')
            dt_local = dt_utc + datetime.timedelta(hours=8)
            time_str = dt_local.strftime('%H:%M:%S')
        except Exception as e:
            pass
            
        data.append({
            "time": time_str, 
            "cpu": r[1], 
            "mem": r[2], 
            "disk": r[3],
            "net_up": r[4], 
            "net_down": r[5]
        })
        
    return jsonify(data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)