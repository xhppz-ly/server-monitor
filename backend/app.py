import sqlite3
import paramiko
import time
import threading
import json
import os
import datetime
import queue
import subprocess
from flask import Flask, request, jsonify, Response
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

# --- 优化后的 Agent 脚本（支持进程监控）---
AGENT_SCRIPT = r"""
import json, os, time, subprocess
def get_data():
    data = {"cpu": {"total": 0, "user": 0, "system": 0, "nice": 0, "iowait": 0, "steal": 0}, "load": {"1m": 0, "5m": 0, "15m": 0}, "memory": {"used": 0, "cached": 0, "free": 0, "total": 0}, "swap": {"used": 0, "total": 0}, "disk": 0, "net": {"up": 0, "down": 0}, "uptime": "", "processes": []}
    try:
        with open('/proc/stat', 'r') as f:
            cpu_line = f.readline().split()
        user, nice, system, idle, iowait, irq, softirq, steal = map(int, cpu_line[1:9])
        total = user + nice + system + iowait + irq + softirq + steal
        data["cpu"] = {"total": round((total / (total + idle)) * 100, 1), "user": round((user / (total + idle)) * 100, 1), "system": round((system / (total + idle)) * 100, 1), "nice": round((nice / (total + idle)) * 100, 1), "iowait": round((iowait / (total + idle)) * 100, 1), "steal": round((steal / (total + idle)) * 100, 1)}
        with open('/proc/loadavg', 'r') as f:
            loads = f.read().split()
        data["load"] = {"1m": float(loads[0]), "5m": float(loads[1]), "15m": float(loads[2])}
        mem_info = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split()
                mem_info[parts[0].rstrip(':')] = int(parts[1])
        total_mem = mem_info.get('MemTotal', 1)
        used_mem = total_mem - mem_info.get('MemAvailable', 0)
        cached_mem = mem_info.get('Cached', 0) + mem_info.get('Buffers', 0)
        data["memory"] = {"used": round(used_mem / 1024, 1), "cached": round(cached_mem / 1024, 1), "free": round(mem_info.get('MemAvailable', 0) / 1024, 1), "total": round(total_mem / 1024, 1)}
        data["swap"] = {"used": round((mem_info.get('SwapTotal', 0) - mem_info.get('SwapFree', 0)) / 1024), "total": round(mem_info.get('SwapTotal', 0) / 1024)}
        disk = os.statvfs('/')
        disk_total = disk.f_blocks * disk.f_frsize
        disk_free = disk.f_bfree * disk.f_frsize
        data["disk"] = round(((disk_total - disk_free) / disk_total) * 100, 1)
        def get_net_bytes():
            try:
                with open('/proc/net/dev', 'r') as f:
                    recv, sent = 0, 0
                    for line in f:
                        if ':' in line and line.strip()[0] not in ('#', 'I'):
                            iface = line.split(':')[0].strip()
                            if iface != 'lo':
                                nums = line.split(':')[1].split()
                                recv += int(nums[0])
                                sent += int(nums[8])
                    return recv, sent
            except: return 0, 0
        r1, t1 = get_net_bytes()
        time.sleep(0.5)
        r2, t2 = get_net_bytes()
        data["net"]["down"] = round((r2 - r1) / 1024 / 1024 * 2, 2)
        data["net"]["up"] = round((t2 - t1) / 1024 / 1024 * 2, 2)
        with open('/proc/uptime', 'r') as f:
            uptime_sec = int(float(f.read().split()[0]))
        days = uptime_sec // 86400
        hours = (uptime_sec % 86400) // 3600
        minutes = (uptime_sec % 3600) // 60
        data["uptime"] = f"{days}d {hours}h {minutes}m"
        try:
            ps_output = subprocess.check_output("ps -eo pid,comm,user,%cpu,%mem --sort=-%cpu --no-headers | head -40", shell=True, text=True)
            for line in ps_output.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5: data["processes"].append({"pid": int(parts[0]), "name": parts[1], "user": parts[2], "cpu": float(parts[3]), "mem": float(parts[4])})
        except: pass
        print(json.dumps(data))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
get_data()
"""

# --- SSE 实时流管理 ---
class StreamManager:
    def __init__(self):
        self.connections = {}
        self.lock = threading.Lock()
    
    def add_connection(self, host_id):
        with self.lock:
            if host_id not in self.connections:
                self.connections[host_id] = {
                    "queue": queue.Queue(maxsize=10),
                    "ssh": None,
                    "last_reconnect": 0,
                    "clients": 0
                }
            self.connections[host_id]["clients"] += 1
    
    def remove_connection(self, host_id):
        with self.lock:
            if host_id in self.connections:
                self.connections[host_id]["clients"] -= 1
                if self.connections[host_id]["clients"] <= 0:
                    self._cleanup(host_id)
    
    def _cleanup(self, host_id):
        if host_id in self.connections:
            ssh = self.connections[host_id].get("ssh")
            if ssh:
                try:
                    ssh.close()
                except:
                    pass
            del self.connections[host_id]
    
    def get_queue(self, host_id):
        with self.lock:
            if host_id in self.connections:
                return self.connections[host_id]["queue"]
        return None
    
    def get_ssh_client(self, host_id):
        with self.lock:
            if host_id not in self.connections:
                return None
            
            conn_info = self.connections[host_id]
            now = time.time()
            
            if conn_info["ssh"] is None and (now - conn_info["last_reconnect"]) < 5:
                return None
            
            if conn_info["ssh"] is not None:
                try:
                    conn_info["ssh"].exec_command("echo 1")
                    return conn_info["ssh"]
                except:
                    try:
                        conn_info["ssh"].close()
                    except:
                        pass
                    conn_info["ssh"] = None
            
            return None
    
    def set_ssh_client(self, host_id, ssh):
        with self.lock:
            if host_id in self.connections:
                self.connections[host_id]["ssh"] = ssh
                self.connections[host_id]["last_reconnect"] = time.time()

stream_mgr = StreamManager()

class RealTimeCollector(threading.Thread):
    def __init__(self, host_id, host_info, agent_script):
        super().__init__(daemon=True)
        self.host_id = host_id
        self.ip, self.username, self.password, self.port = host_info
        self.agent_script = agent_script
        self.running = True
    
    def run(self):
        while self.running:
            try:
                ssh = stream_mgr.get_ssh_client(self.host_id)
                if ssh is None:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.ip, port=self.port, username=self.username,
                               password=self.password, timeout=10)
                    stream_mgr.set_ssh_client(self.host_id, ssh)
                
                stdin, stdout, stderr = ssh.exec_command(
                    'python3 -c "{}"'.format(self.agent_script.replace('"', '\\"'))
                )
                output = stdout.read().decode().strip()
                
                if output:
                    data = json.loads(output)
                    data["timestamp"] = datetime.datetime.utcnow().isoformat() + 'Z'
                    
                    q = stream_mgr.get_queue(self.host_id)
                    if q:
                        try:
                            q.put_nowait(data)
                        except queue.Full:
                            try:
                                q.get_nowait()
                                q.put_nowait(data)
                            except:
                                pass
                
                time.sleep(1)
            
            except Exception as e:
                error_data = {
                    "error": "SSH connection failure",
                    "detail": str(e),
                    "timestamp": datetime.datetime.utcnow().isoformat() + 'Z'
                }
                q = stream_mgr.get_queue(self.host_id)
                if q:
                    try:
                        q.put_nowait(error_data)
                    except:
                        pass
                time.sleep(5)
    
    def stop(self):
        self.running = False

active_collectors = {}

@app.route('/api/stream/<int:host_id>')
def stream(host_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT ip, username, password, port FROM hosts WHERE id=?", (host_id,))
    host = c.fetchone()
    conn.close()
    
    if not host:
        return json.dumps({"error": "Host not found"}), 404
    
    ip, username, enc_pwd, port = host
    password = decrypt_pwd(enc_pwd)
    
    stream_mgr.add_connection(host_id)
    
    if host_id not in active_collectors:
        collector = RealTimeCollector(host_id, (ip, username, password, port), AGENT_SCRIPT)
        collector.start()
        active_collectors[host_id] = collector
    
    def event_generator():
        try:
            while True:
                q = stream_mgr.get_queue(host_id)
                if q is None:
                    break
                
                try:
                    data = q.get(timeout=5)
                    yield f"data: {json.dumps(data)}\n\n"
                except queue.Empty:
                    yield f": keepalive\n\n"
                except:
                    break
        finally:
            stream_mgr.remove_connection(host_id)
    
    return Response(event_generator(), mimetype='text/event-stream',
                   headers={
                       'Cache-Control': 'no-cache',
                       'Connection': 'keep-alive',
                       'X-Accel-Buffering': 'no'
                   })

# --- 数据采集与告警逻辑 ---
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
        
        # 从新Agent脚本中提取需要的数据
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''INSERT INTO metrics 
                     (host_id, cpu, memory_usage, memory_total, memory_used, 
                      disk_usage, net_up, net_down, load_1, load_5, load_15, uptime)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (host_id, metrics['cpu']['total'], 
                   round((metrics['memory']['used'] / metrics['memory']['total']) * 100, 1),
                   metrics['memory']['total'], metrics['memory']['used'],
                   metrics['disk'], metrics['net']['up'], metrics['net']['down'], 
                   metrics['load']['1m'], metrics['load']['5m'], metrics['load']['15m'], 
                   metrics['uptime']))
        check_alerts(c, host_id, ip, metrics, cpu_thr, mem_thr, disk_thr)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Connection failed {ip}: {str(e)}")
        log_alert(host_id, 'Offline', f'主机 {ip} 连接失败: {str(e)}', 'danger')

def check_alerts(cursor, host_id, ip, m, cpu_thr, mem_thr, disk_thr):
    cpu_val = m['cpu']['total']
    mem_val = round((m['memory']['used'] / m['memory']['total']) * 100, 1)
    disk_val = m['disk']
    
    if cpu_val > cpu_thr:
        log_alert_db(cursor, host_id, 'CPU', f'{ip} CPU使用率过高: {cpu_val}% > {cpu_thr}%', 'danger')
    if mem_val > mem_thr:
        log_alert_db(cursor, host_id, 'Memory', f'{ip} 内存不足: {mem_val}% > {mem_thr}%', 'warning')
    if disk_val > disk_thr:
        log_alert_db(cursor, host_id, 'Disk', f'{ip} 磁盘空间不足: {disk_val}%', 'danger')

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
                last_time = datetime.datetime.strptime(r[10], '%Y-%m-%d %H:%M:%S')
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
        time_str = r[0][11:19]
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