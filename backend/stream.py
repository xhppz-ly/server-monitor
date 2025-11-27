"""
SSE 实时数据流接口模块
- 1秒级实时推送
- 支持多并发连接
- 防止SSH重连风暴
"""

import json
import time
import threading
import queue
import paramiko
import datetime
from flask import Response, request
from functools import wraps

# 全局状态管理
class StreamManager:
    def __init__(self):
        self.connections = {}  # {host_id: {"queue": queue, "ssh": ssh_client, "last_reconnect": time}}
        self.lock = threading.Lock()
    
    def add_connection(self, host_id):
        """添加新连接"""
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
        """移除连接"""
        with self.lock:
            if host_id in self.connections:
                self.connections[host_id]["clients"] -= 1
                if self.connections[host_id]["clients"] <= 0:
                    self._cleanup(host_id)
    
    def _cleanup(self, host_id):
        """清理连接资源"""
        if host_id in self.connections:
            ssh = self.connections[host_id].get("ssh")
            if ssh:
                try:
                    ssh.close()
                except:
                    pass
            del self.connections[host_id]
    
    def get_queue(self, host_id):
        """获取连接队列"""
        with self.lock:
            if host_id in self.connections:
                return self.connections[host_id]["queue"]
        return None
    
    def get_ssh_client(self, host_id):
        """获取或创建SSH连接"""
        with self.lock:
            if host_id not in self.connections:
                return None
            
            conn_info = self.connections[host_id]
            now = time.time()
            
            # 防止重连风暴：5秒内不重试
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
        """设置SSH连接"""
        with self.lock:
            if host_id in self.connections:
                self.connections[host_id]["ssh"] = ssh
                self.connections[host_id]["last_reconnect"] = time.time()

stream_mgr = StreamManager()


class RealTimeCollector(threading.Thread):
    """实时数据采集线程"""
    
    def __init__(self, host_id, host_info, agent_script):
        super().__init__(daemon=True)
        self.host_id = host_id
        self.ip, self.username, self.password, self.port = host_info
        self.agent_script = agent_script
        self.running = True
    
    def run(self):
        """1秒循环采集"""
        while self.running:
            try:
                # 获取或创建SSH连接
                ssh = stream_mgr.get_ssh_client(self.host_id)
                if ssh is None:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.ip, port=self.port, username=self.username,
                               password=self.password, timeout=10)
                    stream_mgr.set_ssh_client(self.host_id, ssh)
                
                # 执行Agent脚本
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
                                q.get_nowait()  # 丢弃最旧数据
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
                time.sleep(5)  # 错误后等待5秒重试
    
    def stop(self):
        self.running = False


def stream_handler(app, db_decrypt_func, agent_script):
    """
    SSE流处理器工厂函数
    参数：
      - app: Flask应用
      - db_decrypt_func: 密码解密函数
      - agent_script: Agent脚本内容
    """
    
    active_collectors = {}  # {host_id: collector_thread}
    
    @app.route('/api/stream/<int:host_id>')
    def stream(host_id):
        """SSE实时数据流接口"""
        
        # 从DB获取主机信息
        import sqlite3
        conn = sqlite3.connect('data/monitor_v2.db')
        c = conn.cursor()
        c.execute("SELECT ip, username, password, port FROM hosts WHERE id=?", (host_id,))
        host = c.fetchone()
        conn.close()
        
        if not host:
            return json.dumps({"error": "Host not found"}), 404
        
        ip, username, enc_pwd, port = host
        password = db_decrypt_func(enc_pwd)
        
        # 添加连接
        stream_mgr.add_connection(host_id)
        
        # 启动采集线程（如果未启动）
        if host_id not in active_collectors:
            collector = RealTimeCollector(host_id, (ip, username, password, port), agent_script)
            collector.start()
            active_collectors[host_id] = collector
        
        def event_generator():
            """生成SSE事件流"""
            try:
                while True:
                    q = stream_mgr.get_queue(host_id)
                    if q is None:
                        break
                    
                    try:
                        data = q.get(timeout=5)
                        yield f"data: {json.dumps(data)}\n\n"
                    except queue.Empty:
                        yield f": keepalive\n\n"  # 心跳
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
    
    return stream
