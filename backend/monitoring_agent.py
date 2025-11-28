"""
监控 Agent 脚本 - 可直接嵌入 python3 -c 执行
包含：CPU、内存、磁盘、网络、进程采集
执行方式：python3 -c "$(cat monitoring_agent.py)"
"""

import json
import os
import time
import subprocess

def get_monitoring_data():
    """采集完整监控数据（含进程）"""
    data = {
        "cpu": {"total": 0, "user": 0, "system": 0, "nice": 0, "iowait": 0, "steal": 0},
        "load": {"1m": 0, "5m": 0, "15m": 0},
        "memory": {"used": 0, "cached": 0, "free": 0, "total": 0},
        "swap": {"used": 0, "total": 0},
        "disk": 0,
        "net": {"up": 0, "down": 0},
        "uptime": "",
        "processes": []
    }

    try:
        # ===== CPU 采集 =====
        with open('/proc/stat', 'r') as f:
            cpu_line = f.readline().split()
        user, nice, system, idle, iowait, irq, softirq, steal = map(int, cpu_line[1:9])
        total = user + nice + system + iowait + irq + softirq + steal
        data["cpu"] = {
            "total": round((total / (total + idle)) * 100, 1),
            "user": round((user / (total + idle)) * 100, 1),
            "system": round((system / (total + idle)) * 100, 1),
            "nice": round((nice / (total + idle)) * 100, 1),
            "iowait": round((iowait / (total + idle)) * 100, 1),
            "steal": round((steal / (total + idle)) * 100, 1)
        }

        # ===== 负载采集 =====
        with open('/proc/loadavg', 'r') as f:
            loads = f.read().split()
        data["load"] = {"1m": float(loads[0]), "5m": float(loads[1]), "15m": float(loads[2])}

        # ===== 内存采集 =====
        mem_info = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split()
                mem_info[parts[0].rstrip(':')] = int(parts[1])
        
        total_mem = mem_info.get('MemTotal', 1)
        used_mem = total_mem - mem_info.get('MemAvailable', 0)
        cached_mem = mem_info.get('Cached', 0) + mem_info.get('Buffers', 0)
        
        data["memory"] = {
            "used": round(used_mem / 1024, 1),
            "cached": round(cached_mem / 1024, 1),
            "free": round(mem_info.get('MemAvailable', 0) / 1024, 1),
            "total": round(total_mem / 1024, 1)
        }
        
        data["swap"] = {
            "used": round(mem_info.get('SwapTotal', 0) - mem_info.get('SwapFree', 0)) // 1024,
            "total": round(mem_info.get('SwapTotal', 0) // 1024)
        }

        # ===== 磁盘采集 =====
        disk = os.statvfs('/')
        disk_total = disk.f_blocks * disk.f_frsize
        disk_free = disk.f_bfree * disk.f_frsize
        data["disk"] = round(((disk_total - disk_free) / disk_total) * 100, 1)

        # ===== 网络采集 =====
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
            except:
                return 0, 0
        
        r1, t1 = get_net_bytes()
        time.sleep(0.5)
        r2, t2 = get_net_bytes()
        data["net"]["down"] = round((r2 - r1) / 1024 / 1024 * 2, 2)
        data["net"]["up"] = round((t2 - t1) / 1024 / 1024 * 2, 2)

        # ===== Uptime 采集 =====
        with open('/proc/uptime', 'r') as f:
            uptime_sec = int(float(f.read().split()[0]))
        days = uptime_sec // 86400
        hours = (uptime_sec % 86400) // 3600
        minutes = (uptime_sec % 3600) // 60
        data["uptime"] = f"{days}d {hours}h {minutes}m"

        # ===== 进程采集（前40个） =====
        try:
            ps_output = subprocess.check_output(
                "ps -eo pid,comm,user,%cpu,%mem --sort=-%cpu --no-headers | head -40",
                shell=True, text=True
            )
            for line in ps_output.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        data["processes"].append({
                            "pid": int(parts[0]),
                            "name": parts[1],
                            "user": parts[2],
                            "cpu": float(parts[3]),
                            "mem": float(parts[4])
                        })
        except Exception as e:
            pass  # 进程采集失败不影响其他数据

        print(json.dumps(data, ensure_ascii=False))

    except Exception as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))

if __name__ == '__main__':
    get_monitoring_data()