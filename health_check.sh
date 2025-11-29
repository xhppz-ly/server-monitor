#!/bin/bash
#系统健康检查脚本

TARGET_URL="http://localhost:8080"
LOG_FILE="./health_check.log"

echo "[$(date)] Starting Health Check..." >> $LOG_FILE

# 1. 检查 Docker 容器状态
if [ "$(docker ps -q -f name=monitor-backend)" ]; then
    echo "✅ Backend Container is running."
else
    echo "❌ Backend Container is DOWN!"
    exit 1
fi

# 2. 检查 Web 服务可用性
HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}\n" $TARGET_URL)
if [ "$HTTP_CODE" == "200" ]; then
    echo "✅ Web Service is available (HTTP 200)."
else
    echo "❌ Web Service Error: HTTP $HTTP_CODE"
    exit 1
fi

echo "[$(date)] Health Check Passed." >> $LOG_FILE
