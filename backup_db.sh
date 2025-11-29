#!/bin/bash
# SQLite 数据库自动冷备份脚本

# 访问当前目录下的 backend_data
DATA_DIR="./backend_data"
BACKUP_DIR="./backend_data/backups"
DB_FILE="monitor_v2.db"
DATE_TAG=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

echo "Starting backup for $DB_FILE..."

# 备份操作
cp "$DATA_DIR/$DB_FILE" "$BACKUP_DIR/${DB_FILE}_$DATE_TAG.bak"

if [ $? -eq 0 ]; then
    echo "✅ Backup success: ${DB_FILE}_$DATE_TAG.bak"
    # 清理超过 7 天的旧备份
    find $BACKUP_DIR -name "*.bak" -type f -mtime +7 -exec rm {} \;
    echo "🧹 Old backups cleaned."
else
    echo "❌ Backup failed! (Please check if directory $DATA_DIR exists)"
    exit 1
fi
