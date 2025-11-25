FROM python:3.9-slim

WORKDIR /app

# 安装系统依赖
# 为了防止 apt-get 也很慢，这里最好也换源，但通常 pip 是主要瓶颈，先只处理 pip
RUN apt-get update && apt-get install -y sshpass && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# 关键修改：添加了 -i https://pypi.tuna.tsinghua.edu.cn/simple
# 这会强制 pip 从清华大学的镜像站下载，速度非常快
RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]