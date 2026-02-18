# 基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 1. 换源并安装系统级依赖 OpenSSL
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y openssl \
    && rm -rf /var/lib/apt/lists/*

# 2. 复制依赖文件并安装 (使用清华源加速)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 3. 复制剩余项目文件
COPY . .

# 4. 暴露端口
EXPOSE 2002

# 5. 启动命令
CMD ["python", "app.py"]