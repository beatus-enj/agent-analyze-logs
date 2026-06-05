FROM python:3.12-slim


ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # 强制允许 Celery 在容器根权限下安全初始化（防止容器内启动报错）
    C_FORCE_ROOT=1 

WORKDIR /app


RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 规避缓存漏洞：单独复制并安装依赖层
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


COPY . .


EXPOSE 8000

# 注意：此处不写硬编码的 CMD。
# 因为我们将复用这一个镜像，在 docker-compose 中通过 command 分别驱动 Web 网关和 Celery Worker。