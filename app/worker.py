from celery import Celery
from app.config import settings

# 初始化独立工作的分布式异步队列
celery_app = Celery(
    "security_agent_workers",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

celery_app.conf.update(
    # === 连接与重试 ===
    broker_connection_retry_on_startup=True,   # 启动时等待 Redis 就绪
    broker_connection_retry=True,              # 运行时自动重连
    broker_pool_limit=20,                      # 限制连接池大小，防止耗尽 Redis 连接
    broker_transport_options={
        'visibility_timeout': 3600,
        'socket_keepalive': True,              # TCP keepalive 防止空闲断开
        'socket_timeout': 30,
        'retry_on_timeout': True,
    },
      # === 任务预取与确认 ===
    worker_prefetch_multiplier=1,              # 一次只预取一个任务，公平分发
    task_acks_late=True,                       # 任务执行完成后才确认，防止 worker 崩溃时丢任务
    task_reject_on_worker_lost=True,           # worker 崩溃时自动拒绝并重入队
    task_track_started=True,                   # 记录任务开始状态，便于监控

    # === 结果存储 ===
    result_expires=3600,                       # 结果 1 小时后自动过期，防止 Redis 内存爆炸
    result_backend_transport_options={
        'retry_policy': {
            'timeout': 5.0,                    # 重试间隔 5 秒
            'max_retries': 5,                  # 最多重试 5 次
        },
        'socket_connect_timeout': 5,
        'socket_timeout': 10,
    },
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_max_tasks_per_child=1000  # 定期销毁子进程，彻底规避模型解析引发的物理内存泄漏
)

# 显式导入任务，注册至系统集群
import app.tasks