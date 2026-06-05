import logging
from fastapi import FastAPI, status, HTTPException
from contextlib import asynccontextmanager
from app.schema import RawLogPayload
from app.tasks import execute_threat_hunt_pipeline

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s - %(message)s')
logger = logging.getLogger("GatewayAPI")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("======================================================")
    logger.info(" 安全日志研判网关 Agent 成功启动，核心安全防护体系就位")
    logger.info("======================================================")
    yield
    logger.info("安全日志研判网关安全关闭。")

app = FastAPI(title="Secure Log Ingestion Gateway", lifespan=lifespan)

@app.post("/api/v1/logs/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_raw_system_log(payload: RawLogPayload):
    """
    统一的日志安全接收端点
    """
    try:
        # 【避坑优化点 5】：彻底拦截任意未知字段或 Log4j/SQL 注入载荷
        # Pydantic 在进入方法前就已经完成了强类型过滤清洗
        sanitized_dict = payload.model_dump()
        
        # 丢进 Celery 异步分布式集群，实现微秒级网络响应，物理隔离突发海量日志流量冲击
        async_task = execute_threat_hunt_pipeline.delay(sanitized_dict)
        
        return {
            "status": "ingested",
            "message": "原始日志已被网关成功捕获，全面流转进入分布式 AI 研判网络。",
            "incident_task_id": async_task.id
        }
    except Exception as e:
        logger.error(f"网关层发生致命异常阻断: {e}")
        raise HTTPException(status_code=500, detail="Gateway Security Interdiction")

@app.get("/api/v1/tasks/status/{task_id}")
async def get_ai_analysis_status(task_id: str):
    """获取指定任务的分布式智能研判结果状态"""
    from celery.result import AsyncResult
    res = AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": res.status,
        "report_output": res.result if res.ready() else "AI Hunting Agent is still analyzing..."
    }