import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class AppConfig(BaseSettings):
    # 基础配置
    PROJECT_NAME: str = "Security-Log-Analysis-Agent"
    DEBUG: bool = False
    
    # 安全加固配置
    SAAS_API_TOKEN: str = "mock_secure_token_vault_fallback"
    LOG_SINK_PATH: str = "secure_worm_audit_storage.log"
    
    # 基础设施中间件链接
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"
    
    # 本地大模型配置 (Ollama / vLLM)
    # LOCAL_LLM_URL: str = "http://localhost:11434/api/chat"
    # LOCAL_LLM_MODEL: str = "qwen2.5:7b-instruct"
    LOCAL_LLM_URL: str = "http://ollama_llm:8080/v1/chat/completions"
    LOCAL_LLM_MODEL: str = "Qwen2.5-3B-Instruct-Q4_K_M"
    
    # 核心滑动窗口安全控制 (分钟)
    SECURITY_WINDOW_MINUTES: int = 5

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = AppConfig()