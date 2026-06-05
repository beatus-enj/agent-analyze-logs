from enum import Enum
from typing import List, Dict, Any
from pydantic import BaseModel, Field, field_validator

class ThreatLevelEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class RawLogPayload(BaseModel):
    """FastAPI 网关接收的原始可疑输入模型"""
    timestamp: str = Field(..., description="外部系统上报时间")
    user: str = Field(..., max_length=50, description="触发账户")
    source_ip: str = Field(..., description="关联源IP")
    event_type: str = Field(..., description="事件类型")
    status: str = Field(..., description="状态")
    payload: str = Field("", max_length=1000, description="扩展上下文载荷，严防注入")

class FeatureProfile(BaseModel):
    """特征提取层输出的量化指标画像"""
    trigger_user: str
    trigger_ip: str
    event_time: str
    login_failures_in_window: int
    violations_in_window: int
    distinct_ip_count: int
    is_root: bool

class StructuredSecurityReport(BaseModel):
    """本地 LLM 必须无条件服从生成的最终结构化合规报告"""
    threat_level: ThreatLevelEnum = Field(..., description="威胁等级判定")
    attack_justification: str = Field(..., description="结合历史案例深度挖掘的技术研判论据")
    mitre_attack_technique_ids: list[str] = Field(..., description="映射的 MITRE ATT&CK 技术ID")
    confidence_score: float = Field(..., description="研判置信度，范围 [0.0, 1.0]")
    is_automated_block_recommended: bool = Field(..., description="是否立即联动物理网关进行阻断")
    remediation_playbook_commands: list[str] = Field(..., description="下游执行网关直接可运行的原子API命令序列")

    @field_validator("confidence_score")
    @classmethod
    def check_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("置信度必须在 0.0 至 1.0 之间")
        return v

    @field_validator("mitre_attack_technique_ids")
    @classmethod
    def check_mitre_format(cls, v: list[str]) -> list[str]:
        for idx in v:
            if not idx.upper().startswith("T") or len(idx) < 4:
                raise ValueError(f"MITRE ID 格式错误: {idx}")
        return [idx.upper() for idx in v]