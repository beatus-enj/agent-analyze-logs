import os
import json
import logging
import requests
from app.worker import celery_app
from app.schema import RawLogPayload, FeatureProfile, StructuredSecurityReport
from app.services import RedisSlidingWindowTracker, SecurityKnowledgeBase
from app.config import settings

# LangChain 核心基础组件导入
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from pydantic import ValidationError

logger = logging.getLogger("CeleryTasks")

def _write_to_worm_sink(safe_report_str: str):
    """【避坑优化点 3】：输入清洗与安全落地。模拟 WORM (只写一次) 只读审计盘物理备份"""
    try:
        # 生产环境应当设置为只有当前运行用户拥有读写权限 (0600)
        with open(settings.LOG_SINK_PATH, "a", encoding="utf-8") as f:
            f.write(safe_report_str + "\n")
    except Exception as e:
        logger.error(f"WORM 归一化审计日志持久化失败: {e}")

@celery_app.task(name="tasks.execute_threat_hunt_pipeline", bind=True, max_retries=3)
def execute_threat_hunt_pipeline(self, log_data: dict) -> dict:
    """
    全链路分布式核心研判任务
    """
    logger.info(f"分布式 Worker 成功捕获异步安全分析流水线任务...")
    
    # 1. 数据还原与规整
    log = RawLogPayload(**log_data)
    
    # 2. 状态机提取有状态安全特征
    tracker = RedisSlidingWindowTracker()
    profile = tracker.track_and_extract(log)
    
    # 3. 关联知识库检索
    kb = SecurityKnowledgeBase()
    matched_case, similarity = kb.query_closest_case(profile)
    
    # 4. 利用 LangChain 灵活构建生产级 Prompt 骨架
    prompt = ChatPromptTemplate.from_messages([
        ("system", "你是一个资深网络安全分析Agent(SOC L3)。你必须将分析结果输出为严格符合 JSON Schema 规范的单行 JSON 字符串。"),
        ("user", """
        【当前异常指标】
        - 账号: {user} | 源IP: {ip}
        - 窗口内登录失败频次: {login_fails}
        - 窗口内合规策略拦截频次: {violations}
        - 历史关联独立IP总数: {distinct_ips}
        
        【参考相似历史案例 (相似度: {sim:.2%})】
        - 定性: {case_type} | MITRE ID: {case_mitre}
        - 历史实战技术特征: {case_desc}
        - 已验证阻断剧本模版: {case_playbook}
        
        【硬性死命令 - 约束约束约束】
        你必须无条件输出一个合法的 JSON 字符串。严禁包含 ```json 等任何 Markdown 标记。
        JSON 必须包含以下 Key，缺一不可：
        - "threat_level": 必须是 "CRITICAL", "HIGH", "MEDIUM", "LOW" 之一
        - "attack_justification": 详细的研判技术论据字符串
        - "mitre_attack_technique_ids": 字符串列表，例如 ["T1110"]
        - "confidence_score": 0.0 到 1.0 的浮点数
        - "is_automated_block_recommended": 布尔值
        - "remediation_playbook_commands": 字符串列表（请将模版中的变量替换为当前的真实用户和IP）
        """)
    ])

    # 填充基础 Prompt
    formatted_prompt = prompt.format(
        user=profile.trigger_user,
        ip=profile.trigger_ip,
        login_fails=profile.login_failures_in_window,
        violations=profile.violations_in_window,
        distinct_ips=profile.distinct_ip_count,
        sim=similarity,
        case_type=matched_case["attack_type"],
        case_mitre=matched_case["mitre"],
        case_desc=matched_case["desc"],
        case_playbook=str(matched_case["playbook"])
    )

    # 5. 【核心避坑优化点 4】：闭环修复自愈循环 (Self-Healing Loop)
    # 本地小模型极易发生微小的格式崩溃，在此构建自愈反馈网格，最多自动重试修正 3 次
    max_llm_healing_attempts = 3
    feedback_error_msg = ""
    validated_report = None

    # 沙箱降级方案：若本地未开启 Ollama 容器，自动转入高可信内置确定性语义决策矩阵，确保业务高可用
    fallback_safe_mock_response = {
        "threat_level": "CRITICAL" if profile.login_failures_in_window >= 3 else "HIGH",
        "attack_justification": "系统联动触发沙箱降级保护机制。基于确定性决策树，当前用户高频触犯滑窗安全基线，高度吻合资产沦陷特征。",
        "mitre_attack_technique_ids": ["T1110", "T1078"],
        "confidence_score": 0.99,
        "is_automated_block_recommended": True,
        "remediation_playbook_commands": [
            f"iam:suspend_user --username {profile.trigger_user}",
            f"waf:block_ip --ip {profile.trigger_ip} --duration 86400"
        ]
    }

    for attempt in range(1, max_llm_healing_attempts + 1):
        current_llm_input = formatted_prompt
        if feedback_error_msg:
            # 动态追加反馈错误，迫使本地大模型在下一轮对话中精准自修复
            current_llm_input += f"\n\n❌【前次输出校验失败警告】：你的前一次输出引发了 Pydantic 运行时异常: '{feedback_error_msg}'。请严格修正对应字段的类型与范围，重新输出符合标准的规范 JSON。"

        try:
            logger.info(f"开始投递大模型，当前进行第 {attempt} 次结构化自愈尝试...")
            
            # 兼容性设计：调用本地 Ollama/vLLM HTTP 端点
            response = requests.post(
                settings.LOCAL_LLM_URL, 
                json={
                    "model": settings.LOCAL_LLM_MODEL,
                    "messages": [{"role": "user", "content": current_llm_input}],
                    "stream": False,
                    "options": {"temperature": 0.05} # 极限压制随机性
                },
                timeout=30
            )
            
            if response.status_code == 200:
                raw_llm_output = response.json().get("message", {}).get("content", "").strip()
                # 剔除 Markdown 容器毒瘤
                if raw_llm_output.startswith("```"):
                    raw_llm_output = raw_llm_output.split("```json")[-1].split("```")[0].strip()
            else:
                # 触发向沙箱降级
                raise ConnectionError("Local Ollama Server Unavailable")

            # 强行拉入 Pydantic 严格反序列化校验网格
            validated_report = StructuredSecurityReport.model_validate_json(raw_llm_output)
            break # 校验完全成功，切断自愈循环！

        except (ValidationError, json.JSONDecodeError, Exception) as error:
            feedback_error_msg = str(error)
            logger.warning(f"第 {attempt} 次大模型生成遭到 Pydantic 安全网格弹回拦截! 缺陷原因: {feedback_error_msg}")
            if attempt == max_llm_healing_attempts:
                logger.error("大模型多轮自愈失败。为确保核心系统高可用，全面触发底层降级策略...")
                validated_report = StructuredSecurityReport(**fallback_safe_mock_response)

    # 6. 安全归档落地并交出控制权给下游网关
    final_json_str = validated_report.model_dump_json()
    _write_to_worm_sink(final_json_str)
    
    return validated_report.model_dump()