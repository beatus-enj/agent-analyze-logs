import os
import json
import logging
import requests
from urllib3.util.retry import Retry
from app.worker import celery_app
from app.schema import RawLogPayload, FeatureProfile, StructuredSecurityReport
from app.services import RedisSlidingWindowTracker, SecurityKnowledgeBase
from app.config import settings

# LangGraph & LangChain 核心基础组件导入
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from pydantic import ValidationError
from typing import Annotated, Dict, List, Literal, TypedDict

logger = logging.getLogger("CeleryTasksLangGraph")

def _write_to_worm_sink(safe_report_str: str):
    """【避坑优化点 3】：输入清洗与安全落地。模拟 WORM (只写一次) 只读审计盘物理备份"""
    try:
        # 生产环境应当设置为只有当前运行用户拥有读写权限 (0600)
        with open(settings.LOG_SINK_PATH, "a", encoding="utf-8") as f:
            f.write(safe_report_str + "\n")
    except Exception as e:
        logger.error(f"WORM 归一化审计日志持久化失败: {e}")


class LogAnalysisState(TypedDict):
    # 保持长短期记忆与对话上下文（包含 LLM 的错误自愈历史，用于合规审计）
    messages: Annotated[list, add_messages]
    # 生产级可观测性：记录当前处理的日志元数据、特征、RAG 检索上下文及中间步骤
    current_log_context: Dict[str, any]
    # 核心：引入 LLM-as-a-judge 机制的置信度评分，不达标则拒绝输出并触发重试
    evaluation_score: float
    # 阻断计数，防止多智能体陷入死循环（生产环境的高可用保护机制）
    retry_count: int

def log_ingestion_node(state: LogAnalysisState) -> Dict[str, any]:
    """处理高并发非结构化日志的解析输入、特征提取与有状态 RAG 注入"""
    print("---INGESTING LOGS & EXTRACTING FEATURES---")
    
    # 从初始状态中提取原始日志负载
    log_data = state["current_log_context"]["raw_log_payload"]
    log = RawLogPayload(**log_data)
    
    # 联动 Redis 状态机提取有状态安全特征
    tracker = RedisSlidingWindowTracker()
    profile = tracker.track_and_extract(log)
    
    # 关联知识库检索
    kb = SecurityKnowledgeBase()
    matched_case, similarity = kb.query_closest_case(profile)
    
    # 将富化的有状态特征与 RAG 上下文深度绑定至可观测性上下文中
    context_update = {
        "profile": profile.__dict__,  # 转换为可序列化字典
        "matched_case": matched_case,
        "similarity": similarity,
        "status": "ingested"
    }
    return {
        "current_log_context": context_update, 
        "retry_count": 0
    }


def reasoning_agent_node(state: LogAnalysisState) -> Dict[str, any]:
    """多步推理智能体：感知对话历史流，动态请求本地大模型进行核心研判"""
    print("---AGENT REASONING & OLLAMA CALLING---")
    
    ctx = state["current_log_context"]
    profile_dict = ctx["profile"]
    matched_case = ctx["matched_case"]
    similarity = ctx["similarity"]
    
    # 构建静态硬约束 Prompt 骨架
    system_prompt = "你是一个资深网络安全分析Agent(SOC L3)。你必须将分析结果输出为严格符合 JSON Schema 规范的单行 JSON 字符串。"
    
    user_prompt_template = """
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
    """
    
    formatted_user = user_prompt_template.format(
        user=profile_dict.get("trigger_user"),
        ip=profile_dict.get("trigger_ip"),
        login_fails=profile_dict.get("login_failures_in_window"),
        violations=profile_dict.get("violations_in_window"),
        distinct_ips=profile_dict.get("distinct_ip_count"),
        sim=similarity,
        case_type=matched_case["attack_type"],
        case_mitre=matched_case["mitre"],
        case_desc=matched_case["desc"],
        case_playbook=str(matched_case["playbook"])
    )
    
    # 转换长短期记忆对话流以适配本地 Ollama 格式要求
    ollama_messages = [{"role": "system", "content": system_prompt}]
    
    if not state["messages"]:
        # 首次推理，直接注入组装后的 User Prompt
        ollama_messages.append({"role": "user", "content": formatted_user})
    else:
        # 重试流：复现之前的对话轨迹，末尾会自动包含由 validator 节点注入的【前次输出校验失败警告】
        for msg in state["messages"]:
            role = "user" if isinstance(msg, HumanMessage) else "assistant"
            ollama_messages.append({"role": role, "content": msg.content})
            
    try:
        response = requests.post(
            settings.LOCAL_LLM_URL,
            json={
                "model": settings.LOCAL_LLM_MODEL,
                "messages": ollama_messages,
                "response_format": {"type": "json_object"},
                "stream": False,
                "options": {"temperature": 0.05}  # 极限收敛随机性
            },
            timeout=(5.0, 300.0)
        )

        if response.status_code == 200:
            data = response.json()
            # 安全提取内容
            raw_llm_output = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
                )
        else:
            raise ConnectionError("Local Ollama Server Response Exception")
    except Exception as e:
        logger.error(f"Ollama 推理层网络故障: {e}")
        raw_llm_output = "{}"  # 注入空结构体以触发下游 Validator 捕获
        
    return {"messages": [AIMessage(content=raw_llm_output)]}

def llm_as_a_judge_node(state: LogAnalysisState) -> Dict[str, any]:
    """
    【硬性指标】自动化评估与契约解析验证网格
    执行强类型反序列化，通过 Pydantic 运行时异常充当 Judge，失败则追加惩罚性报错反馈
    """
    print("---AUTOMATED EVALUATION (LLM-AS-A-JUDGE)---")
    
    # 提取多步推理智能体最新生成的 AIMessage 文本
    raw_llm_output = state["messages"][-1].content.strip()
    current_retry = state.get("retry_count", 0)
    
    # 剔除大模型可能固执携带的 Markdown 语法外壳
    if raw_llm_output.startswith("```"):
        if "```json" in raw_llm_output:
            raw_llm_output = raw_llm_output.split("```json")[-1].split("```")[0].strip()
        else:
            raw_llm_output = raw_llm_output.split("```")[1].strip()
            
    try:
        # 1. 强类型网格体检：断言反序列化
        validated_report = StructuredSecurityReport.model_validate_json(raw_llm_output)
        
        # 2. 校验成功：赋予审计满分 1.0，落盘结构化输出并准备退出
        print("  [Judge 审计结果] 🎉 置信契约对齐完全通过。")
        return {
            "evaluation_score": 1.0,
            "current_log_context": {**state["current_log_context"], "validated_report": validated_report.model_dump()},
            "retry_count": current_retry
        }
        
    except (ValidationError, json.JSONDecodeError, Exception) as error:
        feedback_error_msg = str(error)
        logger.warning(f"第 {current_retry + 1} 次大模型格式遭网格弹回拦截! 原因: {feedback_error_msg}")
        
        next_retry = current_retry + 1
        
        # 3. 高可用熔断降级防御机制：若已达到 3 次重试阻断计数，强制启用硬编码安全沙箱
        if next_retry >= 3:
            print("  [Judge 熔断警告] 大模型连续自愈失败，触发确定性保底降级决策树。")
            profile_dict = state["current_log_context"]["profile"]
            
            fallback_safe_mock_response = {
                "threat_level": "CRITICAL" if profile_dict.get("login_failures_in_window", 0) >= 3 else "HIGH",
                "attack_justification": "系统联动触发沙箱降级保护机制。基于确定性决策树，当前用户高频触犯滑窗安全基线，高度吻合资产沦陷特征（LangGraph 熔断保护）。",
                "mitre_attack_technique_ids": ["T1110", "T1078"],
                "confidence_score": 0.99,
                "is_automated_block_recommended": True,
                "remediation_playbook_commands": [
                    f"iam:suspend_user --username {profile_dict.get('trigger_user')}",
                    f"waf:block_ip --ip {profile_dict.get('trigger_ip')} --duration 86400"
                ]
            }
            return {
                "evaluation_score": 1.0,  # 赋予满分以强制切断路由
                "current_log_context": {**state["current_log_context"], "validated_report": fallback_safe_mock_response},
                "retry_count": next_retry
            }
            
        # 4. 处于自愈容量内：打分 0.0，向 messages 中原子追加惩罚性反馈项
        feedback_msg = f"❌【前次输出校验失败警告】：你的前一次输出引发了 Pydantic 运行时异常: '{feedback_error_msg}'。请严格修正对应字段的类型与范围，重新输出符合标准的规范 JSON。"
        return {
            "evaluation_score": 0.0,
            "messages": [HumanMessage(content=feedback_msg)],
            "retry_count": next_retry
        }


# ==========================================
# 3. 路由控制逻辑
# ==========================================
def router_edge(state: LogAnalysisState) -> Literal["reasoning_agent", "__end__"]:
    """条件路由：根据自动化评估分数决定是退回重试，还是放行输出"""
    score = state.get("evaluation_score", 0.0)
    
    if score >= 0.85:
        print("---ROUTING DECISION: SCORE VALIDATED -> EXIT---")
        return "__end__"
    else:
        print("---ROUTING DECISION: RETRY SELF-HEALING LOOP---")
        return "reasoning_agent"


# ==========================================
# 4. 构建状态机图结构
# ==========================================
workflow = StateGraph(LogAnalysisState)

# 注册节点
workflow.add_node("ingest", log_ingestion_node)
workflow.add_node("reasoning_agent", reasoning_agent_node)
workflow.add_node("validator", llm_as_a_judge_node)

# 设置线性起点与核心拓扑连线
workflow.set_entry_point("ingest")
workflow.add_edge("ingest", "reasoning_agent")
workflow.add_edge("reasoning_agent", "validator")

# 【核心条件边】基于评估分数的非线性条件路由
workflow.add_conditional_edges(
    "validator",
    router_edge,
    {
        "reasoning_agent": "reasoning_agent",  # 分数不达标 (0.0)，流回大模型就地自愈
        "__end__": END,                       # 分数达标 (1.0)，或触发熔断，安全退出
    },
)

# 编译图生成执行引擎
app = workflow.compile()


# ==========================================
# 5. Celery 分布式计算工厂接驳入口 (完全向下兼容)
# ==========================================
@celery_app.task(name="tasks.execute_threat_hunt_pipeline", bind=True, max_retries=3)
def execute_threat_hunt_pipeline(self, log_data: dict) -> dict:
    """ 
    全链路分布式核心研判任务（内部改由 LangGraph 引擎驱动轰鸣）
    """
    logger.info(f"分布式 Worker 成功捕获异步安全分析流水线任务（LangGraph 架构）...")
    
    # 初始化满足审计标准的初始状态体
    initial_state = {
        "messages": [],
        "current_log_context": {"raw_log_payload": log_data, "status": "initializing"},
        "evaluation_score": 0.0,
        "retry_count": 0
    }
    
    # 驱动图拓扑在当前子进程中运行
    final_state = app.invoke(initial_state)
    
    # 提取通过安全验证（或熔断降级保护）后的标准化报告
    final_report_dict = final_state["current_log_context"]["validated_report"]
    
    # 原子化追加到只读 WORM 审计盘，完成分布式控制权转交
    final_json_str = json.dumps(final_report_dict, ensure_ascii=False)
    _write_to_worm_sink(final_json_str)
    
    return final_report_dict