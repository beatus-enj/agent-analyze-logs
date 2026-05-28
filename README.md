# Security Log Analysis Agent
本 Agent 通过 **MCP 工具调用 + RAG 检索 + LLM 推理 + Pydantic** 校验 四层架构，自动将安全日志分析从“人工翻找”升级为“智能诊断”，并输出可供下游消费的结构化 JSON。
```bash
{'attack_type': 'Brute Force Attack', 'risk_level': 'High', 'suggestions': ['Block suspicious IP addresses', 'Enable MFA', 'Monitor failed login attempts']}
```

# 数据流示意
```bash
┌────────────────┐
│   用户 / 触发   │
└───────┬────────┘
        ▼
┌────────────────┐
│   MCP 工具调用  │  ← 1. 从外部系统拉取原始日志
└───────┬────────┘
        ▼
┌────────────────┐
│   特征提取      │  ← 2. 提取安全指标 (如失败登录计数)
└───────┬────────┘
        ▼
┌────────────────┐
│   RAG 检索      │  ← 3. 从历史攻击库检索最相似案例
└───────┬────────┘
        ▼
┌────────────────┐
│   LLM 推理      │  ← 4. 生成攻击类型/风险等级/建议
└───────┬────────┘
        ▼
┌────────────────┐
│ Pydantic 校验  │  ← 5. 类型安全校验，确保下游可靠消费
└───────┬────────┘
        ▼
┌────────────────┐
│ 结构化 JSON    │
│ 供下游系统使用  │
└────────────────┘
```

# 🚀 功能特性
**MCP 工具集成**：通过 MCP 协议从外部系统安全、结构化地获取原始日志
**RAG 检索增强**：从已知攻击案例库中匹配最相似的历史案例，为 LLM 分析提供上下文
**LLM 推理输出**：自动生成攻击类型（attack_type）、风险等级（risk_level）、修复建议（suggestions）
**结构化输出**：使用 Pydantic 强类型校验，输出可直接被下游自动化系统消费


Pipeline:
1. MCP tool retrieves raw logs first
2. RAG retrieves similar attack cases
3. LLM generates structured JSON
4. Pydantic validates output

Final schema:

```json
{
  "attack_type": "...",
  "risk_level": "...",
  "suggestions": [...]
}
```
# 🛠️ 部署方式
1. 本地运行
```bash
# 克隆仓库
git clone https://github.com/beatus-enj/agent-analyze-logs.git
cd agent-analyze-logs

# 安装依赖
pip install -r requirement.txt

# 运行 Agent
python agent.py
```
