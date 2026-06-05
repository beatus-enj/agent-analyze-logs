# 🛡️ Distributed Self-Healing Security Log Analysis Agent
本系统是一个基于 Python 3.12+ / FastAPI / Redis / Celery / LangChain / Pydantic v2 构建的工业级、高性能、具分布式流式抗载能力与 LLM 格式自愈能力的有状态安全日志智能研判闭环系统。
专注于解决高频海量日志上报（微秒级）与大模型慢速推理（秒级）之间的吞吐矛盾，并原生具备对抗输入污染、大模型幻觉及格式崩溃的自愈防御机制。

🏗️ 核心架构与技术选型漏斗模型本系统摒弃了盲目追求重型 LLM 框架的过度工程化做法，采用高并发“生产线漏斗模型”：
```text
[海量日志流量] ──> FastAPI 网关 (微秒级清洗、阻断注入载荷)
                     │
                     └──> [Redis ZSET 滑动窗口] ──> 高性能多维特征提取
                     │
              (投递 1ms 削峰)
                     │
                     ▼
             [Redis 内存队列 (Broker)]
                     │
             (分布式抢占算力调度)
                     │
                     ▼
         [Celery Workers 异步计算工厂]
                     │
                     ├──> [余弦相似度特征匹配] ──> 案例知识库 (防 Token 溢出)
                     ├──> [LangChain 渲染] ──> 直连本地 Ollama 
                     └──> [Pydantic v2 校验网格] ──> 格式崩溃自愈修复循环 (Self-Healing)
                               │
                               ▼
              [安全落盘 (WORM 盘) & 联动响应 API 剧本生成]
```

## 核心功能
| 功能 | 说明 |
|------|------|
| **MCP 工具调用层** | 通过 MCP 协议，从外部系统安全地获取原始日志 |
| **特征提取层** | 从日志中提取关键安全指标 |
| **RAG 检索增强层** | 将提取的特征作为查询，从历史攻击案例库中检索最相似的案例，为LLM提供分析上下文 |
| **LLM 推理与结构化输出层** | 结合上下文和检索到的案例，由LLM分析日志并生成结构化的安全报告，最后通过Pydantic进行强类型校验 |
| **只读安全落盘日志审计** | 通过强校验后将完全合规、脱敏的结构化JSON数据放到只读审计盘 |

## 🚀 容器化全链路快速部署
1. 一键拉起分布式全栈集群在项目根目录下，利用 Docker Compose 触发单次镜像编译与多服务异构复用启动：
```bash
docker compose up -d --build
```
2. 大模型冷启动热加载（基础权重注入）首次部署时，本地 Ollama 容器是一个空壳，需向其拉取并注入指定的网络安全研判担当大模型（由于配置了 volumes 持久化卷，此操作一生只需执行一次）：
```bash
docker exec -it security_ollama_engine ollama run qwen2.5-7b-instruct
```
3. 运行自动化黑盒对抗测试在宿主机（本地电脑）直接运行验证脚本，模拟高并发暴力破解+高危越权的双重组合攻击流：
```bash
python ./tests/test_agent_analyze_logs.py 
```
