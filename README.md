# Security Log Analysis Agent

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
