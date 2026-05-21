from schemas import SecurityReport
from mcp_client import MCPClient
from rag_engine import VectorDB
from feature_extractor import extract_security_features

class SecurityLogAnalysisAgent:

    def __init__(self):
        self.mcp = MCPClient()
        self.vectordb = VectorDB()

    def analyze(self, user_query: str):

        logs = self.mcp.call_tool(
            "security_log_tool",
            {
                "query": user_query,
                "time_range": "24h"
            }
        )

        features = extract_security_features(logs)

        similar_cases = self.vectordb.similarity_search(features)

        attack_type = similar_cases[0]["attack_type"]

        risk_level = (
            "High"
            if features["failed_login_count"] > 2
            else "Low"
        )

        suggestions = similar_cases[0]["resolution"]

        report = SecurityReport(
            attack_type=attack_type,
            risk_level=risk_level,
            suggestions=suggestions
        )

        return report.model_dump()


if __name__ == "__main__":

    agent = SecurityLogAnalysisAgent()

    result = agent.analyze(
        "Investigate suspicious login activity"
    )

    print(result)