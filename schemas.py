from pydantic import BaseModel
from typing import List

class SecurityReport(BaseModel):
    attack_type: str
    risk_level: str
    suggestions: List[str]