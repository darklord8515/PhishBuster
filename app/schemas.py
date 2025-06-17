from pydantic import BaseModel
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    email_text: str

class FlaggedItem(BaseModel):
    type: str  # e.g., 'phrase', 'url', etc.
    value: str
    reason: Optional[str] = None

class AnalyzeResponse(BaseModel):
    is_phishing: bool
    score: float  # 0-1 risk score
    flagged: List[FlaggedItem]
    message: Optional[str] = None