from fastapi import FastAPI
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.nlp_utils import analyze_email

app = FastAPI(
    title="PhishGuard Email Phishing Detection API",
    description="API for detecting phishing attempts in email content using NLP and blacklists.",
    version="0.1.0"
)

@app.get("/")
def root():
    return {"message": "Welcome to PhishGuard!"}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    """
    Analyzes an email for phishing indicators.
    """
    result = analyze_email(request.email_text)
    return result