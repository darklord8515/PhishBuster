from app.schemas import AnalyzeResponse, FlaggedItem
import re
import joblib
import os

# Load model and vectorizer at startup
MODEL_PATH = os.path.join(os.path.dirname(__file__), '../model.pkl')
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), '../vectorizer.pkl')

if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
else:
    model = None
    vectorizer = None

SUSPICIOUS_PHRASES = [
    "urgent action required", "verify your account", "reset your password",
    "click here", "confirm your identity", "scholarship offer", "bank account"
]
URL_REGEX = re.compile(r'https?://[^\s]+')

def extract_urls(text: str):
    return URL_REGEX.findall(text)

def is_url_blacklisted(url: str):
    # Real blacklist API call can be inserted here
    return ".ru" in url or ".cn" in url

def ml_predict(email_text: str):
    if model and vectorizer:
        X = vectorizer.transform([email_text])
        prob = model.predict_proba(X)[0][1]
        is_phish = prob > 0.5
        return is_phish, float(prob)
    else:
        return False, 0.0

def analyze_email(email_text: str):
    lower = email_text.lower()
    flagged = []

    # Phrase matching
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in lower:
            flagged.append(FlaggedItem(
                type="phrase",
                value=phrase,
                reason="Common phishing phrase"
            ))

    # URL analysis
    urls = extract_urls(email_text)
    for url in urls:
        if is_url_blacklisted(url):
            flagged.append(FlaggedItem(
                type="url",
                value=url,
                reason="URL matches known phishing TLD or blacklist"
            ))

    # ML Model prediction
    is_phish, prob = ml_predict(email_text)
    if is_phish:
        flagged.append(FlaggedItem(
            type="ml_model",
            value=f"Probability: {prob:.2f}",
            reason="ML model predicts high phishing risk"
        ))

    score = max(prob, min(1.0, 0.2 * len(flagged)))  # Either ML score or phrase/url score

    return AnalyzeResponse(
        is_phishing=score > 0.5,
        score=score,
        flagged=flagged,
        message="Phishing indicators detected." if flagged else "No obvious phishing detected."
    )