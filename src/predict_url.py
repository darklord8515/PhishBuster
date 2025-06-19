import pandas as pd
import joblib
import tldextract

from src.url_features import extract_url_features, SAFE_DOMAINS
MODEL_PATH = "data/url_rf_model.joblib"
FEATURE_COLS_PATH = "data/url_feature_columns.joblib"
try:
    model = joblib.load(MODEL_PATH)
    feature_cols = joblib.load(FEATURE_COLS_PATH)
except Exception as e:
    print(f"Failed to load model or feature columns: {e}")
    model = None
    feature_cols = None

def extract_root_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()

def is_url_safe(url):
    root_domain = extract_root_domain(url)
    return root_domain in SAFE_DOMAINS

def predict_url_safety(url):
    """
    Predict if a single URL is safe or unsafe.
    Returns:
        result (str): "safe" or "unsafe"
    """
    if is_url_safe(url):
        return "safe"
    if model is None or feature_cols is None:
        return "Error: Model not loaded"
    feats = extract_url_features(url)
    # Ensure all expected columns are present in order
    features_row = [feats.get(col, 0) for col in feature_cols]
    features_df = pd.DataFrame([features_row], columns=feature_cols)
    pred = model.predict(features_df)[0]
    return "unsafe" if pred == 1 else "safe"

if __name__ == "__main__":
    url = input("Enter a URL to check: ").strip()
    result = predict_url_safety(url)
    print(f"{url} is {result}")