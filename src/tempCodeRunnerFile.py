import pandas as pd
import joblib
from .url_features import extract_url_features, SAFE_DOMAINS
import tldextract

def extract_root_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()

def is_url_safe(url):
    root_domain = extract_root_domain(url)
    return root_domain in SAFE_DOMAINS

def predict_url_safety(
    url,
    model_path="data/url_rf_model.joblib",
    feature_cols_path="data/url_feature_columns.joblib"
):
    """Predict if a single URL is safe or unsafe.

    Returns:
        result (str): "safe" or "unsafe"
    """
    if is_url_safe(url):
        return "safe"
    # Load model and feature columns
    model = joblib.load(model_path)
    feature_cols = joblib.load(feature_cols_path)
    # Extract features and ensure column order
    feats = extract_url_features(url)
    features_row = [feats.get(col, 0) for col in feature_cols]
    features_df = pd.DataFrame([features_row], columns=feature_cols)
    pred = model.predict(features_df)[0]
    return "unsafe" if pred == 1 else "safe"

if __name__ == "__main__":
    url = input("Enter a URL to check: ").strip()
    result = predict_url_safety(url)
    print(f"{url} is {result}")