import pandas as pd
import joblib
import tldextract
from url_features import extract_url_features, SAFE_DOMAINS

def extract_root_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()

def is_url_safe(url):
    if not isinstance(url, str):
        return False
    root_domain = extract_root_domain(url)
    return root_domain in SAFE_DOMAINS

def predict_from_file(model_path, data_path, drop_cols, url_col=None):
    model = joblib.load(model_path)
    df = pd.read_csv(data_path)
    X = df.drop(columns=drop_cols)
    preds = []

    for idx, row in df.iterrows():
        # Whitelist for URLs using root domain
        if url_col and is_url_safe(row[url_col]):
            preds.append(0)  # 0 = legitimate
        else:
            # Standard model prediction
            x = X.iloc[[idx]]
            pred = model.predict(x)[0]
            preds.append(pred)
    preds = pd.Series(preds, index=df.index)
    print(preds.values)
    return preds

# --- For Webpage usage: predict a single URL ---
def extract_features_for_model(url):
    # Use your feature extraction routine
    feats = extract_url_features(url)
    feature_cols = joblib.load("data/url_feature_columns.joblib")
    return pd.DataFrame([[feats.get(col, 0) for col in feature_cols]], columns=feature_cols)

def predict_single_url(url, model_path):
    if is_url_safe(url):
        return 0, f"Trusted domain: {extract_root_domain(url)}"
    model = joblib.load(model_path)
    features = extract_features_for_model(url)
    pred = model.predict(features)[0]
    explanation = "Suspicious structure or content detected." if pred == 1 else "No major risks detected."
    return pred, explanation

if __name__ == "__main__":
    # Predict on URL test set with whitelist
    predict_from_file("data/url_rf_model.joblib", "data/url_test.csv", ["url", "label"], url_col="url")
    # Predict on Email test set (no whitelist needed)
    predict_from_file("data/email_rf_model.joblib", "data/email_test.csv", ["Email_ID", "label"])