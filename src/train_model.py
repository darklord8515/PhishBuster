import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np
from url_features import extract_url_features

def evaluate_and_print(model, X, y, name="set"):
    y_pred = model.predict(X)
    print(f"[{name}] Accuracy: {accuracy_score(y, y_pred):.3f}")
    print(f"[{name}] Precision: {precision_score(y, y_pred):.3f}")
    print(f"[{name}] Recall: {recall_score(y, y_pred):.3f}")
    print(f"[{name}] F1-score: {f1_score(y, y_pred):.3f}")

def train_and_eval(type_):
    assert type_ in ["url", "email"]
    print(f"Loading {type_} data...")
    train = pd.read_csv(f"data/{type_}_train.csv")
    val = pd.read_csv(f"data/{type_}_val.csv")
    test = pd.read_csv(f"data/{type_}_test.csv")

    y_train, y_val, y_test = train["label"], val["label"], test["label"]

    if type_ == "url":
        print("Extracting URL features...")
        X_train = train["url"].fillna("").apply(extract_url_features).apply(pd.Series)
        X_val = val["url"].fillna("").apply(extract_url_features).apply(pd.Series)
        X_test = test["url"].fillna("").apply(extract_url_features).apply(pd.Series)
        # --- FILTER TO NUMERIC COLUMNS ONLY ---
        X_train = X_train.select_dtypes(include=[np.number])
        X_val = X_val.select_dtypes(include=[np.number])
        X_test = X_test.select_dtypes(include=[np.number])
        feature_cols = list(X_train.columns)
        joblib.dump(feature_cols, "data/url_feature_columns.joblib")
    else:
        print("Extracting email text features (TF-IDF)...")
        text_col = None
        for col in ["text", "body", "email", "content"]:
            if col in train.columns:
                text_col = col
                break
        if not text_col:
            text_col = train.columns[0]
        train[text_col] = train[text_col].fillna("").astype(str)
        val[text_col] = val[text_col].fillna("").astype(str)
        test[text_col] = test[text_col].fillna("").astype(str)
        vectorizer = TfidfVectorizer(max_features=1000)
        X_train = vectorizer.fit_transform(train[text_col])
        X_val = vectorizer.transform(val[text_col])
        X_test = vectorizer.transform(test[text_col])
        joblib.dump(vectorizer, "data/email_tfidf_vectorizer.joblib")

    print(f"Training RandomForestClassifier for {type_}...")
    model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    model.fit(X_train, y_train)
    joblib.dump(model, f"data/{type_}_rf_model.joblib")
    print(f"Trained and saved {type_} model & preprocessors.")

    print(f"Evaluating on {type_} data...")
    evaluate_and_print(model, X_val, y_val, name="Validation")
    evaluate_and_print(model, X_test, y_test, name="Test")

if __name__ == "__main__":
    train_and_eval("url")
    train_and_eval("email")