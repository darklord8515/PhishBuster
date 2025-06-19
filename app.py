from flask import Flask, render_template, request, jsonify
import joblib
from src.url_features import extract_url_features

app = Flask(__name__)

url_model = joblib.load("data/url_rf_model.joblib")
url_feature_columns = joblib.load("data/url_feature_columns.joblib")
email_model = joblib.load("data/email_rf_model.joblib")
email_vectorizer = joblib.load("data/email_tfidf_vectorizer.joblib")

def get_url_feature_vector(url):
    feats = extract_url_features(url)
    return [feats.get(col, 0) for col in url_feature_columns]

def explain(pred, input_type):
    if pred == 1 and input_type == "url":
        return "⚠️ This URL is likely a phishing or malicious link. Do NOT click it."
    elif pred == 0 and input_type == "url":
        return "✅ This URL appears to be safe."
    elif pred == 1 and input_type == "email":
        return "⚠️ This email is likely a phishing/fraud attempt. Do not trust or respond."
    elif pred == 0 and input_type == "email":
        return "✅ This email appears to be safe."
    else:
        return "Unable to determine."

@app.route("/", methods=["GET", "POST"])
def index():
    result = explanation = None
    if request.method == "POST":
        input_type = request.form.get("inputType")
        if input_type == "url":
            url = request.form.get("url")
            feature_vector = get_url_feature_vector(url)
            pred = url_model.predict([feature_vector])[0]
            result = "Phishing" if pred == 1 else "Safe"
            explanation = explain(pred, "url")
        elif input_type == "email":
            email = request.form.get("email")
            X = email_vectorizer.transform([email])
            pred = email_model.predict(X)[0]
            result = "Phishing" if pred == 1 else "Safe"
            explanation = explain(pred, "email")
    return render_template("index.html", result=result, explanation=explanation)

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json()
    input_type = data.get("inputType")
    input_url = data.get("url", "")
    input_email = data.get("email", "")
    result = explanation = None

    if input_type == "url":
        if not input_url:
            result = "Error"
            explanation = "Please enter a URL."
        else:
            feature_vector = get_url_feature_vector(input_url)
            pred = url_model.predict([feature_vector])[0]
            result = "Phishing" if pred == 1 else "Safe"
            explanation = explain(pred, "url")
    elif input_type == "email":
        if not input_email:
            result = "Error"
            explanation = "Please enter email text."
        else:
            X = email_vectorizer.transform([input_email])
            pred = email_model.predict(X)[0]
            result = "Phishing" if pred == 1 else "Safe"
            explanation = explain(pred, "email")

    return jsonify({
        "result": result,
        "explanation": explanation,
        "inputType": input_type,
        "inputUrl": input_url,
        "inputEmail": input_email
    })

if __name__ == "__main__":
    app.run(debug=True)