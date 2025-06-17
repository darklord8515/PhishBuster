from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def detect_phishing_url(url):
    if "phish" in url.lower():
        return "Phishing", "⚠️ This looks like a phishing link!"
    else:
        return "Safe", "✅ This link appears safe."

def detect_phishing_email(email_text):
    if "urgent" in email_text.lower():
        return "Phishing", "⚠️ This email looks suspicious!"
    else:
        return "Safe", "✅ This email appears safe."

@app.route("/")
def index():
    return render_template("index.html")

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
            result, explanation = detect_phishing_url(input_url)
    elif input_type == "email":
        if not input_email:
            result = "Error"
            explanation = "Please enter email text."
        else:
            result, explanation = detect_phishing_email(input_email)

    return jsonify({
        "result": result,
        "explanation": explanation,
        "inputType": input_type,
        "inputUrl": input_url,
        "inputEmail": input_email
    })

if __name__ == "__main__":
    app.run(debug=True)