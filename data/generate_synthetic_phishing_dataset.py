import csv
import random

# ----- Configuration -----
N_URLS = 5000
N_EMAILS = 5000

# ---- URL Patterns -----
phishing_keywords = [
    "login", "verify", "update", "secure", "account", "signin", "confirm", "security", "bank", "unlock", "reset", "alert", "support"
]
legit_domains = [
    "paypal.com", "amazon.com", "apple.com", "facebook.com", "microsoft.com", "ebay.com", "dropbox.com", "google.com", "bankofamerica.com", "chase.com"
]
phishing_tlds = [".ru", ".cn", ".tk", ".ml", ".gq", ".xyz", ".top", ".pw", ".info", ".cc"]
legit_urls = [
    f"https://www.{d}/" for d in legit_domains
] + [
    f"https://{d}/login" for d in legit_domains
] + [
    f"https://secure.{d}/" for d in legit_domains
]

def random_phishing_url():
    domain = random.choice(legit_domains)
    tld = random.choice(phishing_tlds)
    keyword = random.choice(phishing_keywords)
    subdomain = f"{domain.split('.')[0]}-{keyword}-{random.randint(100,999)}"
    extra = random.choice([
        "", f"/{keyword}/", f"/{keyword}/account/", f"/{keyword}/update/", f"/verify/", f"/secure/"
    ])
    return f"http://{subdomain}.{domain.split('.')[1]}{tld}{extra}"

def random_legit_url():
    return random.choice(legit_urls)

# ---- Email Patterns ----
phishing_subjects = [
    "Your Account Has Been Suspended",
    "Action Required: Confirm Your Account",
    "Security Alert: Unusual Activity",
    "Immediate Account Verification Needed",
    "Important: Password Expiry Notification",
    "Account Locked: Verify Now",
    "Payment Failed: Update Info",
    "Final Notice: Account Termination",
    "Your Account Will Be Deleted",
    "Urgent: Suspicious Login Detected"
]
legit_subjects = [
    "Meeting Reminder",
    "Your Amazon order has shipped!",
    "Welcome to Our Newsletter",
    "Invoice for Your Recent Purchase",
    "Project Update",
    "Bank Statement Available",
    "Event Invitation",
    "Password Changed Successfully",
    "Account Settings Updated",
    "Thank You for Your Feedback"
]

phishing_bodies = [
    "Dear User, We detected suspicious activity on your account. Please verify your information immediately to restore access: {url}",
    "Dear Customer, Your account has been temporarily suspended. Click here to verify: {url}",
    "We noticed unusual login attempts. Confirm your account here: {url}",
    "Your payment failed. Update your information: {url}",
    "Your account is at risk. Reactivate now: {url}",
    "Immediate action required: reset your password at {url}",
    "Your account will be deleted if not verified: {url}",
    "Unlock your account by confirming your details here: {url}",
    "Security alert! Review activity: {url}",
    "Final notice: click here to keep your account active: {url}"
]
legit_bodies = [
    "Hi Team, Just a reminder that we have a meeting scheduled tomorrow at 10:00 AM in the main conference room. Please bring your project updates.",
    "Hello, Your order has shipped and is on its way! Track your package here: https://www.amazon.com/trackorder",
    "Welcome to our weekly newsletter. Here are the top stories...",
    "Attached is the invoice for your recent purchase. Thank you for shopping with us.",
    "The project is on track for completion. Let me know if you need anything else.",
    "Your latest bank statement is now available in your online banking portal.",
    "You're invited to our annual event! RSVP here.",
    "Your password was changed successfully. No further action is needed.",
    "Your account settings have been updated as requested.",
    "Thank you for your feedback. We appreciate your input."
]

def random_phishing_email():
    subj = random.choice(phishing_subjects)
    url = random_phishing_url()
    body_template = random.choice(phishing_bodies)
    body = body_template.format(url=url)
    return subj, body

def random_legit_email():
    subj = random.choice(legit_subjects)
    body = random.choice(legit_bodies)
    return subj, body

# ---- Write URLs ----
with open("custom_urls.csv", "w", newline='', encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["url", "label"])
    # Phishing
    for _ in range(N_URLS):
        writer.writerow([random_phishing_url(), 1])
    # Legit
    for _ in range(N_URLS):
        writer.writerow([random_legit_url(), 0])

# ---- Write Emails ----
with open("custom_emails.csv", "w", newline='', encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["subject", "body", "label"])
    # Phishing
    for _ in range(N_EMAILS):
        subj, body = random_phishing_email()
        writer.writerow([subj, body, 1])
    # Legit
    for _ in range(N_EMAILS):
        subj, body = random_legit_email()
        writer.writerow([subj, body, 0])

print("Generated 5000 phishing + 5000 legit URLs and emails each!")