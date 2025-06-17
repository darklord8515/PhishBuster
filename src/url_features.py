import re
from urllib.parse import urlparse
import tldextract

SAFE_DOMAINS = [
    "coursera.org", "google.com", "github.com", "microsoft.com", "apple.com", "wikipedia.org",
    "amazon.com", "facebook.com", "linkedin.com", "twitter.com", "instagram.com", "youtube.com",
    "outlook.com", "yahoo.com", "gmail.com", "dropbox.com", "adobe.com", "stackoverflow.com",
    "paypal.com", "office.com", "mozilla.org", "bbc.com", "espn.com", "cnn.com", "nytimes.com",
    "reddit.com", "quora.com", "cloudflare.com", "netflix.com", "whatsapp.com", "udemy.com", "khanacademy.org",
    "spotify.com", "slack.com", "zoom.us", "airbnb.com", "booking.com", "github.io", "icloud.com", "medium.com",
    "forbes.com", "bloomberg.com", "salesforce.com", "trello.com", "asana.com", "atlassian.net", "bitbucket.org",
    "digitalocean.com", "heroku.com", "doordash.com", "uber.com", "lyft.com", "stripe.com", "visa.com", "mastercard.com",
    "americanexpress.com", "capitalone.com", "chase.com", "bankofamerica.com", "usbank.com", "citibank.com", "discover.com",
    "samsung.com", "huawei.com", "hbo.com", "disneyplus.com", "primevideo.com", "coursera.com", "edx.org", "pluralsight.com",
    "udacity.com", "datacamp.com", "alibaba.com", "taobao.com", "weibo.com", "baidu.com", "163.com", "qq.com", "tmall.com"
]

SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'zip', 'review', 'fit', 'club'}

def extract_url_features(url):
    parsed = urlparse(url)
    feats = {}
    url_lc = url.lower()
    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    tld = ext.suffix
    domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""

    feats['url_length'] = len(url)
    feats['hostname_length'] = len(hostname)
    feats['path_length'] = len(parsed.path)
    feats['num_dots'] = url.count('.')
    feats['num_hyphens'] = url.count('-')
    feats['num_at'] = url.count('@')
    feats['num_question'] = url.count('?')
    feats['num_equals'] = url.count('=')
    feats['num_underscore'] = url.count('_')
    feats['num_and'] = url.count('&')
    feats['num_percent'] = url.count('%')
    feats['num_slash'] = url.count('/')
    feats['num_colon'] = url.count(':')
    feats['num_digits'] = sum(c.isdigit() for c in url)
    feats['num_letters'] = sum(c.isalpha() for c in url)
    feats['has_https'] = int(url_lc.startswith('https'))
    feats['has_ip'] = int(bool(re.match(r'http[s]?://(\d{1,3}\.){3}\d{1,3}', url_lc)))
    feats['count_www'] = url_lc.count('www')
    feats['count_com'] = url_lc.count('.com')
    feats['count_exe'] = url_lc.count('.exe')
    feats['tld_length'] = len(tld)
    feats['is_suspicious_tld'] = int(tld in SUSPICIOUS_TLDS)
    feats['num_subdomains'] = len(hostname.split('.')) - 2 if len(hostname.split('.')) > 2 else 0
    feats['starts_with_http'] = int(url_lc.startswith('http'))
    feats['has_double_slash'] = int('//' in parsed.path[1:])  # skip the '//' after protocol
    feats['has_https_token'] = int('https' in parsed.path.lower() or 'https' in parsed.query.lower())
    feats['is_long_url'] = int(len(url) > 75)
    feats['is_encoded'] = int('%' in url)
    feats['is_whitelisted_domain'] = int(domain in SAFE_DOMAINS)
    # Suspicious words
    suspicious_words = [
        'login', 'secure', 'account', 'update', 'bank', 'verify', 'webscr', 'confirm',
        'signin', 'submit', 'admin', 'wp', 'host', 'invoice', 'pay', 'password', 'ebayisapi', 'paypal'
    ]
    for word in suspicious_words:
        feats[f'word_{word}'] = int(word in url_lc)
    return feats