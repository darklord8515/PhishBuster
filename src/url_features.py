import re
import math
from urllib.parse import urlparse
import tldextract

SAFE_DOMAINS = ["coursera.org", "google.com", "github.com", "microsoft.com", "apple.com", "wikipedia.org",
    "amazon.com", "facebook.com", "linkedin.com", "twitter.com", "instagram.com", "youtube.com",
    "outlook.com", "yahoo.com", "gmail.com", "dropbox.com", "adobe.com", "stackoverflow.com",
    "paypal.com", "office.com", "mozilla.org", "bbc.com", "espn.com", "cnn.com", "nytimes.com",
    "reddit.com", "quora.com", "cloudflare.com", "netflix.com", "whatsapp.com", "udemy.com", "khanacademy.org",
    "spotify.com", "slack.com", "zoom.us", "airbnb.com", "booking.com", "github.io", "icloud.com", "medium.com",
    "forbes.com", "bloomberg.com", "salesforce.com", "trello.com", "asana.com", "atlassian.net", "bitbucket.org",
    "digitalocean.com", "heroku.com", "doordash.com", "uber.com", "lyft.com", "stripe.com", "visa.com", "mastercard.com",
    "americanexpress.com", "capitalone.com", "chase.com", "bankofamerica.com", "usbank.com", "citibank.com", "discover.com",
    "samsung.com", "huawei.com", "hbo.com", "disneyplus.com", "primevideo.com", "coursera.com", "edx.org", "pluralsight.com",
    "udacity.com", "datacamp.com", "alibaba.com", "taobao.com", "weibo.com", "baidu.com", "163.com", "qq.com", "tmall.com",
    "jd.com", "sina.com.cn", "sohu.com", "youku.com", "tencent.com", "xiaomi.com", "oppo.com", "vivo.com", "lenovo.com", "zte.com.cn",
    "tiktok.com", "pinterest.com", "tumblr.com", "flickr.com", "vimeo.com", "soundcloud.com", "bandcamp.com", "mixcloud.com", "last.fm",
    "behance.net", "dribbble.com", "deviantart.com", "artstation.com", "500px.com", "unsplash.com", "pixabay.com", "pexels.com", 
   
]

SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'zip', 'review', 'fit', 'club'}

BRANDS = [
    "paypal", "apple", "facebook", "microsoft", "google", "amazon", "bankofamerica", "whatsapp",
    "icloud", "instagram", "linkedin", "twitter", "youtube", "outlook", "yahoo", "dropbox", "adobe", "netflix", "spotify", "slack", "zoom", "airbnb", "booking", "github", "coursera",
    "khanacademy", "udemy", "edx", "pluralsight", "udacity", "datacamp", "salesforce", "trello", "asana", "atlassian", "bitbucket", "digitalocean", "heroku", "stripe", "visa", "mastercard",
]

HOMOGLYPHS = {'0', '1', 'l', 'i', '5', '3', '2', '8', '6', '9', '@', '$'}
SUSPICIOUS_WORDS = [
    'login', 'secure', 'account', 'update', 'bank', 'verify', 'webscr', 'confirm',
    'signin', 'submit', 'admin', 'wp', 'host', 'invoice', 'pay', 'password', 'ebayisapi', 'paypal', 'support', 'help', 'reset'
]

def shannon_entropy(s):
    # Calculate the Shannon entropy of a string
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p, 2) for p in prob])

def extract_url_features(url):
    parsed = urlparse(url)
    feats = {}
    url_lc = url.lower()
    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    tld = ext.suffix
    domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""
    subdomain = ext.subdomain

    feats['url_length'] = len(url)
    feats['hostname_length'] = len(hostname)
    feats['domain_length'] = len(ext.domain or "")
    feats['subdomain_length'] = len(subdomain or "")
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
    feats['has_double_slash'] = int('//' in parsed.path[1:])
    feats['has_https_token'] = int('https' in parsed.path.lower() or 'https' in parsed.query.lower())
    feats['is_long_url'] = int(len(url) > 75)
    feats['is_encoded'] = int('%' in url)
    feats['is_whitelisted_domain'] = int(domain in SAFE_DOMAINS)
    feats['hostname_entropy'] = shannon_entropy(hostname)
    feats['has_homoglyph'] = int(any(c in HOMOGLYPHS for c in hostname))
    feats['subdomain_suspicious'] = int(any(brand in subdomain for brand in BRANDS))
    # Brand in subdomain but not official domain
    feats['brand_in_subdomain_not_official'] = 0
    for brand in BRANDS:
        if brand in hostname and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
            feats['brand_in_subdomain_not_official'] = 1
            break
    # Suspicious words and combos
    num_suspicious_words = 0
    for word in SUSPICIOUS_WORDS:
        found = int(word in url_lc)
        feats[f'word_{word}'] = found
        num_suspicious_words += found
    feats['num_suspicious_words'] = num_suspicious_words
    feats['combo_suspicious_words'] = int(num_suspicious_words >= 2)
    # Suspicious path (has login, verify, etc)
    feats['path_suspicious'] = int(any(word in parsed.path.lower() for word in SUSPICIOUS_WORDS))
    # Suspicious pattern: brand-support/help/secure in subdomain
    feats['subdomain_support_or_help'] = int(any(x in subdomain for x in ['support', 'help', 'secure']))
    return feats