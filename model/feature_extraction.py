import re
import pandas as pd
from urllib.parse import urlparse

def extract_features(url):
    # ensure the URL is a string (dataset may contain NaNs or numeric types)
    if not isinstance(url, str):
        if pd.isna(url):
            url = ""
        else:
            url = str(url)

    features = {}

    # Length of URL
    features['url_length'] = len(url)

    # Count of dots
    features['dot_count'] = url.count('.')

    # Count of hyphen
    features['hyphen_count'] = url.count('-')

    # Count of @
    features['at_count'] = url.count('@')

    # Count of question mark
    features['question_count'] = url.count('?')

    # Count of equal sign
    features['equal_count'] = url.count('=')

    # Count of digits
    features['digit_count'] = sum(c.isdigit() for c in url)

    # HTTPS presence
    features['https'] = 1 if 'https' in url else 0

    # IP address presence
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0

    # Suspicious words appearing anywhere in the URL
    suspicious_words = ['login', 'verify', 'bank', 'secure', 'update']
    features['suspicious_word'] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    # Homograph / digit‑substitution checks in the hostname
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    # common substitutions (0/o, 1/l, 3/e) followed by m/e etc
    homograph_patterns = [r'c0m$', r'goog1e', r'faceb00k', r'on1ine', r'paypa1']
    features['homograph'] = 1 if any(re.search(pat, host) for pat in homograph_patterns) else 0

    # flag if any digit appears inside the domain portion (excluding port)
    features['digit_in_domain'] = 1 if re.search(r'[0-9]', host.split(':')[0]) else 0

    return features
