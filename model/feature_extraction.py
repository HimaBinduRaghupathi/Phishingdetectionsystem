import re
import pandas as pd
from urllib.parse import urlparse

def extract_features(url):
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

    # Suspicious words
    suspicious_words = ['login', 'verify', 'bank', 'secure', 'update']
    features['suspicious_word'] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    return features
