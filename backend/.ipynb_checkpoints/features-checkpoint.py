from urllib.parse import urlparse, unquote
import re
import unicodedata

# Known URL shorteners
SHORTENERS = r'(bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|cli\.gs|pic\.gd|DwarfURL\.com|zip\.net|short\.to|tiny\.cc|tr\.im|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net)'

# Known brands for typosquatting detection
BRANDS = ['google', 'facebook', 'paypal', 'apple', 'amazon', 'microsoft', 'netflix', 'instagram', 'twitter', 'linkedin', 'whatsapp', 'youtube', 'yahoo', 'gmail', 'outlook', 'bankofamerica', 'chase', 'wellsfargo', 'x']

# Homograph detection - standard confusable pairs from phishing research
CONFUSABLE_PAIRS = {
    'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р',
    'c': 'с', 'x': 'х', 'y': 'у', 'i': 'і'
}

def approximate_unicode_script(char):
    """Heuristic script approximation using codepoint ranges"""
    codepoint = ord(char)
    if 0x0410 <= codepoint <= 0x04FF: return 'CYRILLIC'
    if 0x0370 <= codepoint <= 0x03FF: return 'GREEK'
    if codepoint <= 0x007F: return 'LATIN'
    try:
        name = unicodedata.name(char, '').upper()
        if 'CYRILLIC' in name: return 'CYRILLIC'
        if 'GREEK' in name: return 'GREEK'
    except:
        pass
    return 'OTHER'

def calculate_homograph_risk(hostname):
    """Risk scoring: 0=safe, 1=suspicious, 2=high risk"""
    risk = 0

    non_ascii_scripts = [approximate_unicode_script(c) for c in hostname if ord(c) > 127]

    # Check mix of ASCII Latin letters + Cyrillic/Greek lookalikes
    has_latin = any(ord(c) <= 127 and c.isalpha() for c in hostname)
    has_cyrillic = 'CYRILLIC' in non_ascii_scripts
    has_greek = 'GREEK' in non_ascii_scripts

    # Priority 1: Mixed Latin + Cyrillic or Greek (classic homograph attack)
    if has_latin and (has_cyrillic or has_greek):
        return 2

    # Priority 2: Punycode + non-ASCII
    if 'xn--' in hostname.lower() and any(ord(c) > 127 for c in hostname):
        risk = max(risk, 1)

    # Priority 3: Multiple confusable glyphs
    confusable_count = sum(1 for c in hostname.lower()
                           if any(c == CONFUSABLE_PAIRS.get(ascii_char, '')
                                  for ascii_char in CONFUSABLE_PAIRS))
    if confusable_count >= 2:
        risk = max(risk, 2)
    elif confusable_count == 1:
        risk = max(risk, 1)

    return risk

def extract_homograph_features(hostname):
    """Balanced homograph feature vector"""
    features = {}
    features['homograph_risk'] = calculate_homograph_risk(hostname)
    features['has_non_ascii'] = 1 if any(ord(c) > 127 for c in hostname) else 0

    non_ascii_scripts = [approximate_unicode_script(c) for c in hostname if ord(c) > 127]
    has_latin = any(ord(c) <= 127 and c.isalpha() for c in hostname)
    has_cyrillic = 'CYRILLIC' in non_ascii_scripts
    has_greek = 'GREEK' in non_ascii_scripts

    features['mixed_scripts'] = 1 if (has_latin and (has_cyrillic or has_greek)) else 0
    features['has_cyrillic'] = 1 if has_cyrillic else 0
    features['punycode'] = 1 if 'xn--' in hostname.lower() else 0

    confusable_count = sum(1 for c in hostname.lower()
                           if any(c == CONFUSABLE_PAIRS.get(ascii_char, '')
                                  for ascii_char in CONFUSABLE_PAIRS))
    features['confusable_count'] = confusable_count

    return features

def has_homograph_chars(text):
    """Original basic check (backward compatibility)"""
    try:
        text.encode('ascii')
        return 0
    except UnicodeEncodeError:
        return 1

def has_non_ascii(text):
    return 1 if any(ord(c) > 127 for c in text) else 0

def detect_typosquatting(hostname):
    hostname_clean = hostname.lower().replace('www.', '')
    domain = hostname_clean.split('.')[0]
    normalized = domain.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('@', 'a').replace('5', 's')
    for brand in BRANDS:
        if normalized == brand and domain != brand:
            return 1
        if brand in normalized and normalized != brand:
            if len(normalized) - len(brand) <= 2:
                return 1
    return 0

def detect_encoding_obfuscation(url):
    decoded = unquote(url)
    if decoded != url:
        return 1
    if re.search(r'%[0-9a-fA-F]{2}', url):
        return 1
    return 0

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()

    # URL length
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)
    features['ip'] = 1 if re.match(r'(\d{1,3}\.){3}\d{1,3}', hostname) else 0

    # Special characters
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')

    # www and com counts
    features['nb_www'] = url.count('www')
    features['nb_com'] = url.count('.com')
    features['nb_dslash'] = url.count('//')

    # HTTPS checks
    features['http_in_path'] = 1 if 'http' in parsed.path else 0
    features['https_token'] = 1 if 'https' in parsed.scheme else 0

    # Digit ratios
    digits = sum(c.isdigit() for c in url)
    features['ratio_digits_url'] = digits / len(url) if len(url) > 0 else 0
    digits_host = sum(c.isdigit() for c in hostname)
    features['ratio_digits_host'] = digits_host / len(hostname) if len(hostname) > 0 else 0

    # Domain features
    features['port'] = 1 if parsed.port else 0
    features['tld_in_path'] = 1 if re.search(r'\.(com|net|org|info|biz)', parsed.path) else 0
    features['tld_in_subdomain'] = 1 if re.search(r'\.(com|net|org|info|biz)', hostname) else 0
    features['abnormal_subdomain'] = 1 if re.search(r'(^|\.)(w+\d+|mail\d+)', hostname) else 0
    features['nb_subdomains'] = len(hostname.split('.')) - 2 if len(hostname.split('.')) > 2 else 0
    features['prefix_suffix'] = 1 if '-' in hostname else 0
    features['random_domain'] = 0
    features['shortening_service'] = 1 if re.search(r'(?<![\w.])' + SHORTENERS + r'(?![\w])', hostname, re.IGNORECASE) else 0
    features['path_extension'] = 1 if re.search(r'\.(exe|php|html|htm|js)', parsed.path) else 0
    features['nb_redirection'] = url.count('//')
    features['nb_external_redirection'] = 0

    # Word features
    words = re.split(r'\W+', url)
    features['length_words_raw'] = len(words)
    features['char_repeat'] = max([url.count(c) for c in set(url)]) if url else 0
    features['shortest_words_raw'] = min([len(w) for w in words if w]) if words else 0
    features['shortest_word_host'] = min([len(w) for w in hostname.split('.') if w]) if hostname else 0
    features['shortest_word_path'] = min([len(w) for w in parsed.path.split('/') if w], default=0) if parsed.path else 0
    features['longest_words_raw'] = max([len(w) for w in words if w]) if words else 0
    features['longest_word_host'] = max([len(w) for w in hostname.split('.') if w]) if hostname else 0
    features['longest_word_path'] = max([len(w) for w in parsed.path.split('/') if w], default=0) if parsed.path else 0
    features['avg_words_raw'] = sum([len(w) for w in words if w]) / len(words) if words else 0
    features['avg_word_host'] = sum([len(w) for w in hostname.split('.') if w]) / len(hostname.split('.')) if hostname else 0
    features['avg_word_path'] = sum([len(w) for w in parsed.path.split('/') if w]) / len([w for w in parsed.path.split('/') if w]) if parsed.path and any(parsed.path.split('/')) else 0

    # Phishing hints
    features['phish_hints'] = 1 if re.search(r'(login|signin|verify|update|secure|account|password|bank)', url, re.IGNORECASE) else 0
    features['domain_in_brand'] = 0

    # Subdomain structure analysis
    subdomain_parts = hostname.split('.')[:-2] if len(hostname.split('.')) > 2 else []
    subdomain_str = '.'.join(subdomain_parts)
    features['brand_in_subdomain'] = 1 if any(brand in subdomain_str for brand in BRANDS) else 0
    features['brand_in_path'] = 1 if any(brand in parsed.path.lower() for brand in BRANDS) else 0
    features['suspecious_tld'] = 1 if re.search(r'\.(tk|ml|ga|cf|gq|ru|cn|pw|top|xyz|club|online|site|live)', url) else 0
    features['statistical_report'] = 0

    # ORIGINAL homograph features (backward compatibility)
    features['homograph'] = has_homograph_chars(url)
    features['non_ascii'] = has_non_ascii(url)
    features['encoding_obfuscation'] = detect_encoding_obfuscation(url)
    features['typosquatting'] = detect_typosquatting(hostname)

    # Advanced homograph features
    homograph_feats = extract_homograph_features(hostname)
    features.update(homograph_feats)

    # Page features - default to 0 (for ML compatibility)
    page_features = [
        'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
        'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors',
        'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags', 'submit_email',
        'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor',
        'onmouseover', 'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright',
        'whois_registered_domain', 'domain_registration_length', 'domain_age', 'web_traffic',
        'dns_record', 'google_index', 'page_rank'
    ]
    for feat in page_features:
        features[feat] = 0

    return features