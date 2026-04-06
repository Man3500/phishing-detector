from urllib.parse import urlparse
import re

def extract_features(url):
    features = {}
    
    # URL length
    features['length_url'] = len(url)
    
    # Hostname length
    parsed = urlparse(url)
    features['length_hostname'] = len(parsed.netloc)
    features['ip'] = 1 if re.match(r'(\d{1,3}\.){3}\d{1,3}', parsed.netloc) else 0
    
    # Count special characters
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
    
    # Count www and com
    features['nb_www'] = url.count('www')
    features['nb_com'] = url.count('.com')
    features['nb_dslash'] = url.count('//')
    
    # HTTPS checks
    features['http_in_path'] = 1 if 'http' in parsed.path else 0
    features['https_token'] = 1 if 'https' in parsed.scheme else 0
    
    # Ratio of digits
    digits = sum(c.isdigit() for c in url)
    features['ratio_digits_url'] = digits / len(url) if len(url) > 0 else 0
    digits_host = sum(c.isdigit() for c in parsed.netloc)
    features['ratio_digits_host'] = digits_host / len(parsed.netloc) if len(parsed.netloc) > 0 else 0
    
    # Other features
    features['punycode'] = 1 if 'xn--' in url else 0
    features['port'] = 1 if parsed.port else 0
    features['tld_in_path'] = 1 if re.search(r'\.(com|net|org|info|biz)', parsed.path) else 0
    features['tld_in_subdomain'] = 1 if re.search(r'\.(com|net|org|info|biz)', parsed.netloc) else 0
    features['abnormal_subdomain'] = 1 if re.search(r'(^|\.)(w+\d+|mail\d+)', parsed.netloc) else 0
    features['nb_subdomains'] = len(parsed.netloc.split('.')) - 2 if len(parsed.netloc.split('.')) > 2 else 0
    features['prefix_suffix'] = 1 if '-' in parsed.netloc else 0
    features['random_domain'] = 0
    features['shortening_service'] = 1 if re.search(r'(bit\.ly|goo\.gl|tinyurl|ow\.ly)', url) else 0
    features['path_extension'] = 1 if re.search(r'\.(exe|php|html|htm|js)', parsed.path) else 0
    features['nb_redirection'] = url.count('//')
    features['nb_external_redirection'] = 0
    
    # Word based features
    words = re.split(r'\W+', url)
    features['length_words_raw'] = len(words)
    features['char_repeat'] = max([url.count(c) for c in set(url)]) if url else 0
    features['shortest_words_raw'] = min([len(w) for w in words if w]) if words else 0
    features['shortest_word_host'] = min([len(w) for w in parsed.netloc.split('.') if w]) if parsed.netloc else 0
    features['shortest_word_path'] = min([len(w) for w in parsed.path.split('/') if w]) if parsed.path else 0
    features['longest_words_raw'] = max([len(w) for w in words if w]) if words else 0
    features['longest_word_host'] = max([len(w) for w in parsed.netloc.split('.') if w]) if parsed.netloc else 0
    features['longest_word_path'] = max([len(w) for w in parsed.path.split('/') if w]) if parsed.path else 0
    features['avg_words_raw'] = sum([len(w) for w in words if w]) / len(words) if words else 0
    features['avg_word_host'] = sum([len(w) for w in parsed.netloc.split('.') if w]) / len(parsed.netloc.split('.')) if parsed.netloc else 0
    features['avg_word_path'] = sum([len(w) for w in parsed.path.split('/') if w]) / len([w for w in parsed.path.split('/') if w]) if parsed.path else 0
    
    # Phishing hints
    features['phish_hints'] = 1 if re.search(r'(login|signin|verify|update|secure|account|password|bank)', url, re.IGNORECASE) else 0
    features['domain_in_brand'] = 0
    features['brand_in_subdomain'] = 0
    features['brand_in_path'] = 0
    features['suspecious_tld'] = 1 if re.search(r'\.(tk|ml|ga|cf|gq)', url) else 0
    features['statistical_report'] = 0
    
    # Page features - default to 0 since we're URL only
    features['nb_hyperlinks'] = 0
    features['ratio_intHyperlinks'] = 0
    features['ratio_extHyperlinks'] = 0
    features['ratio_nullHyperlinks'] = 0
    features['nb_extCSS'] = 0
    features['ratio_intRedirection'] = 0
    features['ratio_extRedirection'] = 0
    features['ratio_intErrors'] = 0
    features['ratio_extErrors'] = 0
    features['login_form'] = 0
    features['external_favicon'] = 0
    features['links_in_tags'] = 0
    features['submit_email'] = 0
    features['ratio_intMedia'] = 0
    features['ratio_extMedia'] = 0
    features['sfh'] = 0
    features['iframe'] = 0
    features['popup_window'] = 0
    features['safe_anchor'] = 0
    features['onmouseover'] = 0
    features['right_clic'] = 0
    features['empty_title'] = 0
    features['domain_in_title'] = 0
    features['domain_with_copyright'] = 0
    features['whois_registered_domain'] = 0
    features['domain_registration_length'] = 0
    features['domain_age'] = 0
    features['web_traffic'] = 0
    features['dns_record'] = 0
    features['google_index'] = 0
    features['page_rank'] = 0
    
    return features