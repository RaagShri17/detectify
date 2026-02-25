"""
PhishGuard - Phishing Awareness Website
Backend: Flask + ML-based phishing detection
"""
from flask_cors import CORS
from flask import Flask, render_template, request, jsonify
import re
import math
from collections import Counter

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
#  ML-BASED PHISHING DETECTOR (No external libs)
#  Uses handcrafted features + weighted scoring
# ─────────────────────────────────────────────

class PhishingDetector:
    """
    Rule/feature-based phishing detector that mimics
    an ML pipeline:  feature extraction → weighted score → classification
    """

    URGENT_WORDS = [
        "urgent", "immediately", "action required", "verify now",
        "suspended", "locked", "limited time", "expire", "click here",
        "confirm your account", "update your information", "won", "winner",
        "congratulations", "prize", "free", "risk", "alert", "warning",
        "unusual activity", "unauthorized", "compromised", "reset your password"
    ]

    LEGIT_DOMAINS = [
        "gmail.com", "yahoo.com", "outlook.com", "microsoft.com",
        "apple.com", "amazon.com", "paypal.com", "google.com",
        "facebook.com", "twitter.com", "linkedin.com", "github.com"
    ]

    def extract_features(self, text: str) -> dict:
        text_lower = text.lower()

        # 1. Urgency language score
        urgency_count = sum(1 for w in self.URGENT_WORDS if w in text_lower)

        # 2. Suspicious URLs
        urls = re.findall(r'https?://[^\s]+', text)
        suspicious_url_count = 0
        for url in urls:
            domain = re.findall(r'https?://([^/]+)', url)
            if domain:
                d = domain[0]
                # IP address instead of domain
                if re.match(r'\d+\.\d+\.\d+\.\d+', d):
                    suspicious_url_count += 3
                # Lots of hyphens
                elif d.count('-') > 2:
                    suspicious_url_count += 2
                # Looks like a legit domain but isn't
                elif any(legit in d and not d.endswith(legit) for legit in self.LEGIT_DOMAINS):
                    suspicious_url_count += 3

        # 3. Grammar & spelling heuristics
        sentences = re.split(r'[.!?]', text)
        long_sentences = sum(1 for s in sentences if len(s.split()) > 40)

        # 4. Excessive punctuation / caps
        exclamation_count = text.count('!')
        caps_ratio = sum(1 for c in text if c.isupper()) / (len(text) + 1)

        # 5. Suspicious requests
        sensitive_patterns = [
            r'(ssn|social security)',
            r'(credit card|card number|cvv)',
            r'(password|passwd|pwd)',
            r'(bank account|routing number)',
            r'(date of birth|dob)',
        ]
        sensitive_count = sum(1 for p in sensitive_patterns if re.search(p, text_lower))

        # 6. Mismatched sender (if email-like)
        email_addresses = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', text)
        domain_mismatch = 0
        if email_addresses:
            domains = [e.split('@')[1] for e in email_addresses]
            if len(set(domains)) > 2:
                domain_mismatch = 2

        # 7. Entropy of text (phishing often has odd character distribution)
        char_counts = Counter(text_lower)
        total = sum(char_counts.values())
        entropy = -sum((c/total) * math.log2(c/total) for c in char_counts.values() if c > 0)

        return {
            "urgency_count": urgency_count,
            "suspicious_url_count": suspicious_url_count,
            "long_sentences": long_sentences,
            "exclamation_count": exclamation_count,
            "caps_ratio": round(caps_ratio, 3),
            "sensitive_count": sensitive_count,
            "domain_mismatch": domain_mismatch,
            "entropy": round(entropy, 3),
            "url_count": len(urls),
            "word_count": len(text.split()),
        }

    def predict(self, text: str) -> dict:
        features = self.extract_features(text)

        # Weighted scoring (simulates trained weights)
        score = 0
        score += features["urgency_count"] * 12
        score += features["suspicious_url_count"] * 20
        score += features["sensitive_count"] * 18
        score += features["exclamation_count"] * 4
        score += features["caps_ratio"] * 30
        score += features["domain_mismatch"] * 15
        score += features["long_sentences"] * 5

        # Entropy: very low or very high = suspicious
        if features["entropy"] < 3.5 or features["entropy"] > 5.5:
            score += 10

        # Normalize to 0–100
        phishing_probability = min(100, score)
        is_phishing = phishing_probability >= 40

        # Build red flags list
        red_flags = []
        if features["urgency_count"] >= 2:
            red_flags.append(f"⚠️ Contains {features['urgency_count']} urgency/pressure phrases")
        if features["suspicious_url_count"] > 0:
            red_flags.append(f"🔗 Found {features['suspicious_url_count']} suspicious URL pattern(s)")
        if features["sensitive_count"] > 0:
            red_flags.append(f"🔑 Requests sensitive info ({features['sensitive_count']} pattern(s))")
        if features["exclamation_count"] > 3:
            red_flags.append(f"❗ Excessive punctuation ({features['exclamation_count']} exclamation marks)")
        if features["caps_ratio"] > 0.15:
            red_flags.append(f"🔠 High capitalization ratio ({int(features['caps_ratio']*100)}%)")
        if features["domain_mismatch"]:
            red_flags.append("📧 Multiple different sender domains detected")

        safe_signs = []
        if features["urgency_count"] == 0:
            safe_signs.append("✅ No urgency/pressure language")
        if features["suspicious_url_count"] == 0 and features["url_count"] > 0:
            safe_signs.append("✅ URLs appear structurally safe")
        if features["sensitive_count"] == 0:
            safe_signs.append("✅ No requests for sensitive information")
        if features["caps_ratio"] <= 0.1:
            safe_signs.append("✅ Normal capitalization")

        return {
            "is_phishing": is_phishing,
            "phishing_probability": phishing_probability,
            "verdict": "PHISHING" if is_phishing else "LEGITIMATE",
            "confidence": "High" if abs(phishing_probability - 50) > 25 else "Medium",
            "red_flags": red_flags,
            "safe_signs": safe_signs,
            "features": features,
        }


detector = PhishingDetector()



# ─────────────────────────────────────────────
#  URL-BASED PHISHING DETECTOR
# ─────────────────────────────────────────────

class URLPhishingDetector:
    """
    Extracts structural/lexical features from a URL
    and applies weighted scoring to classify it.
    """

    SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.link', '.work']
    BRAND_KEYWORDS  = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix',
                       'facebook', 'instagram', 'bank', 'secure', 'login', 'signin',
                       'account', 'update', 'verify', 'confirm', 'billing']
    LEGIT_DOMAINS   = ['paypal.com', 'amazon.com', 'apple.com', 'google.com',
                       'microsoft.com', 'netflix.com', 'facebook.com', 'instagram.com',
                       'github.com', 'twitter.com', 'linkedin.com']

    def extract_features(self, url: str) -> dict:
        url_lower = url.lower().strip()

        # Parse components
        proto_match = re.match(r'^(https?)://', url_lower)
        protocol = proto_match.group(1) if proto_match else 'none'
        no_proto  = re.sub(r'^https?://', '', url_lower)
        domain_part = no_proto.split('/')[0]
        path_part   = '/' + '/'.join(no_proto.split('/')[1:]) if '/' in no_proto else ''

        # 1. Uses HTTPS
        uses_https = 1 if protocol == 'https' else 0

        # 2. IP address as host
        is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', domain_part) else 0

        # 3. URL length (long URLs are suspicious)
        url_length = len(url)

        # 4. Number of subdomains
        subdomain_count = max(0, len(domain_part.split('.')) - 2)

        # 5. Hyphen count in domain
        hyphen_count = domain_part.count('-')

        # 6. Suspicious TLD
        tld = '.' + domain_part.split('.')[-1] if '.' in domain_part else ''
        has_suspicious_tld = 1 if tld in self.SUSPICIOUS_TLDS else 0

        # 7. Brand keyword in domain but NOT the real domain
        brand_in_domain = 0
        for brand in self.BRAND_KEYWORDS:
            if brand in domain_part:
                real = f'{brand}.com'
                if not (domain_part == real or domain_part.endswith(f'.{real}')):
                    brand_in_domain += 1

        # 8. Special chars in path (@, //, extra dots)
        at_symbol = 1 if '@' in url else 0
        double_slash = 1 if '//' in path_part else 0

        # 9. Digits in domain name
        digit_count = sum(c.isdigit() for c in domain_part)

        # 10. Query string length / params
        query = url.split('?')[1] if '?' in url else ''
        query_length = len(query)
        param_count  = query.count('&') + 1 if query else 0

        # 11. Known legitimate domain?
        is_legit_domain = 0
        for legit in self.LEGIT_DOMAINS:
            if domain_part == legit or domain_part.endswith('.' + legit):
                is_legit_domain = 1
                break

        # 12. Path depth
        path_depth = path_part.count('/')

        return {
            'uses_https':          uses_https,
            'is_ip_address':       is_ip,
            'url_length':          url_length,
            'subdomain_count':     subdomain_count,
            'hyphen_count':        hyphen_count,
            'suspicious_tld':      has_suspicious_tld,
            'brand_in_domain':     brand_in_domain,
            'at_symbol':           at_symbol,
            'double_slash_path':   double_slash,
            'digit_in_domain':     digit_count,
            'query_param_count':   param_count,
            'query_length':        query_length,
            'is_legit_domain':     is_legit_domain,
            'path_depth':          path_depth,
        }

    def predict(self, url: str) -> dict:
        features = self.extract_features(url)
        score = 0

        # Scoring weights
        score += features['is_ip_address']    * 35
        score += features['brand_in_domain']  * 30
        score += features['suspicious_tld']   * 25
        score += features['at_symbol']        * 20
        score += features['hyphen_count']     * 6
        score += features['subdomain_count']  * 8
        score += features['double_slash_path']* 15
        score += features['digit_in_domain']  * 3
        score += features['query_param_count']* 2
        if features['url_length'] > 75:  score += 10
        if features['url_length'] > 100: score += 10
        if not features['uses_https']:   score += 20

        # Legitimate domain is a strong negative signal
        if features['is_legit_domain']:
            score = max(0, score - 40)

        phishing_probability = min(100, score)
        is_phishing = phishing_probability >= 40

        # Red flags
        red_flags = []
        if features['is_ip_address']:
            red_flags.append("🔴 Uses raw IP address instead of domain name")
        if features['brand_in_domain']:
            red_flags.append(f"🔴 Brand name in domain but not the real domain ({features['brand_in_domain']} match(es))")
        if features['suspicious_tld']:
            red_flags.append("🔴 Uses suspicious free/high-risk TLD (.xyz, .tk, etc.)")
        if not features['uses_https']:
            red_flags.append("🔴 No HTTPS — connection is not encrypted")
        if features['at_symbol']:
            red_flags.append("🔴 '@' symbol in URL — browser ignores everything before it")
        if features['hyphen_count'] > 2:
            red_flags.append(f"🔴 Many hyphens in domain ({features['hyphen_count']}) — spoofing tactic")
        if features['subdomain_count'] > 2:
            red_flags.append(f"🔴 Deep subdomain structure ({features['subdomain_count']} levels)")
        if features['url_length'] > 75:
            red_flags.append(f"🔴 Unusually long URL ({features['url_length']} chars) to obscure destination")
        if features['double_slash_path']:
            red_flags.append("🔴 Double slash in path — URL redirection trick")

        # Safe signs
        safe_signs = []
        if features['uses_https']:
            safe_signs.append("✅ Uses HTTPS (encrypted connection)")
        if features['is_legit_domain']:
            safe_signs.append("✅ Matches a known legitimate domain")
        if not features['is_ip_address']:
            safe_signs.append("✅ Uses a proper domain name, not a raw IP")
        if features['brand_in_domain'] == 0:
            safe_signs.append("✅ No brand name spoofing detected")
        if not features['suspicious_tld']:
            safe_signs.append("✅ Standard, reputable TLD")
        if features['hyphen_count'] <= 1:
            safe_signs.append("✅ Clean domain with minimal hyphens")

        return {
            "is_phishing":          is_phishing,
            "phishing_probability": phishing_probability,
            "verdict":              "PHISHING" if is_phishing else "LEGITIMATE",
            "confidence":           "High" if abs(phishing_probability - 50) > 25 else "Medium",
            "red_flags":            red_flags,
            "safe_signs":           safe_signs,
            "features":             features,
        }


url_detector = URLPhishingDetector()

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    text = data.get('text', '').strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400
    result = detector.predict(text)
    return jsonify(result)

@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    data = request.get_json()
    email = data.get('email', '').strip()

    if not email:
        return jsonify({"error": "No email provided"}), 400

    # Simple reuse of URL-style logic on domain
    domain = email.split('@')[-1] if '@' in email else email
    result = url_detector.predict("http://" + domain)

    return jsonify(result)

@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

@app.route('/learn')
def learn():
    return render_template('learn.html')


@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    # Add scheme if missing so parsing works
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    result = url_detector.predict(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)