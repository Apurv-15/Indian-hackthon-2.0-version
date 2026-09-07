"""
╔════════════════════════════════════════════════════════════════════════════╗
║                     AGENT 1: EXTERNAL ANALYSIS AGENT                        ║
║              URL, Domain & External Threat Intelligence Analysis             ║
╚════════════════════════════════════════════════════════════════════════════╝

ALGORITHMS USED:

1. SUPPORT VECTOR MACHINE (SVM)
   - Model File: phishing_new.pkl
   - Vectorizer: vectorizerurl_new.pkl (TF-IDF)
   - Purpose: URL classification for malicious/phishing detection
   - Training Data: malicious_url_dataset.csv
   - Implementation: scikit-learn SVM classifier
   - Output: Probability of URL being malicious (0-1 scale)
   - Use Case: Detects sophisticated URL patterns not caught by heuristics

2. SENTENCE TRANSFORMERS (MiniLM-L6-v2 Embeddings)
   - Model: sentence-transformers/all-MiniLM-L6-v2
   - Purpose: Semantic similarity matching for domain/brand impersonation detection
   - Application: Homoglyph attack detection by comparing embeddings
   - Output: Cosine similarity scores (0-1 scale)
   - Use Case: Identifies domains similar to legitimate brands

3. HEURISTIC PATTERN MATCHING
   - Regex patterns for TLD detection
   - Keyword spotting (login, verify, account, etc.)
   - IP address detection
   - URL shortener detection
   - Subdomain analysis

4. SEQUENCE MATCHING (String Similarity)
   - algorithm: difflib.SequenceMatcher
   - Purpose: Fuzzy string matching for domain name comparison
   - Example: comparing "gogle.com" to "google.com"
"""

import re
from sentence_transformers import SentenceTransformer
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from urllib.parse import urlparse
from difflib import SequenceMatcher
import os
import pickle
import requests

class ExternalAnalysisAgent:
    def __init__(self):
        print("Loading External Analysis Agent...")
        self.model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
        
        # Load pickle models for URL analysis
        # ALGORITHM: Support Vector Machine (SVM) with TF-IDF vectorization
        # Training data: malicious_url_dataset.csv
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        try:
            with open(os.path.join(model_dir, 'phishing_new.pkl'), 'rb') as f:
                self.url_ml_model = pickle.load(f)  # SVM / LogisticRegression classifier
                # Patch for sklearn version mismatch (model pickled with newer version)
                if hasattr(self.url_ml_model, '_estimator_type') and not hasattr(self.url_ml_model, 'multi_class'):
                    self.url_ml_model.multi_class = 'auto'
            with open(os.path.join(model_dir, 'vectorizerurl_new.pkl'), 'rb') as f:
                self.url_vectorizer = pickle.load(f)  # TF-IDF feature extractor
            self.has_url_ml = True
            print("Successfully loaded URL ML models (SVM + TF-IDF).")
        except Exception as e:
            print(f"Failed to load URL ML models: {e}")
            self.has_url_ml = False

        # Load UCI model
        try:
            with open(os.path.join(model_dir, 'phishing_uci_model.pkl'), 'rb') as f:
                self.url_uci_model = pickle.load(f)
            self.has_url_uci = True
            print("Successfully loaded URL UCI model (Random Forest).")
        except Exception as e:
            print(f"Failed to load URL UCI model: {e}")
            self.has_url_uci = False
        
        self.phishing_patterns = [
            "verify your account immediately",
            "suspicious activity detected",
            "click here to confirm",
            "your account will be suspended",
            "update your payment information",
            "unusual sign-in attempt",
            "secure your account now",
            "limited time offer",
            "you have won a prize",
            "inheritance money transfer"
        ]
        
        self.suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.win', '.bid']
        
        self.legitimate_brand_domains = {
            'google': ['google.com', 'google.co.in', 'gmail.com', 'youtube.com'],
            'microsoft': ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
            'amazon': ['amazon.com', 'amazon.in', 'amazon.co.uk'],
            'paypal': ['paypal.com'],
            'apple': ['apple.com', 'icloud.com'],
            'netflix': ['netflix.com'],
            'facebook': ['facebook.com', 'fb.com'],
            'instagram': ['instagram.com'],
            'chase': ['chase.com'],
            'wellsfargo': ['wellsfargo.com'],
            'openai': ['openai.com', 'chatgpt.com'],
            'linkedin': ['linkedin.com'],
            'github': ['github.com'],
            # Indian Banking & Financial Services
            'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'],
            'hdfc': ['hdfcbank.com', 'hdfc.com'],
            'icici': ['icicibank.com'],
            'axis': ['axisbank.com'],
            'kotak': ['kotak.com'],
            'paytm': ['paytm.com'],
            'phonepe': ['phonepe.com'],
            # Indian Government & Public Utilities
            'indiapost': ['indiapost.gov.in'],
            'incometax': ['incometax.gov.in', 'incometaxindiaefiling.gov.in'],
            'uidai': ['uidai.gov.in'],
            # Logistics, Couriers & Crypto
            'shiprocket': ['shiprocket.in', 'shiprocket.com'],
            'bluedart': ['bluedart.com'],
            'binance': ['binance.com'],
            'metamask': ['metamask.io']
        }
        self.legitimate_domains = [domain for domains in self.legitimate_brand_domains.values() for domain in domains]
        self._live_cache = {}
        
        self.pattern_embeddings = self.model.encode(self.phishing_patterns)
        
        # Load PhishTank verified phishing URL database
        self.phishtank_urls = self.load_phishtank_database()
        
        print("External Analysis Agent loaded successfully!")
    
    def check_url_live(self, url):
        """
        Fast, cached reachability check.
        Uses low-latency DNS resolution first (<50ms), then cached HTTP verification.
        """
        import socket
        try:
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path.split('/')[0]
            if ':' in host:
                host = host.split(':')[0]
            host = host.lower().strip()
        except Exception:
            host = url

        if not host:
            return {'reachable': False, 'ssl_valid': True, 'final_url': url, 'redirected': False}

        if host in self._live_cache:
            return self._live_cache[host]

        result = {'reachable': False, 'ssl_valid': True, 'final_url': url, 'redirected': False}

        try:
            resp = requests.get(url, timeout=1.5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            result['reachable'] = True
            result['final_url'] = resp.url
            final_host = urlparse(resp.url).netloc.lower().split(':')[0]
            result['redirected'] = final_host != host and final_host != f"www.{host}" and host != f"www.{final_host}"
        except requests.exceptions.SSLError:
            result['ssl_valid'] = False
            result['reachable'] = True
        except Exception:
            # Fallback: check if host at least resolves in DNS
            try:
                socket.gethostbyname(host)
                result['reachable'] = True
            except Exception:
                result['reachable'] = False


        self._live_cache[host] = result
        return result


    def load_phishtank_database(self):
        """
        Load PhishTank verified phishing database (free, no API key).
        Downloads once and caches locally. Re-downloads if older than 24h.
        """
        import json, time
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        os.makedirs(data_dir, exist_ok=True)
        cache_path = os.path.join(data_dir, 'phishtank_cache.json')
        
        # Check if cache exists and is fresh (< 24 hours)
        if os.path.exists(cache_path):
            age_hours = (time.time() - os.path.getmtime(cache_path)) / 3600
            if age_hours < 24:
                try:
                    with open(cache_path, 'r') as f:
                        urls = set(json.load(f))
                    print(f"PhishTank: Loaded {len(urls)} URLs from cache ({age_hours:.1f}h old).")
                    return urls
                except Exception:
                    pass
        
        # Download fresh database
        print("PhishTank: Downloading latest verified phishing database...")
        try:
            resp = requests.get(
                'http://data.phishtank.com/data/online-valid.json',
                timeout=30,
                headers={'User-Agent': 'phishtank/aegisai'}
            )
            if resp.status_code == 200:
                data = resp.json()
                urls = set()
                for entry in data:
                    url = entry.get('url', '').strip().rstrip('/')
                    if url:
                        urls.add(url.lower())
                # Cache it
                with open(cache_path, 'w') as f:
                    json.dump(list(urls), f)
                print(f"PhishTank: Downloaded and cached {len(urls)} verified phishing URLs.")
                return urls
            else:
                print(f"PhishTank: HTTP {resp.status_code}, using empty set.")
                return set()
        except Exception as e:
            print(f"PhishTank: Download failed ({e}), using empty set.")
            return set()
    
    def check_phishtank(self, url):
        """Check if URL is in the PhishTank verified phishing database."""
        normalized = url.lower().strip().rstrip('/')
        if normalized in self.phishtank_urls:
            return True
        # Also check without trailing path variants
        from urllib.parse import urlparse
        parsed = urlparse(normalized)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base in self.phishtank_urls:
            return True
        return False

    def analyze_url_risk(self, url):
        """Analyze URL for suspicious patterns"""
        risk_score = 0.0
        reasons = []

        # Real Threat Intelligence Check (PhishTank database)
        if self.check_phishtank(url):
            risk_score = 1.0
            reasons.append("CRITICAL: URL found in PhishTank verified phishing database")
            return risk_score, reasons, 1.0

        # Optional: Google Safe Browsing API (if key is provided)
        api_key = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
        if api_key:
            try:
                endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
                payload = {
                    "client": {"clientId": "aegisai", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                resp = requests.post(endpoint, json=payload, timeout=3)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'matches' in data and len(data['matches']) > 0:
                        threats = [m.get('threatType', 'UNKNOWN') for m in data['matches']]
                        risk_score = 1.0
                        reasons.append(f"CRITICAL: Google Safe Browsing flagged this URL: {', '.join(set(threats))}")
                        return risk_score, reasons, 1.0
            except Exception as e:
                print(f"Safe Browsing API Error: {e}")

        live = self.check_url_live(url)
        if not live['reachable']:
            risk_score += 0.15
            reasons.append("Live check: URL is unreachable right now (DNS/connection failure) — often a dead or sinkholed phishing host")
        else:
            if not live['ssl_valid']:
                risk_score = max(risk_score, 0.6)
                reasons.append("Live check: SSL certificate is invalid on the live connection — insecure or spoofed endpoint")
            if live['redirected']:
                final_domain = urlparse(live['final_url']).netloc
                reasons.append(f"Live check: URL redirects in real time to a different domain: {final_domain}")
                redirect_similarity = self.check_domain_similarity(live['final_url'])
                if redirect_similarity > 0.7:
                    risk_score = max(risk_score, 0.9)
                    reasons.append("Live check: redirect destination impersonates a known brand")

        domain = self.extract_domain(url).lower()
        is_already_official = any(domain == d or domain.endswith('.' + d) for d in self.legitimate_domains)

        for tld in self.suspicious_tlds:
            if domain.endswith(tld) or f"{tld}/" in url.lower():
                risk_score += 0.3
                reasons.append(f"Suspicious TLD: {tld}")
                break
        
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain):
            risk_score += 0.4
            reasons.append("IP address used instead of domain name")
        
        # Only check dots in domain hostname, not query strings
        clean_host = re.sub(r'\.(co|com|gov|net|org|edu)\.[a-z]{2,}$', '', domain)
        if clean_host.count('.') >= 3:
            risk_score += 0.2
            reasons.append(f"Excessive subdomains in host: {domain}")
        
        shortening_services = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'tiny.cc']
        for service in shortening_services:
            if service in domain:
                risk_score += 0.3
                reasons.append(f"URL shortening service detected: {service}")
                break
        
        suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm', 'suspended', 'security', 'banking', 'password', 'validation', 'authenticate']
        matched_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
        # Contextualize: Only penalize keywords if the domain is NOT an official legitimate domain AND other risk signals exist
        if matched_keywords and not is_already_official:
            has_other_signals = (
                any(domain.endswith(tld) for tld in self.suspicious_tlds)
                or not live.get('reachable', True)
                or live.get('redirected', False)
                or not live.get('ssl_valid', True)
                or risk_score > 0.2
            )
            if has_other_signals:
                keyword_boost = min(0.1 * len(matched_keywords), 0.4)
                risk_score += keyword_boost
                reasons.append(f"Suspicious keyword(s) in unverified URL: {', '.join(repr(k) for k in matched_keywords)}")

        # Brand impersonation: Brand appears in domain hostname (NOT path/query) but is not official
        if not is_already_official and domain:
            domain_tokens = set(re.split(r'[\.\-_0-9]+', domain))
            for brand, official_domains in self.legitimate_brand_domains.items():
                if (brand in domain_tokens) or f"-{brand}" in domain or f"{brand}-" in domain:
                    risk_score = max(risk_score, 0.90)
                    reasons.append(f"Brand impersonation: '{brand}' appears in domain '{domain}' but is not an official {brand} domain")
                    break
        
        domain_similarity = self.check_domain_similarity(url)
        if domain_similarity > 0.7:
            risk_score = max(risk_score, 0.85)
            reasons.append(f"Domain '{domain}' is visually similar ({domain_similarity:.0%}) to a legitimate brand (homoglyph/typosquatting)")
            
        url_ml_prob = 0.0
        if self.has_url_ml:
            try:
                # ALGORITHM: TF-IDF + Support Vector Machine (SVM)
                features = self.url_vectorizer.transform([url])
                url_ml_prob = self.url_ml_model.predict_proba(features)[0][1]
            except Exception as e:
                print(f"Error predicting URL with ML model: {e}")

        # UCI Tabular Feature Model Prediction
        url_uci_prob = 0.0
        if getattr(self, 'has_url_uci', False):
            try:
                uci_features = self.extract_uci_features(url, live)
                url_uci_prob = self.url_uci_model.predict_proba([uci_features])[0][1]
            except Exception as e:
                print(f"Error predicting URL with UCI model: {e}")

        # Combine predictions by taking the maximum probability of maliciousness
        combined_ml_prob = max(url_ml_prob, url_uci_prob)

        # If domain is officially legitimate and no homoglyphs, dampen ML false positives
        if is_already_official:
            risk_score = min(risk_score, 0.15)
            combined_ml_prob = min(combined_ml_prob, 0.15)
        else:
            # Hybrid Logic: Weight the ML models heavily if they have high confidence
            if combined_ml_prob > 0.8:
                risk_score = max(risk_score, 0.9)
                reasons.append(f"ML models identified highly malicious URL structure (Score: {combined_ml_prob:.1%})")
            elif combined_ml_prob > 0.5:
                risk_score = max(risk_score, 0.6)
                reasons.append(f"ML models flagged suspicious URL structure (Score: {combined_ml_prob:.1%})")
        
        return min(risk_score, 1.0), reasons, combined_ml_prob
    
    def check_domain_similarity(self, url):
        """
        Check if domain is similar to legitimate domains.
        Compares domain SLD stem and hyphenated sub-tokens against official brand SLD stems.
        Detects leetspeak/homoglyphs (e.g., paypa1 -> paypal, g00gle -> google).
        Filters out false positives like 'pineapple' for 'apple'.
        """
        domain = self.extract_domain(url).lower()
        if not domain:
            return 0.0
        
        # If it is officially the brand or a subdomain of the brand, it is legitimate
        for legit_domain in self.legitimate_domains:
            if domain == legit_domain.lower() or domain.endswith('.' + legit_domain.lower()):
                return 0.0
                
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            if len(domain_parts) >= 3 and domain_parts[-2] in ('co', 'com', 'gov', 'org', 'net'):
                domain_stem = domain_parts[-3]
            else:
                domain_stem = domain_parts[-2]
        else:
            domain_stem = domain_parts[0]

        false_positives = {'pineapple', 'snapple', 'microscope', 'microbiology', 'amazonia', 'chasegroup', 'openness'}
        if domain_stem in false_positives:
            return 0.0

        # Sub-tokens (e.g. 'paypa1' from 'paypa1-security-update')
        candidate_tokens = [domain_stem] + domain_stem.split('-')
        leetspeak_map = str.maketrans({'1': 'l', '0': 'o', '3': 'e', '4': 'a', '5': 's', '@': 'a'})

        max_similarity = 0.0
        for legit_domain in self.legitimate_domains:
            legit_parts = legit_domain.lower().split('.')
            legit_stem = legit_parts[0]

            for tok in candidate_tokens:
                if tok in false_positives or len(tok) < 3:
                    continue

                # Check direct leetspeak normalization (e.g. 'paypa1' -> 'paypal', 'amaz0n' -> 'amazon')
                normalized_tok = tok.translate(leetspeak_map)
                if normalized_tok == legit_stem and tok != legit_stem:
                    return 0.95

                ratio = SequenceMatcher(None, tok, legit_stem).ratio()
                # Only consider typosquats if lengths are close and ratio > 0.70
                if tok != legit_stem and len(tok) >= 4 and abs(len(tok) - len(legit_stem)) <= 2:
                    if ratio > max_similarity:
                        max_similarity = ratio
        
        return max_similarity

    
    def extract_domain(self, url):
        """Extract domain from URL, lowercased and stripped of port"""
        try:
            if not url.startswith('http://') and not url.startswith('https://'):
                url = 'https://' + url
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain.lower().strip()
        except Exception:
            return ""

    
    def analyze(self, input_data):
        """Main analysis function"""
        text = input_data['cleaned_text']
        urls = input_data['urls']
        
        results = {
            'url_risk': 0.0,
            'url_ml_risk': 0.0,
            'domain_similarity': 0.0,
            'suspicious_patterns': [],
            'risk_factors': [],
            'overall_risk': 0.0
        }
        
        if urls:
            url_risks = []
            url_ml_risks = []
            for url in urls:
                risk, reasons, ml_prob = self.analyze_url_risk(url)
                url_risks.append(risk)
                url_ml_risks.append(ml_prob)
                results['risk_factors'].extend(reasons)
            
            results['url_risk'] = np.mean(url_risks) if url_risks else 0
            results['url_ml_risk'] = max(url_ml_risks) if url_ml_risks else 0
            
            results['domain_similarity'] = self.check_domain_similarity(urls[0])
        
        try:
            text_embedding = self.model.encode([text])
            similarities = cosine_similarity(text_embedding, self.pattern_embeddings)[0]
            
            if max(similarities) > 0.6:
                results['suspicious_patterns'].append("Text similar to known phishing patterns")
                results['overall_risk'] += 0.3
        except Exception as e:
            print(f"Error in semantic similarity: {e}")
        
        url_risk_val = max(results['url_risk'], results['url_ml_risk'])
        domain_similarity = results['domain_similarity']
        sim_risk = 0.9 if domain_similarity > 0.7 else (domain_similarity * 0.5)
        results['overall_risk'] = min(
            max(url_risk_val, sim_risk) + 
            len(results['suspicious_patterns']) * 0.3,
            1.0
        )
        
        return results

    def extract_uci_features(self, url, live=None):
        """
        Extract 30 structural/categorical features from a raw URL.
        Features that need a live lookup (WHOIS domain age, traffic rank, page
        rank, backlink count) still default to benign (-1) — those need paid
        APIs, out of scope here. dnsrecord/redirect now come from the real-time
        check_url_live() result instead of being hardcoded.
        """
        live = live or {}
        features = {}
        
        # 1. having_ip_address
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            features['having_ip_address'] = 1
        else:
            features['having_ip_address'] = -1
            
        # 2. url_length
        length = len(url)
        if length < 54:
            features['url_length'] = -1
        elif length <= 75:
            features['url_length'] = 0
        else:
            features['url_length'] = 1
            
        # 3. shortining_service
        shortening_services = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'tiny.cc']
        is_short = any(s in url.lower() for s in shortening_services)
        features['shortining_service'] = 1 if is_short else -1
        
        # 4. having_at_symbol
        features['having_at_symbol'] = 1 if '@' in url else -1
        
        # 5. double_slash_redirecting
        if url.lower().startswith('https://'):
            has_double = '//' in url[8:]
        elif url.lower().startswith('http://'):
            has_double = '//' in url[7:]
        else:
            has_double = '//' in url
        features['double_slash_redirecting'] = 1 if has_double else -1
        
        # 6. prefix_suffix
        features['prefix_suffix'] = 1 if '-' in domain else -1
        
        # 7. having_sub_domain
        dots_count = domain.count('.')
        if dots_count <= 2:
            features['having_sub_domain'] = -1
        elif dots_count == 3:
            features['having_sub_domain'] = 0
        else:
            features['having_sub_domain'] = 1
            
        # 8. sslfinal_state
        if url.lower().startswith('https://'):
            features['sslfinal_state'] = 1
        else:
            features['sslfinal_state'] = -1
            
        # 9. domain_registration_length (default)
        features['domain_registration_length'] = -1
        
        # 10. favicon (default)
        features['favicon'] = -1
        
        # 11. port (default)
        features['port'] = -1
        
        # 12. https_token
        features['https_token'] = 1 if 'https' in domain else -1
        
        # Other offline features default to -1 (benign)
        features['request_url'] = -1
        features['url_of_anchor'] = -1
        features['links_in_tags'] = -1
        features['sfh'] = -1
        features['submitting_to_email'] = -1
        features['abnormal_url'] = -1
        features['redirect'] = 1 if live.get('redirected') else -1
        features['on_mouseover'] = -1
        features['rightclick'] = -1
        features['popupwindow'] = -1
        features['iframe'] = -1
        features['age_of_domain'] = -1
        features['dnsrecord'] = 1 if not live.get('reachable', True) else -1
        features['web_traffic'] = -1
        features['page_rank'] = -1
        features['google_index'] = -1
        features['links_pointing_to_page'] = -1
        features['statistical_report'] = -1
        
        col_order = [
            'having_ip_address', 'url_length', 'shortining_service', 'having_at_symbol',
            'double_slash_redirecting', 'prefix_suffix', 'having_sub_domain', 'sslfinal_state',
            'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url',
            'url_of_anchor', 'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url',
            'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe', 'age_of_domain',
            'dnsrecord', 'web_traffic', 'page_rank', 'google_index', 'links_pointing_to_page',
            'statistical_report'
        ]
        return [features[col] for col in col_order]


def _demo():
    """Self-check: live-check results must map to the correct UCI feature codes, without hitting the network."""
    agent = object.__new__(ExternalAnalysisAgent)  # skip __init__ (no model loading needed for this check)
    dns_idx = ['having_ip_address', 'url_length', 'shortining_service', 'having_at_symbol',
               'double_slash_redirecting', 'prefix_suffix', 'having_sub_domain', 'sslfinal_state',
               'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url',
               'url_of_anchor', 'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url',
               'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe', 'age_of_domain',
               'dnsrecord', 'web_traffic', 'page_rank', 'google_index', 'links_pointing_to_page',
               'statistical_report'].index

    unreachable = ExternalAnalysisAgent.extract_uci_features(agent, "http://example.com", {'reachable': False})
    assert unreachable[dns_idx('dnsrecord')] == 1, "unreachable domain should mark dnsrecord as suspicious"

    reachable = ExternalAnalysisAgent.extract_uci_features(agent, "http://example.com", {'reachable': True})
    assert reachable[dns_idx('dnsrecord')] == -1, "reachable domain should mark dnsrecord as benign"

    redirected = ExternalAnalysisAgent.extract_uci_features(agent, "http://example.com", {'redirected': True})
    assert redirected[dns_idx('redirect')] == 1

    not_redirected = ExternalAnalysisAgent.extract_uci_features(agent, "http://example.com", {})
    assert not_redirected[dns_idx('redirect')] == -1

    print("agent1_external self-check passed")


if __name__ == "__main__":
    _demo()