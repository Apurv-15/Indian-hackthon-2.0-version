import re
from sentence_transformers import SentenceTransformer
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from urllib.parse import urlparse
from difflib import SequenceMatcher
import os
import pickle

class ExternalAnalysisAgent:
    def __init__(self):
        print("Loading External Analysis Agent...")
        self.model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
        
        # Load pickle models for URL analysis
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        try:
            with open(os.path.join(model_dir, 'phishing.pkl'), 'rb') as f:
                self.url_ml_model = pickle.load(f)
            with open(os.path.join(model_dir, 'vectorizerurl.pkl'), 'rb') as f:
                self.url_vectorizer = pickle.load(f)
            self.has_url_ml = True
            print("Successfully loaded URL ML models.")
        except Exception as e:
            print(f"Failed to load URL ML models: {e}")
            self.has_url_ml = False
        
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
        
        self.legitimate_domains = ['google.com', 'microsoft.com', 'amazon.com', 'paypal.com', 'apple.com']
        
        self.pattern_embeddings = self.model.encode(self.phishing_patterns)
        print("External Analysis Agent loaded successfully!")
    
    def analyze_url_risk(self, url):
        """Analyze URL for suspicious patterns"""
        risk_score = 0.0
        reasons = []
        
        for tld in self.suspicious_tlds:
            if url.lower().endswith(tld) or tld in url.lower():
                risk_score += 0.3
                reasons.append(f"Suspicious TLD: {tld}")
                break
        
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            risk_score += 0.4
            reasons.append("IP address used instead of domain name")
        
        if url.count('.') > 3:
            risk_score += 0.2
            reasons.append("Excessive subdomains")
        
        shortening_services = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'tiny.cc']
        for service in shortening_services:
            if service in url.lower():
                risk_score += 0.3
                reasons.append(f"URL shortening service detected: {service}")
                break
        
        suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm']
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                risk_score += 0.1
                reasons.append(f"Suspicious keyword in URL: '{keyword}'")
                break
        
        domain_similarity = self.check_domain_similarity(url)
        if domain_similarity > 0.7:
            risk_score += 0.3
            reasons.append("Domain similar to legitimate brand")
            
        url_ml_prob = 0.0
        if self.has_url_ml:
            try:
                features = self.url_vectorizer.transform([url])
                # phishing.pkl is LogisticRegression
                url_ml_prob = self.url_ml_model.predict_proba(features)[0][1]
                if url_ml_prob > 0.6:
                    risk_score += 0.4
                    reasons.append(f"ML model marked URL as highly suspicious (Score: {url_ml_prob:.1%})")
                elif url_ml_prob > 0.4:
                    risk_score += 0.2
                    reasons.append(f"ML model flagged potential URL risk (Score: {url_ml_prob:.1%})")
            except Exception as e:
                print(f"Error predicting URL with ML model: {e}")
        
        return min(risk_score, 1.0), reasons, url_ml_prob
    
    def check_domain_similarity(self, url):
        """Check if domain is similar to legitimate domains"""
        domain = self.extract_domain(url)
        max_similarity = 0.0
        
        for legit_domain in self.legitimate_domains:
            similarity = SequenceMatcher(None, domain.lower(), legit_domain).ratio()
            max_similarity = max(max_similarity, similarity)
        
        return max_similarity
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        return domain
    
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
        
        results['overall_risk'] = min(
            results['url_risk'] * 0.6 + 
            results['domain_similarity'] * 0.4 +
            len(results['suspicious_patterns']) * 0.1,
            1.0
        )
        
        return results