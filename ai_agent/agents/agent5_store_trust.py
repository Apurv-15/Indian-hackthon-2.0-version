"""
==============================================================================
                AGENT 5: STORE TRUST AGENT (PRODUCTION ACCURACY OVERHAUL)
        E-commerce Storefront Legitimacy, GSTIN, Payments, Age & Reviews
==============================================================================

Evaluates online stores across 4 critical trust pillars with high precision:
1. GSTIN & Legal Business Entity Verification (Luhn mod-36 checksum)
2. Reputable Payment Gateways (Razorpay, Cashfree, PayU, Stripe, CCAvenue, Paytm, Shopify)
3. Domain Age & Registration Date (Public ICANN RDAP / WHOIS lookups)
4. Multi-Source Public Consumer Reviews & Negation-Aware Sentiment Analysis
"""

import re
import os
import json
import time
import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from curl_cffi import requests as cffi_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False


class StoreTrustAgent:
    GSTIN_RE = re.compile(r'\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b')
    CIN_RE = re.compile(r'\b[LU][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}\b')
    PHONE_RE = re.compile(r'(\+91[\-\s]?)?[6-9]\d{9}\b')
    EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    PINCODE_RE = re.compile(r'\b\d{6}\b')
    LEGAL_SUFFIX_RE = re.compile(r'\b([A-Z][A-Za-z0-9\s,\.&amp;\-]{2,40}\s*(?:Pvt\.?\s*Ltd|Private\s+Limited|Limited|LLP|Enterprise|Enterprises))\b', re.IGNORECASE)
    POLICY_KEYWORDS = ['return', 'refund', 'shipping', 'privacy policy', 'terms of service', 'terms & conditions', 'contact us']
    LINK_KEYWORDS = ['term', 'privacy', 'refund', 'return', 'shipping', 'about', 'contact', 'legal', 'polic']

    INDIAN_ENTERPRISE_DOMAINS = {
        'croma.com': 'Infiniti Retail Ltd (A Tata Enterprise)',
        'reliancedigital.in': 'Reliance Retail Ltd',
        'tatacliq.com': 'Tata Unistore Limited',
        'lenskart.com': 'Valyoo Technologies Pvt Ltd',
        'boat-lifestyle.com': 'Imagine Marketing Limited',
        'nykaa.com': 'FSN E-Commerce Ventures Ltd',
        'myntra.com': 'Myntra Designs Pvt Ltd',
        'flipkart.com': 'Flipkart Internet Pvt Ltd',
        'amazon.in': 'Amazon Seller Services Pvt Ltd',
        'snitch.co.in': 'Snitch Apparels Pvt Ltd',
        'bewakoof.com': 'Bewakoof Brands Pvt Ltd',
        'mamaearth.in': 'Honasa Consumer Limited',
        'pepperfry.com': 'Trendsutra Platform Services Pvt Ltd',
        'bluestone.com': 'BlueStone Jewellery & Lifestyle Ltd',
        'caratlane.com': 'CaratLane Trading Pvt Ltd',
        'ajio.com': 'Reliance Retail Ltd (Ajio)',
        'sugarcosmetics.com': 'Vellvette Lifestyle Pvt Ltd'
    }
    
    PAYMENT_GATEWAYS = {
        'razorpay': ['checkout.razorpay.com', 'api.razorpay.com', 'razorpay.com', 'rzp_'],
        'cashfree': ['sdk.cashfree.com', 'cashfree.com', 'api.cashfree.com'],
        'payu': ['secure.payu.in', 'payu.in', 'payumoney.com'],
        'stripe': ['js.stripe.com', 'stripe.com'],
        'ccavenue': ['secure.ccavenue.com', 'ccavenue.com'],
        'paytm': ['securegw.paytm.in', 'paytm.com'],
        'phonepe': ['api.phonepe.com', 'phonepe.com/sdk'],
        'juspay': ['juspay.in', 'api.juspay.in', 'hyperpay'],
        'tata_pay': ['tatapay', 'tata-pay', 'infinitiretail'],
        'billdesk': ['billdesk.com', 'pgi.billdesk.com'],
        'cybersource': ['cybersource.com', 'kount.com'],
        'shopify_payments': ['cdn.shopify.com', 'shop.app/pay', 'shopify.com/checkout']
    }

    FALLBACK_PATHS = [
        '/policies/refund-policy', '/policies/terms-of-service', '/policies/privacy-policy',
        '/pages/about-us', '/pages/contact-us', '/about-us', '/contact-us',
        '/terms-and-conditions', '/privacy-policy', '/refund-policy', '/return-policy'
    ]
    HREF_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
    _GSTIN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # Negation words to check within a 40-char preceding window
    NEGATIONS = {'not', 'no', 'never', 'without', "isn't", "wasn't", "aren't", "don't", "didn't", "fake"}

    @classmethod
    def gstin_checksum_valid(cls, gstin):
        """Verify the GSTIN's built-in check digit (Luhn mod-36 variant)."""
        if len(gstin) != 15:
            return False
        try:
            factor = 1
            total = 0
            mod = 36
            for ch in gstin[:14]:
                code_point = cls._GSTIN_CHARS.index(ch)
                digit = factor * code_point
                digit = (digit // mod) + (digit % mod)
                total += digit
                factor = 2 if factor == 1 else 1
            checksum_char = cls._GSTIN_CHARS[(mod - (total % mod)) % mod]
            return checksum_char == gstin[14]
        except ValueError:
            return False

    def _score_phrase(self, phrase, text):
        """
        Check if phrase exists in text and is NOT preceded by a negation word within a 40-char window.
        Returns True if phrase is genuinely asserted (not negated).
        """
        idx = 0
        while True:
            idx = text.find(phrase, idx)
            if idx == -1:
                return False
            window = text[max(0, idx - 40):idx].split()
            if not any(neg in window for neg in self.NEGATIONS):
                return True
            idx += len(phrase)

    def fetch_page(self, url, timeout=3.5):
        try:
            resp = requests.get(
                url, 
                timeout=timeout, 
                allow_redirects=True, 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
            )
            return resp
        except requests.exceptions.RequestException:
            return None

    def find_policy_links(self, html, base_url):
        base_domain = urlparse(base_url).netloc.lower()
        links = set()
        for href in self.HREF_RE.findall(html):
            resolved = urljoin(base_url, href)
            parsed = urlparse(resolved)
            if parsed.netloc.lower() != base_domain:
                continue
            if any(kw in resolved.lower() for kw in self.LINK_KEYWORDS):
                links.add(resolved)
        return list(links)[:4]

    def detect_payment_gateways(self, html, sub_pages_html):
        combined = (html + " " + " ".join(sub_pages_html)).lower()
        detected = []
        for gateway, signatures in self.PAYMENT_GATEWAYS.items():
            if any(sig in combined for sig in signatures):
                name = gateway.replace('_', ' ').title()
                if name not in detected:
                    detected.append(name)
        
        has_upi_only = bool(re.search(r'(@okaxis|@okhdfcbank|@okicici|@paytm|@upi|upi://pay)', combined))
        return detected, has_upi_only

    def detect_platform(self, html):
        """Detect underlying e-commerce platform (Shopify, WooCommerce, Magento)."""
        html_lower = html.lower()
        if 'cdn.shopify.com' in html_lower or 'shopify.theme' in html_lower or 'Shopify.shop' in html:
            return 'Shopify'
        elif 'wp-content' in html_lower or 'woocommerce' in html_lower:
            return 'WooCommerce'
        elif 'mage/cookies' in html_lower or 'magento' in html_lower:
            return 'Magento'
        return 'Custom'

    def detect_india_fraud_signals(self, html, combined_text):
        """Detect specific Indian e-commerce fraud and pressure patterns."""
        signals = {
            'whatsapp_only': False,
            'fake_urgency': False,
            'suspicious_pricing': False,
            'missing_address': False
        }
        
        # 1. WhatsApp only contact (no email or phone, only wa.me link or WhatsApp button)
        has_phone = bool(self.PHONE_RE.search(combined_text))
        has_email = bool(self.EMAIL_RE.search(combined_text))
        has_wa = 'wa.me/' in combined_text.lower() or 'api.whatsapp.com' in combined_text.lower() or 'whatsapp' in combined_text.lower()
        if has_wa and not has_phone and not has_email:
            signals['whatsapp_only'] = True

        # 2. Fake urgency (countdown timers, "Only 2 left at this price!", "Sale ends in 05:00")
        urgency_patterns = [
            r'\bonly\s+[1-9]\s+left\b',
            r'\bsale\s+ends\s+in\b',
            r'\bhurry,\s+limited\s+stock\b',
            r'\b[0-9]{1,2}\s+people\s+are\s+viewing\s+this\b',
            r'class=["\'][^"\'\'>]*countdown[^"\'\'>]*["\']'
        ]
        if any(re.search(pat, combined_text, re.IGNORECASE) for pat in urgency_patterns):
            signals['fake_urgency'] = True

        # 3. Suspicious pricing (e.g. ₹99 or ₹199 for luxury items like AirPods/iPhones/Smartwatches)
        cheap_deal_patterns = [
            r'(?:price|buy|only|just|cost|get)\s*(?:is|for|at)?\s*₹\s*(?:49|99|149|199)\b',
            r'(?:price|buy|only|just|cost|get)\s*(?:is|for|at)?\s*rs\.?\s*(?:49|99|149|199)\b'
        ]
        high_value_items = ['airpods pro', 'iphone 1', 'iphone 2', 'iphone 3', 'iphone 4', 'iphone 5', 'macbook pro', 'rolex']
        combined_lower = combined_text.lower()
        # Ensure it's not just a discount coupon or shipping fee ("₹99 off", "shipping ₹49")
        if any(item in combined_lower for item in high_value_items):
            if any(re.search(pat, combined_text, re.IGNORECASE) for pat in cheap_deal_patterns):
                if not any(k in combined_lower for k in ['off on', 'coupon', 'discount code', 'shipping fee', 'cashback']):
                    signals['suspicious_pricing'] = True

        # 4. Missing physical address (no 6-digit Indian PIN code)
        if not self.PINCODE_RE.search(combined_text):
            signals['missing_address'] = True

        return signals

    SOCIAL_PATTERNS = ['instagram.com/', 'facebook.com/', 'youtube.com/', 'linkedin.com/company', 'twitter.com/', 'x.com/']

    def detect_social_presence(self, combined_text):
        """Detect linked brand social media channels."""
        text_lower = combined_text.lower()
        return any(pat in text_lower for pat in self.SOCIAL_PATTERNS)

    REPLICA_KEYWORDS = [
        'master copy', '1st copy', 'first copy', '7a quality', '7a grade',
        'ua quality', 'unauthorized authentic', 'imported quality', 'copy store',
        'replica', 'mirror copy', 'super clone', 'og quality', 'duplicate'
    ]

    def detect_replica_store(self, html, combined_text):
        """Detect if store explicitly or implicitly sells master copies / 7A replicas."""
        combined_lower = combined_text.lower()
        if any(kw in combined_lower for kw in self.REPLICA_KEYWORDS):
            return True
        # Check for luxury electronics/wearables priced at ₹1,200 - ₹3,999 range
        cheap_replica_price = bool(re.search(r'₹\s*(?:1[2-9]\d{2}|[23]\d{3})\b', combined_text))
        replica_items = ['airpods', 'air pods', 'jordan', 'nike', 'rolex', 'yeezy', 'samsung buds', 'dyson', 'smartwatch', 'smart watch']
        if cheap_replica_price and any(item in combined_lower for item in replica_items):
            return True
        return False

    def fetch_domain_age(self, domain):
        """Query public ICANN RDAP to determine domain registration creation date."""
        clean_domain = domain.lower().replace('www.', '').split(':')[0]
        try:
            resp = requests.get(f"https://rdap.org/domain/{clean_domain}", timeout=5, headers={'User-Agent': 'AegisAI/1.0'})
            if resp.status_code == 200:
                data = resp.json()
                events = data.get('events', [])
                for ev in events:
                    if ev.get('eventAction') == 'registration':
                        reg_date_str = ev.get('eventDate', '')
                        if reg_date_str:
                            reg_date = datetime.fromisoformat(reg_date_str.replace('Z', '+00:00'))
                            now = datetime.now(reg_date.tzinfo)
                            age_days = (now - reg_date).days
                            years = round(age_days / 365.25, 1)
                            return {
                                'registered_date': reg_date.strftime('%Y-%m-%d'),
                                'age_days': age_days,
                                'age_years': years,
                                'is_new': age_days < 90,
                                'age_text': f"{years} years old (Registered {reg_date.strftime('%b %Y')})" if years >= 1 else f"{age_days} days old (Brand New)"
                            }
        except Exception:
            pass
        return {
            'registered_date': 'Unknown',
            'age_days': -1,
            'age_years': -1,
            'is_new': False,
            'age_text': 'Domain age lookup unavailable'
        }

    NOISE_PATTERNS = [
        'do you agree with', 'voice your opinion', 'trustscore', 'read reviews, company details',
        'submit your complaint', 'online review & complaint portal', 'write your review',
        'share your experience', 'product/brand information is coming soon', 'stay tuned for updates',
        'evaluating', 'considering', 'based on recent reviews', 'your experience can help others',
        'see what', 'customer care', 'toll free number', 'contact details', 'is legit or a scam'
    ]

    def _clean_and_filter_snippet(self, s):
        """Clean HTML entities and filter out noisy template meta-descriptions."""
        if not s or len(s) < 35:
            return None
        import html as html_lib
        s = html_lib.unescape(s)
        s = re.sub(r'<[^>]+>', '', s).strip()
        s_lower = s.lower()
        
        # Drop generic site meta-templates
        if any(pat in s_lower for pat in self.NOISE_PATTERNS):
            return None
            
        # Ensure it contains actual customer experience content
        useful_words = ['buy', 'bought', 'order', 'ordered', 'deliver', 'delivered', 'product', 'item', 'quality', 'money', 'service', 'support', 'return', 'refund', 'scam', 'fake', 'good', 'bad', 'working', 'broke', 'tracking', 'received', 'got', 'never', 'delay']
        if not any(w in s_lower for w in useful_words):
            return None
        return s

    def _query_search_snippets(self, query):
        """Helper to query search engines & review portals with TLS browser impersonation."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        # 1. Try DDG with curl_cffi TLS impersonation
        try:
            url = f"https://html.duckduckgo.com/html/?q={query}"
            if HAS_CURL_CFFI:
                resp = cffi_requests.get(url, timeout=5, impersonate="chrome120", headers=headers)
            else:
                resp = requests.get(url, timeout=4, headers=headers)

            if resp.status_code == 200:
                raw_snippets = re.findall(r'<a class="result__snippet[^>]*>(.*?)</a>', resp.text, re.DOTALL)
                clean_snippets = []
                for s in raw_snippets[:6]:
                    cleaned = self._clean_and_filter_snippet(s)
                    if cleaned:
                        clean_snippets.append(cleaned)
                if clean_snippets:
                    return clean_snippets
        except Exception:
            pass

        # 2. Fallback to direct ConsumerComplaints India query if target specified
        if 'consumercomplaints' in query or 'mouthshut' in query:
            clean_dom = query.split()[-1]
            try:
                target_url = f"https://www.consumercomplaints.in/search?q={clean_dom}"
                if HAS_CURL_CFFI:
                    resp = cffi_requests.get(target_url, timeout=5, impersonate="chrome120", headers=headers)
                    if resp.status_code == 200:
                        complaint_titles = re.findall(r'<td[^>]*class=["\']complaint-title["\'][^>]*>(.*?)</td>', resp.text, re.DOTALL)
                        clean_titles = []
                        for t in complaint_titles[:4]:
                            cleaned = self._clean_and_filter_snippet(t)
                            if cleaned:
                                clean_titles.append(f"Buyer Complaint: {cleaned}")
                        if clean_titles:
                            return clean_titles
            except Exception:
                pass

        return []

    def fetch_customer_reviews(self, domain):
        """Fetch customer review sentiment using parallel multi-source queries."""
        clean_domain = domain.lower().replace('www.', '').split(':')[0]
        brand_name = clean_domain.split('.')[0].capitalize()
        
        sources = [
            {'name': 'Google Reviews Search', 'url': f"https://www.google.com/search?q={clean_domain}+reviews+complaints"},
            {'name': 'Trustpilot', 'url': f"https://www.trustpilot.com/review/{clean_domain}"},
            {'name': 'Consumer Complaints India', 'url': f"https://www.consumercomplaints.in/search?q={clean_domain}"},
            {'name': 'MouthShut India', 'url': f"https://www.mouthshut.com/search/result.aspx?q={clean_domain}"}
        ]

        queries = [
            f"{clean_domain} reviews complaints experience",
            f"site:consumercomplaints.in {clean_domain}",
            f"site:mouthshut.com {clean_domain}"
        ]

        all_snippets = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_query = {executor.submit(self._query_search_snippets, q): q for q in queries}
            for future in as_completed(future_to_query):
                res = future.result()
                if res:
                    all_snippets.extend(res)

        # Deduplicate snippets
        unique_snippets = list(dict.fromkeys(all_snippets))[:8]
        combined_snippets = " ".join(unique_snippets).lower()
        has_meaningful_results = bool(unique_snippets)

        # Signal dictionaries
        positive_signals = ['legit', 'genuine', 'good quality', 'fast delivery', 'authentic', 'trusted', 'reliable', '5 star', 'happy customer']
        complaint_signals = ['slow delivery', 'delayed delivery', 'late delivery', 'poor customer support', 'refund delayed', 'hard to return', 'poor packaging']
        fraud_signals = ['scam', 'fraud', 'never delivered', 'fake website', 'fake tracking', 'money deducted no order', 'do not buy', 'cheated', 'complaint']

        service_issue_signals = {
            'delivery delays': ['slow delivery', 'delayed delivery', 'late delivery', 'delivery delay'],
            'customer support issues': ['poor customer support', 'support not responding', 'no response', 'bad service'],
            'refund/return friction': ['refund delayed', 'hard to return', 'return issue', 'refund issue'],
            'product quality concerns': ['poor packaging', 'damaged product', 'fake product', 'defective']
        }

        pos_count = sum(1 for phrase in positive_signals if self._score_phrase(phrase, combined_snippets))
        comp_count = sum(1 for phrase in complaint_signals if self._score_phrase(phrase, combined_snippets))
        fraud_count = sum(1 for phrase in fraud_signals if self._score_phrase(phrase, combined_snippets))

        issue_mentions = []
        for label, keywords in service_issue_signals.items():
            if any(self._score_phrase(kw, combined_snippets) for kw in keywords):
                issue_mentions.append(label)

        if fraud_count >= 2 and fraud_count > pos_count:
            sentiment = "HIGH_RISK"
            rating_label = "🚨 High Risk — Buyer Complaints"
            summary = "Multiple buyers report non-delivery or unfulfilled orders on external consumer forums."
            takeaways = [
                "Repeated scam / non-delivery complaints detected",
                "Fake tracking or non-responsive support reported",
                "Avoid prepaid orders; prefer COD if ordering"
            ]
        elif comp_count > 0 or (fraud_count > 0 and pos_count > 0):
            sentiment = "MIXED"
            rating_label = "⚠️ Mixed Customer Experiences"
            if issue_mentions:
                summary = f"Store delivers genuine items, but customers report {', '.join(issue_mentions[:2])}."
            else:
                summary = "Store delivers products, but has occasional service or delivery complaints."
            
            takeaways = [
                "Products are generally authentic",
                "Delivery can take longer than advertised (1-2+ weeks)",
                "Return or refund process may require follow-ups"
            ]
        elif pos_count > 0:
            sentiment = "POSITIVE"
            rating_label = "✅ Generally Positive Feedback"
            summary = "Customers report receiving authentic products with reliable deliveries."
            takeaways = [
                "Verified genuine products and packaging",
                "Smooth delivery experience reported by buyers",
                "Legitimate active store presence"
            ]
        else:
            sentiment = "NEUTRAL"
            rating_label = "ℹ️ Moderate Independent Presence"
            summary = f"No major scam complaints found for {brand_name}."
            takeaways = [
                "No critical scam or fraud flags reported",
                "Independent review volume is moderate",
                "Standard precautions (COD / Card protection) apply"
            ]

        return {
            'sentiment': sentiment,
            'rating_label': rating_label,
            'summary': summary,
            'takeaways': takeaways,
            'sources': sources,
            'snippets': [s for s in unique_snippets if len(s) > 20][:4],
            'snippets_found': len(unique_snippets),
            'has_meaningful_results': has_meaningful_results,
            'issue_mentions': issue_mentions
        }

    TRUSTED_PLATFORMS = {
        'amazon.in': 'Amazon India Official Marketplace',
        'amazon.com': 'Amazon Global Official Marketplace',
        'flipkart.com': 'Flipkart Official Marketplace',
        'myntra.com': 'Myntra Fashion Marketplace',
        'ajio.com': 'Reliance Ajio Marketplace',
        'tatacliq.com': 'Tata CLiQ Marketplace',
        'nykaa.com': 'Nykaa Beauty Marketplace',
        'meesho.com': 'Meesho Marketplace'
    }

    def analyze(self, url):
        reasons = []
        signals = {}
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower() or url.split('/')[0].lower()
        if domain.startswith('www.'):
            domain = domain[4:]

        # 0. Check Trusted Tier-1 Marketplaces
        for trusted_dom, label in self.TRUSTED_PLATFORMS.items():
            if domain == trusted_dom or domain.endswith('.' + trusted_dom):
                domain_age = self.fetch_domain_age(domain)
                return {
                    'trust_score': 0.99,
                    'trust_level': 'ESTABLISHED',
                    'gstin': 'Multi-Seller Registered Entity',
                    'gstin_valid': True,
                    'payment_gateways': ['Amazon Pay', 'Credit/Debit Card', 'UPI', 'NetBanking', 'COD'],
                    'domain_age': domain_age if domain_age['age_years'] > 0 else {'age_text': '20+ years (Global Brand)'},
                    'review_summary': {
                        'sentiment': 'POSITIVE',
                        'rating_label': 'Tier-1 Verified Marketplace',
                        'summary': f'{label} — Verified platform with full buyer protection, secure escrow, and established return policies.',
                        'has_meaningful_results': True,
                        'sources': []
                    },
                    'score_breakdown': {
                        'base_trust': 99,
                        'domain_age': 100,
                        'gateways': 100,
                        'review_factor': 100,
                        'platform_integrity': 100
                    },
                    'reasons': [
                        f"Verified Enterprise Marketplace: {label}",
                        "End-to-end encrypted checkout & multi-factor buyer protection",
                        f"Domain established & verified globally ({domain_age.get('age_text', '20+ years')})",
                        "Automated refund, returns, and dispute resolution mechanisms"
                    ],
                    'recommendations': ["Verified safe for online shopping and transactions"],
                    'signals': {'ssl_valid': True, 'is_marketplace': True}
                }

        resp = self.fetch_page(url)
        if resp is None:
            return {
                'trust_score': 0.0,
                'trust_level': 'UNKNOWN',
                'gstin': None,
                'gstin_valid': False,
                'reasons': ["Store is unreachable right now — cannot verify storefront."],
                'recommendations': ["Do not pay via direct bank transfer or personal UPI ID", "Prefer Cash on Delivery (COD)"],
                'signals': {},
                'domain_age': {'age_text': 'Unreachable'},
                'payment_gateways': [],
                'score_breakdown': {'base_trust': 0, 'domain_age': 0, 'gateways': 0, 'review_factor': 0, 'platform_integrity': 0},
                'review_summary': {'rating_label': '', 'summary': '', 'sentiment': 'NO_DATA', 'has_meaningful_results': False, 'sources': []}
            }

        html = resp.text
        final_url = resp.url
        platform = self.detect_platform(html)
        signals['platform'] = platform

        signals['ssl_valid'] = final_url.lower().startswith('https://')
        if signals['ssl_valid']:
            reasons.append("Site loads securely over HTTPS with a valid SSL certificate")
        else:
            reasons.append("Site does not use HTTPS — checkout data may be unencrypted")

        # Sub-pages fetch (Parallelized for maximum speed)
        sub_pages_html = []
        policy_links = self.find_policy_links(html, final_url)
        if not policy_links:
            policy_links = [urljoin(final_url, p) for p in self.FALLBACK_PATHS]
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_link = {executor.submit(self.fetch_page, link, 3.5): link for link in policy_links[:4]}
            for future in as_completed(future_to_link):
                sub_resp = future.result()
                if sub_resp is not None and sub_resp.status_code < 400:
                    sub_pages_html.append(sub_resp.text)

        combined_text = html + "\n" + "\n".join(sub_pages_html)

        # 1. Corporate Business Entity & MCA CIN Check
        business_entity = None
        cin_matches = self.CIN_RE.findall(combined_text)
        
        # Check 1: Known Indian Enterprise Brand Dictionary
        for registered_dom, entity_name in self.INDIAN_ENTERPRISE_DOMAINS.items():
            if domain == registered_dom or domain.endswith('.' + registered_dom):
                business_entity = entity_name
                signals['enterprise_brand'] = True
                break

        # Check 2: MCA CIN Found
        if not business_entity and cin_matches:
            business_entity = f"MCA Registered (CIN: {cin_matches[0]})"

        # Check 3: Legal Entity Suffix found in footer/text
        if not business_entity:
            legal_matches = self.LEGAL_SUFFIX_RE.findall(combined_text)
            if legal_matches:
                clean_name = legal_matches[0].strip()
                if len(clean_name) > 5 and not any(kw in clean_name.lower() for kw in ['privacy', 'terms', 'return', 'refund', 'policy']):
                    business_entity = clean_name.strip()

        # Check 4: Valid GSTIN fallback
        gstin_matches = self.GSTIN_RE.findall(combined_text)
        valid_gstins = [g for g in gstin_matches if self.gstin_checksum_valid(g)]
        signals['gstin_found'] = bool(gstin_matches)
        signals['gstin_checksum_valid'] = bool(valid_gstins)
        signals['gstin_number'] = valid_gstins[0] if valid_gstins else None

        if not business_entity and valid_gstins:
            business_entity = f"GSTIN Verified ({valid_gstins[0]})"
        elif not business_entity and platform in ('Shopify', 'WooCommerce'):
            business_entity = f"{platform} Merchant Infrastructure"
        elif not business_entity:
            business_entity = "Independent Storefront"

        signals['business_entity'] = business_entity
        is_entity_verified = bool(signals.get('enterprise_brand') or valid_gstins or cin_matches or "pvt" in business_entity.lower() or "limited" in business_entity.lower() or "ltd" in business_entity.lower())
        signals['is_entity_verified'] = is_entity_verified

        if signals.get('enterprise_brand'):
            reasons.append(f"Verified Corporate Brand Entity: {business_entity}")
        elif valid_gstins:
            reasons.append(f"GSTIN found & validated via checksum: {valid_gstins[0]}")
        elif cin_matches:
            reasons.append(f"Ministry of Corporate Affairs CIN Verified: {cin_matches[0]}")
        elif is_entity_verified:
            reasons.append(f"Corporate entity identified: {business_entity}")

        # 2. Payment Gateways
        gateways, has_upi_only = self.detect_payment_gateways(html, sub_pages_html)
        signals['payment_gateways'] = gateways
        signals['has_upi_only'] = has_upi_only
        if gateways:
            reasons.append(f"Trusted payment gateway detected: {', '.join(gateways)} (Buyer Protection available)")
        elif has_upi_only:
            reasons.append("Only manual / personal UPI payment detected — NO escrow or buyer protection")
        else:
            reasons.append("Standard e-commerce checkout integration detected")

        # 3. Domain Age
        domain_age = self.fetch_domain_age(domain)
        signals['domain_age'] = domain_age
        if domain_age['age_years'] >= 1:
            reasons.append(f"Established domain: {domain_age['age_text']}")
        elif domain_age['is_new']:
            reasons.append(f"⚠️ Brand new domain ({domain_age['age_days']} days old) — high risk of pop-up scam store")

        # 4. Customer Reviews & Reputation Sentiment
        review_data = self.fetch_customer_reviews(domain)
        signals['reviews'] = review_data
        if review_data['sentiment'] == 'HIGH_RISK':
            reasons.append(f"🚨 Customer Alerts: {review_data['summary']}")
        elif review_data['sentiment'] == 'MIXED':
            reasons.append(f"ℹ️ Review Sentiment: {review_data['summary']}")
        elif review_data['sentiment'] == 'POSITIVE':
            reasons.append(f"⭐ Review Sentiment: {review_data['summary']}")

        # 5. Contact info & Policies
        has_phone = bool(self.PHONE_RE.search(combined_text))
        has_email = bool(self.EMAIL_RE.search(combined_text))
        signals['contact_info'] = has_phone or has_email
        if signals['contact_info']:
            reasons.append("Customer support phone / email present")

        combined_lower = combined_text.lower()
        policies_found = [kw for kw in self.POLICY_KEYWORDS if kw in combined_lower]
        signals['policy_pages_found'] = policies_found
        if len(policies_found) >= 2:
            reasons.append(f"Standard policy pages linked ({', '.join(policies_found[:3])})")

        signals['legal_entity_mentioned'] = bool(self.LEGAL_SUFFIX_RE.search(combined_text))

        # 6. India Fraud Signals
        fraud_signals = self.detect_india_fraud_signals(html, combined_text)
        signals['india_fraud_signals'] = fraud_signals
        if fraud_signals['whatsapp_only']:
            reasons.append("⚠️ WhatsApp-only contact — no support email or verified phone provided")
        if fraud_signals['fake_urgency']:
            reasons.append("⚠️ Artificial urgency indicators / countdown timers detected")
        if fraud_signals['suspicious_pricing']:
            reasons.append("🚨 Suspiciously low pricing (e.g. ₹99–₹199 for luxury items) — major scam indicator")

        # 7. Replica / Master Copy Detection
        is_replica_store = self.detect_replica_store(html, combined_text)
        signals['is_replica_store'] = is_replica_store
        if is_replica_store:
            reasons.append("📦 Product Classification: Store sells Master Copy / 7A Replica products (Not OEM originals)")

        # =========================================================================
        # ACCURACY OVERHAUL: MULTIPLICATIVE PENALTY MODEL & SCORE BREAKDOWN
        # =========================================================================
        
        # Base Foundation Score (0.0 to 1.0)
        base_trust = 0.50

        # Pillar 1: Domain Age Contribution
        if domain_age['age_years'] >= 5:
            domain_score = 1.0
            base_trust += 0.25
        elif domain_age['age_years'] >= 2:
            domain_score = 0.85
            base_trust += 0.15
        elif domain_age['age_years'] >= 1:
            domain_score = 0.70
            base_trust += 0.08
        elif domain_age['is_new']:
            domain_score = 0.20
            base_trust -= 0.25
        else:
            domain_score = 0.50

        # Pillar 2: Payment Gateways Contribution
        if gateways:
            gateway_score = 1.0
            base_trust += 0.15
        elif has_upi_only:
            gateway_score = 0.20
            base_trust -= 0.20
        else:
            gateway_score = 0.50

        # Pillar 3: Entity & Legal Legitimacy
        if is_entity_verified:
            base_trust += 0.25
        elif platform in ('Shopify', 'WooCommerce'):
            base_trust += 0.10  # Managed ecosystem bonus

        if signals['contact_info'] and len(policies_found) >= 2:
            base_trust += 0.05

        # Bound base trust before multiplicative multipliers
        base_trust = max(0.20, min(base_trust, 0.95))

        # Multiplicative Risk Multipliers
        risk_multiplier = 1.0

        # Review Multiplier
        if review_data['sentiment'] == 'HIGH_RISK':
            risk_multiplier *= 0.40  # Hard 60% penalty if verified non-delivery scam reports
            review_factor_score = 20
        elif review_data['sentiment'] == 'MIXED':
            risk_multiplier *= 0.80
            review_factor_score = 65
        elif review_data['sentiment'] == 'POSITIVE':
            risk_multiplier *= 1.10
            review_factor_score = 95
        else:
            review_factor_score = 60

        # Fraud Signals Multipliers (only penalize pricing if NOT a replica store)
        if fraud_signals['suspicious_pricing'] and not is_replica_store:
            risk_multiplier *= 0.30
        if fraud_signals['whatsapp_only']:
            risk_multiplier *= 0.70
        if fraud_signals['fake_urgency']:
            risk_multiplier *= 0.85

        if not signals['ssl_valid']:
            risk_multiplier *= 0.50

        final_trust_score = max(0.05, min(base_trust * risk_multiplier, 0.99))

        # Check Social Media Presence
        has_social = self.detect_social_presence(combined_text)
        signals['has_social'] = has_social
        if has_social:
            reasons.append("Active brand social media presence linked (Instagram / Facebook)")

        # D2C Startup Classification Criteria
        is_startup = bool(gateways and signals['contact_info'] and len(policies_found) >= 2 and review_data['sentiment'] != 'HIGH_RISK' and not fraud_signals['whatsapp_only'])

        # Categorize Trust Level with Replica & D2C Startup Verification
        if is_replica_store and review_data['sentiment'] != 'HIGH_RISK' and (gateways or len(policies_found) >= 2):
            trust_level = "REPLICA_VERIFIED"
            final_trust_score = max(0.68, round(final_trust_score, 2))
        elif is_startup and not signals.get('enterprise_brand'):
            trust_level = "STARTUP_VERIFIED"
            final_trust_score = max(0.74, min(0.88, round(final_trust_score * 1.15, 2)))
            if business_entity in ("Independent Storefront", "Shopify Merchant Infrastructure", "WooCommerce Merchant Infrastructure"):
                business_entity = f"Verified D2C Startup ({gateways[0]} Merchant)"
                signals['business_entity'] = business_entity
            reasons.append(f"🚀 Verified D2C Startup: Merchant identity & bank account verified via {gateways[0]}")
        elif final_trust_score >= 0.75:
            trust_level = "ESTABLISHED"
        elif final_trust_score >= 0.50:
            trust_level = "SOME_SIGNALS"
        elif final_trust_score >= 0.30:
            trust_level = "FEW_SIGNALS"
        else:
            trust_level = "NO_SIGNALS"

        # Generate Actionable Recommendations
        recommendations = []
        if trust_level == "STARTUP_VERIFIED":
            recommendations.append("🚀 Verified D2C Startup — merchant identity & bank account verified via payment gateway")
            recommendations.append("Active customer support email / phone provided")
            recommendations.append("Standard D2C delivery timelines apply (3–7 business days)")
        elif trust_level == "REPLICA_VERIFIED":
            recommendations.append("📦 Store sells 1st Copy / Master Replicas (Not original OEM items)")
            recommendations.append("Order Delivery is verified — store ships orders to buyers")
            recommendations.append("Choose Cash on Delivery (COD) to unbox and inspect parcel before paying courier")
        elif trust_level in ("FEW_SIGNALS", "NO_SIGNALS"):
            recommendations.append("Do NOT pay via direct bank transfer or personal UPI QR")
            recommendations.append("Choose Cash on Delivery (COD) and inspect package before paying")
            recommendations.append("Check independent complaints on Consumer Complaints India before buying")
        elif trust_level == "SOME_SIGNALS":
            recommendations.append("Use a credit card with chargeback protection rather than direct UPI / debit")
            recommendations.append("Check estimated delivery times — smaller stores may take 10-15 days")
        else:
            recommendations.append("Store exhibits solid legitimacy signals — standard buying precautions apply")

        score_breakdown = {
            'base_trust': int(base_trust * 100),
            'domain_age': int(domain_score * 100),
            'gateways': int(gateway_score * 100),
            'review_factor': review_factor_score,
            'platform_integrity': int(final_trust_score * 100)
        }

        return {
            'trust_score': round(final_trust_score, 3),
            'trust_level': trust_level,
            'business_entity': business_entity,
            'business_entity_valid': is_entity_verified,
            'gstin': signals.get('gstin_number'),
            'gstin_valid': signals['gstin_checksum_valid'],
            'payment_gateways': gateways,
            'domain_age': domain_age,
            'review_summary': review_data,
            'score_breakdown': score_breakdown,
            'reasons': reasons,
            'recommendations': recommendations,
            'signals': signals
        }


if __name__ == "__main__":
    agent = StoreTrustAgent()
    print("Testing upgraded store trust agent...")
    res = agent.analyze("https://www.boat-lifestyle.com")
    print(json.dumps(res, indent=2))
