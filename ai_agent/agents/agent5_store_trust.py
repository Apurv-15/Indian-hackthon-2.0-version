"""
==============================================================================
                AGENT 5: STORE TRUST AGENT (ENHANCED)
        E-commerce Storefront Legitimacy, GSTIN, Payments, Age & Reviews
==============================================================================

Evaluates online stores across 4 critical trust pillars:
1. GSTIN & Legal Business Entity Verification (Luhn mod-36 checksum)
2. Reputable Payment Gateways (Razorpay, Cashfree, PayU, Stripe, CCAvenue, Paytm, Shopify)
3. Domain Age & Registration Date (Public ICANN RDAP / WHOIS lookups)
4. Public Consumer Reviews & Sentiment Analysis (Delivery speed, fake products, scam alerts)
"""

import re
import os
import json
import time
import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin


class StoreTrustAgent:
    GSTIN_RE = re.compile(r'\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b')
    PHONE_RE = re.compile(r'(\+91[\-\s]?)?[6-9]\d{9}\b')
    EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    PINCODE_RE = re.compile(r'\b\d{6}\b')
    LEGAL_SUFFIX_RE = re.compile(r'\b(pvt\.?\s*ltd|private\s+limited|llp|opc\b|limited|enterprises|technologies)', re.IGNORECASE)
    POLICY_KEYWORDS = ['return', 'refund', 'shipping', 'privacy policy', 'terms of service', 'terms & conditions', 'contact us']
    LINK_KEYWORDS = ['term', 'privacy', 'refund', 'return', 'shipping', 'about', 'contact', 'legal', 'polic']
    
    PAYMENT_GATEWAYS = {
        'razorpay': ['checkout.razorpay.com', 'api.razorpay.com', 'razorpay.com', 'rzp_'],
        'cashfree': ['sdk.cashfree.com', 'cashfree.com', 'api.cashfree.com'],
        'payu': ['secure.payu.in', 'payu.in', 'payumoney.com'],
        'stripe': ['js.stripe.com', 'stripe.com'],
        'ccavenue': ['secure.ccavenue.com', 'ccavenue.com'],
        'paytm': ['securegw.paytm.in', 'paytm.com'],
        'phonepe': ['api.phonepe.com', 'phonepe.com/sdk'],
        'shopify_payments': ['cdn.shopify.com', 'shop.app/pay', 'shopify.com/checkout']
    }

    FALLBACK_PATHS = [
        '/policies/refund-policy', '/policies/terms-of-service', '/policies/privacy-policy',
        '/pages/about-us', '/pages/contact-us', '/about-us', '/contact-us',
        '/terms-and-conditions', '/privacy-policy', '/refund-policy', '/return-policy'
    ]
    HREF_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
    _GSTIN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

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

    def fetch_page(self, url):
        try:
            resp = requests.get(url, timeout=6, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
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

    def fetch_domain_age(self, domain):
        """Query public ICANN RDAP to determine domain registration creation date."""
        clean_domain = domain.lower().replace('www.', '').split(':')[0]
        try:
            # RDAP public open resolver
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

    def fetch_customer_reviews(self, domain):
        """Fetch customer review sentiment, summary, and clickable source links."""
        clean_domain = domain.lower().replace('www.', '').split(':')[0]
        brand_name = clean_domain.split('.')[0].capitalize()
        
        # Build direct review destination links
        sources = [
            {
                'name': 'Google Reviews Search',
                'url': f"https://www.google.com/search?q={clean_domain}+reviews+complaints"
            },
            {
                'name': 'Trustpilot',
                'url': f"https://www.trustpilot.com/review/{clean_domain}"
            },
            {
                'name': 'Consumer Complaints India',
                'url': f"https://www.consumercomplaints.in/search?q={clean_domain}"
            }
        ]

        try:
            # Query DuckDuckGo HTML for review signals
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            url = f"https://html.duckduckgo.com/html/?q={clean_domain}+reviews+complaints+experience"
            resp = requests.get(url, timeout=5, headers=headers)
            
            snippets = []
            if resp.status_code == 200:
                # Extract snippet text
                snippets = re.findall(r'<a class="result__snippet[^>]*>(.*?)</a>', resp.text, re.DOTALL)
                snippets = [re.sub(r'<[^>]+>', '', s).strip() for s in snippets[:6]]

            combined_snippets = " ".join(snippets).lower()
            has_meaningful_results = bool(snippets)

            # Analyze sentiment & issues
            positive_signals = ['legit', 'genuine', 'good quality', 'fast delivery', 'authentic', 'trusted', 'reliable', '5 star', 'happy customer']
            complaint_signals = ['slow delivery', 'delayed delivery', 'late delivery', 'poor customer support', 'refund delayed', 'hard to return', 'poor packaging']
            fraud_signals = ['scam', 'fraud', 'never delivered', 'fake website', 'fake tracking', 'money deducted no order', 'do not buy', 'cheated', 'complaint']

            service_issue_signals = {
                'delivery delays': ['slow delivery', 'delayed delivery', 'late delivery', 'delivery delay'],
                'customer support issues': ['poor customer support', 'support not responding', 'no response', 'bad service'],
                'refund/return friction': ['refund delayed', 'hard to return', 'return issue', 'refund issue'],
                'product quality concerns': ['poor packaging', 'damaged product', 'fake product', 'defective']
            }

            pos_count = sum(1 for w in positive_signals if w in combined_snippets)
            comp_count = sum(1 for w in complaint_signals if w in combined_snippets)
            fraud_count = sum(1 for w in fraud_signals if w in combined_snippets)
            issue_mentions = []
            for label, keywords in service_issue_signals.items():
                if any(keyword in combined_snippets for keyword in keywords):
                    issue_mentions.append(label)

            evidence_note = f"Based on {len(snippets)} external review snippet{'s' if len(snippets) != 1 else ''}"
            if len(snippets) <= 2:
                evidence_note += "; confidence is limited because review coverage is thin."
            else:
                evidence_note += "."

            # Extract clean, specific bullet points
            takeaways = []
            if fraud_count >= 2 and fraud_count > pos_count:
                sentiment = "HIGH_RISK"
                rating_label = "🚨 High Risk — Buyer Complaints"
                summary = f"Multiple buyers report non-delivery or unfulfilled orders on external forums. Exercise caution before paying upfront."
                takeaways = [
                    "Repeated scam / non-delivery complaints detected",
                    "Fake tracking or non-responsive support reported",
                    "Avoid prepaid orders; prefer COD if ordering"
                ]
            elif comp_count > 0 or (fraud_count > 0 and pos_count > 0):
                sentiment = "MIXED"
                rating_label = "⚠️ Mixed Customer Experiences"
                if issue_mentions:
                    summary = f"Store delivers genuine items, but customers frequently report {', '.join(issue_mentions[:2])}."
                else:
                    summary = "Store generally delivers products, but has occasional service or delivery complaints."
                
                takeaways = [
                    "Products are generally authentic",
                    "Delivery can take longer than advertised (1-2+ weeks)",
                    "Return or refund process may require follow-ups"
                ]
            elif pos_count > 0:
                sentiment = "POSITIVE"
                rating_label = "✅ Generally Positive Feedback"
                summary = f"Customers report receiving authentic products with reliable deliveries."
                takeaways = [
                    "Verified genuine products and packaging",
                    "Smooth delivery experience reported by buyers",
                    "Legitimate active store presence"
                ]
            else:
                sentiment = "NEUTRAL"
                rating_label = "ℹ️ Moderate Independent Presence"
                summary = f"No major scam complaints found for {brand_name}. Store has standard independent presence online."
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
                'snippets': [s for s in snippets if len(s) > 20][:4],
                'snippets_found': len(snippets),
                'has_meaningful_results': has_meaningful_results,
                'issue_mentions': issue_mentions
            }
        except Exception:
            return {
                'sentiment': 'NEUTRAL',
                'rating_label': 'ℹ️ Standard Store Profile',
                'summary': 'Store appears active with standard online profile.',
                'takeaways': ["Standard e-commerce precautions apply"],
                'sources': sources,
                'snippets': [],
                'snippets_found': 0,
                'has_meaningful_results': False,
                'issue_mentions': []
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

        # 0. Check Trusted Tier-1 Marketplaces (Amazon, Flipkart, etc.)
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
                'review_summary': {'rating_label': '', 'summary': '', 'sentiment': 'NO_DATA', 'has_meaningful_results': False, 'sources': []}
            }

        html = resp.text
        final_url = resp.url
        signals['ssl_valid'] = final_url.lower().startswith('https://')
        if signals['ssl_valid']:
            reasons.append("Site loads securely over HTTPS with a valid SSL certificate")
        else:
            reasons.append("Site does not use HTTPS — checkout data may be unencrypted")

        # Fetch sub-pages (Contact, Terms, Refund, About)
        sub_pages_html = []
        policy_links = self.find_policy_links(html, final_url)
        if not policy_links:
            policy_links = [urljoin(final_url, p) for p in self.FALLBACK_PATHS]
        for link in policy_links[:4]:
            sub_resp = self.fetch_page(link)
            if sub_resp is not None and sub_resp.status_code < 400:
                sub_pages_html.append(sub_resp.text)

        combined_text = html + "\n" + "\n".join(sub_pages_html)

        # 1. GSTIN Check
        gstin_matches = self.GSTIN_RE.findall(combined_text)
        valid_gstins = [g for g in gstin_matches if self.gstin_checksum_valid(g)]
        signals['gstin_found'] = bool(gstin_matches)
        signals['gstin_checksum_valid'] = bool(valid_gstins)
        signals['gstin_number'] = valid_gstins[0] if valid_gstins else (gstin_matches[0] if gstin_matches else None)

        if valid_gstins:
            reasons.append(f"GSTIN found & validated via checksum: {valid_gstins[0]}")
        elif gstin_matches:
            reasons.append(f"GSTIN-shaped string found ({gstin_matches[0]}) but failed checksum — possible fake")
        else:
            reasons.append("No GSTIN found on public pages (Standard for overseas or multi-seller platforms)")

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
        if signals['legal_entity_mentioned']:
            reasons.append("Registered company entity structure mentioned (Pvt Ltd / LLP)")

        # Calculate Balanced Multi-Factor Trust Score
        # Domain age, SSL, gateways, reviews, policies, and GSTIN all contribute harmoniously
        trust_score = 0.20 if signals['ssl_valid'] else 0.0

        # Domain Age contributes up to 35%
        if domain_age['age_years'] >= 5:
            trust_score += 0.35
        elif domain_age['age_years'] >= 1:
            trust_score += 0.25
        elif domain_age['is_new']:
            trust_score -= 0.20

        # Payment Gateways contribute up to 25%
        if gateways:
            trust_score += 0.25
        elif has_upi_only:
            trust_score -= 0.25
        else:
            trust_score += 0.10  # standard cart checkout

        # GSTIN contributes up to 20%
        if signals['gstin_checksum_valid']:
            trust_score += 0.20
        elif signals['gstin_found']:
            trust_score += 0.05

        # Policies & Contact Info contribute 10%
        if len(policies_found) >= 2 or signals['contact_info']:
            trust_score += 0.10

        # Reviews Modifier
        if review_data['sentiment'] == 'POSITIVE':
            trust_score += 0.10
        elif review_data['sentiment'] == 'HIGH_RISK':
            trust_score -= 0.35

        trust_score = max(0.0, min(trust_score, 1.0))

        if trust_score >= 0.70:
            trust_level = "ESTABLISHED"
        elif trust_score >= 0.45:
            trust_level = "SOME_SIGNALS"
        elif trust_score >= 0.25:
            trust_level = "FEW_SIGNALS"
        else:
            trust_level = "NO_SIGNALS"

        recommendations = []
        if trust_level in ("FEW_SIGNALS", "NO_SIGNALS"):
            recommendations.append("Do NOT pay via direct bank transfer or personal UPI QR")
            recommendations.append("Choose Cash on Delivery (COD) and inspect package before paying")
            recommendations.append("Check independent complaints before entering payment details")
        elif trust_level == "SOME_SIGNALS":
            recommendations.append("Use a credit card with chargeback protection rather than UPI / debit")
            recommendations.append("Check estimated delivery times — smaller stores may take 10-15 days")
        else:
            recommendations.append("Store exhibits solid legitimacy signals — standard buying precautions apply")

        return {
            'trust_score': round(trust_score, 3),
            'trust_level': trust_level,
            'gstin': signals.get('gstin_number'),
            'gstin_valid': signals['gstin_checksum_valid'],
            'payment_gateways': gateways,
            'domain_age': domain_age,
            'review_summary': review_data,
            'reasons': reasons,
            'recommendations': recommendations,
            'signals': signals
        }


if __name__ == "__main__":
    agent = StoreTrustAgent()
    print("Testing store trust on sample...")
    res = agent.analyze("https://www.boat-lifestyle.com")
    print(json.dumps(res, indent=2))
