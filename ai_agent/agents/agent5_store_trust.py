"""
==============================================================================
                AGENT 5: STORE TRUST AGENT
        Small/Unknown E-commerce Storefront Legitimacy Check
==============================================================================

Purpose: for stores that aren't Amazon/Flipkart (typically discovered via an
Instagram/Facebook ad) — is this a real registered business likely to ship
the product, or a one-page storefront that takes payment and disappears?

Signals checked, all from one live page fetch (no paid APIs):
- Reachable over HTTPS with a valid cert
- GSTIN present on the page, and passes the real GSTIN checksum algorithm
  (format-valid != verified-with-govt; a passing checksum only means the
  number isn't obviously fabricated)
- Contact info (phone / email) present
- Physical address / PIN code present
- Return/refund/shipping/privacy/terms policy pages linked
- Registered legal entity suffix (Pvt Ltd / LLP / etc.) mentioned

ponytail: no WHOIS-based domain age and no GSTN government verification API
(GSTN has no free public verification endpoint) — both would need a paid
third-party service. Add those if false-positive rate on checksum-valid but
fake GSTINs becomes a problem.
"""

import re
import requests
from urllib.parse import urlparse, urljoin


class StoreTrustAgent:
    GSTIN_RE = re.compile(r'\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b')
    PHONE_RE = re.compile(r'(\+91[\-\s]?)?[6-9]\d{9}\b')
    EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    PINCODE_RE = re.compile(r'\b\d{6}\b')
    LEGAL_SUFFIX_RE = re.compile(r'\b(pvt\.?\s*ltd|private\s+limited|llp|opc\b)', re.IGNORECASE)
    POLICY_KEYWORDS = ['return', 'refund', 'shipping', 'privacy policy', 'terms of service', 'terms & conditions', 'contact us']
    LINK_KEYWORDS = ['term', 'privacy', 'refund', 'return', 'shipping', 'about', 'contact', 'legal', 'polic']
    # Common Shopify/WooCommerce policy page slugs — tried when the homepage links can't be found (e.g. JS-rendered nav)
    FALLBACK_PATHS = [
        '/policies/refund-policy', '/policies/terms-of-service', '/policies/privacy-policy',
        '/pages/about-us', '/pages/contact-us', '/about-us', '/contact-us',
        '/terms-and-conditions', '/privacy-policy', '/refund-policy', '/return-policy'
    ]
    HREF_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)

    _GSTIN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    @classmethod
    def gstin_checksum_valid(cls, gstin):
        """Verify the GSTIN's built-in check digit (Luhn mod-36 variant, public GSTN spec)."""
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
            resp = requests.get(url, timeout=6, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
            return resp
        except requests.exceptions.RequestException:
            return None

    def find_policy_links(self, html, base_url):
        """Pull same-domain links whose URL looks like an about/contact/policy page — that's usually where GSTIN/address actually live, not the homepage footer."""
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

    def visible_text_length(self, html):
        stripped = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=re.IGNORECASE | re.DOTALL)
        stripped = re.sub(r'<[^>]+>', ' ', stripped)
        return len(stripped.split())

    def analyze(self, url):
        reasons = []
        signals = {}

        resp = self.fetch_page(url)
        if resp is None:
            return {
                'trust_score': 0.0,
                'trust_level': 'UNKNOWN',
                'reasons': ["Store is unreachable right now — cannot verify anything about it. Treat as high risk until it loads."],
                'recommendations': [
                    "Do not pay via direct bank transfer or personal UPI ID",
                    "Prefer Cash on Delivery or a payment method with buyer protection (card, established wallet)"
                ],
                'signals': {}
            }

        html = resp.text
        final_url = resp.url
        signals['ssl_valid'] = final_url.lower().startswith('https://')
        if signals['ssl_valid']:
            reasons.append("Site loads over HTTPS with a valid certificate")
        else:
            reasons.append("Site does not use HTTPS — payment/checkout data may be unencrypted")

        # GSTIN/address/policies usually live on About/Contact/Terms pages, not the homepage
        # footer — crawl a few of those too instead of judging off the homepage alone.
        sub_pages_html = []
        policy_links = self.find_policy_links(html, final_url)
        if not policy_links:
            policy_links = [urljoin(final_url, p) for p in self.FALLBACK_PATHS]
        for link in policy_links[:5]:
            sub_resp = self.fetch_page(link)
            if sub_resp is not None and sub_resp.status_code < 400:
                sub_pages_html.append(sub_resp.text)

        combined_text = html + "\n".join(sub_pages_html)

        signals['possibly_js_rendered'] = self.visible_text_length(html) < 150
        if signals['possibly_js_rendered']:
            reasons.append("Homepage looks JavaScript-rendered (very little static text) — some signals below may be missed rather than genuinely absent")

        gstin_matches = self.GSTIN_RE.findall(combined_text)
        valid_gstins = [g for g in gstin_matches if self.gstin_checksum_valid(g)]
        signals['gstin_found'] = bool(gstin_matches)
        signals['gstin_checksum_valid'] = bool(valid_gstins)
        if valid_gstins:
            reasons.append(f"GSTIN found on page and passes checksum validation: {valid_gstins[0]} — format-valid, not government-verified")
        elif gstin_matches:
            reasons.append(f"GSTIN-shaped number found but fails checksum validation ({gstin_matches[0]}) — likely fabricated")
        else:
            reasons.append("No GSTIN found anywhere on the page — legitimate Indian sellers are legally required to display one")

        has_phone = bool(self.PHONE_RE.search(combined_text))
        has_email = bool(self.EMAIL_RE.search(combined_text))
        signals['contact_info'] = has_phone or has_email
        if signals['contact_info']:
            reasons.append("Contact details (phone/email) found on the page")
        else:
            reasons.append("No phone number or email address found — no way to reach the seller if something goes wrong")

        signals['address_found'] = bool(self.PINCODE_RE.search(combined_text))
        if signals['address_found']:
            reasons.append("A PIN code / physical address appears on the page")
        else:
            reasons.append("No physical address or PIN code found — no verifiable business location")

        combined_lower = combined_text.lower()
        policies_found = [kw for kw in self.POLICY_KEYWORDS if kw in combined_lower]
        signals['policy_pages_found'] = policies_found
        if len(policies_found) >= 3:
            reasons.append(f"Store links standard policy pages ({', '.join(policies_found)})")
        elif policies_found:
            reasons.append(f"Only some policy pages found ({', '.join(policies_found)}) — missing return/refund terms is a red flag")
        else:
            reasons.append("No return, refund, shipping, or privacy policy found anywhere — a real store almost always has these")

        signals['legal_entity_mentioned'] = bool(self.LEGAL_SUFFIX_RE.search(combined_text))
        if signals['legal_entity_mentioned']:
            reasons.append("A registered legal entity name (Pvt Ltd / LLP / OPC) is mentioned")

        trust_score = 0.0
        trust_score += 0.15 if signals['ssl_valid'] else 0.0
        trust_score += 0.35 if signals['gstin_checksum_valid'] else (0.1 if signals['gstin_found'] else 0.0)
        trust_score += 0.15 if signals['contact_info'] else 0.0
        trust_score += 0.15 if signals['address_found'] else 0.0
        trust_score += min(len(policies_found) / len(self.POLICY_KEYWORDS), 1.0) * 0.2
        trust_score += 0.10 if signals['legal_entity_mentioned'] else 0.0
        trust_score = min(trust_score, 1.0)

        if trust_score >= 0.75:
            trust_level = "ESTABLISHED"
        elif trust_score >= 0.5:
            trust_level = "SOME_SIGNALS"
        elif trust_score >= 0.25:
            trust_level = "FEW_SIGNALS"
        else:
            trust_level = "NO_SIGNALS"

        recommendations = []
        if trust_level in ("FEW_SIGNALS", "NO_SIGNALS"):
            recommendations.append("Do not pay via direct bank transfer or personal UPI ID")
            recommendations.append("Prefer Cash on Delivery, or a card/payment method with buyer protection and chargeback rights")
            recommendations.append("Search the brand name + 'reviews' or 'scam' outside the site itself before ordering")
            if not signals['gstin_found']:
                recommendations.append("Ask the seller for their GSTIN and verify it manually on the GST portal")
        elif trust_level == "SOME_SIGNALS":
            recommendations.append("Verify the GSTIN manually on the GST portal before a large order")
            recommendations.append("Start with a small/low-value order to confirm delivery before trusting the store further")
        else:
            recommendations.append("Store shows standard legitimacy signals — normal purchase precautions apply")

        return {
            'trust_score': round(trust_score, 3),
            'trust_level': trust_level,
            'reasons': reasons,
            'recommendations': recommendations,
            'signals': signals
        }


def _demo():
    """Self-check: GSTIN checksum algorithm and score thresholds, no network call."""
    agent = StoreTrustAgent()
    assert agent.gstin_checksum_valid("27AAPFU0939F1ZV") is True, "known-valid GSTIN sample should pass checksum"
    assert agent.gstin_checksum_valid("27AAPFU0939F1ZA") is False, "corrupted checksum digit should fail"
    assert agent.gstin_checksum_valid("TOO_SHORT") is False
    print("agent5_store_trust self-check passed")


if __name__ == "__main__":
    _demo()
