"""
Test StoreTrustAgent on live stores (GSTIN, Payment Gateways, Domain Age, Reviews)
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))

from agents.agent5_store_trust import StoreTrustAgent

agent = StoreTrustAgent()

test_stores = [
    "https://www.boat-lifestyle.com",
    "https://mamaearth.in",
    "https://paypa1-secure-login.xyz"
]

for url in test_stores:
    print(f"\n{'='*70}")
    print(f"TESTING STORE: {url}")
    print(f"{'='*70}")
    res = agent.analyze(url)
    print(f"Trust Score:     {res['trust_score'] * 100}% ({res['trust_level']})")
    print(f"GSTIN:           {res['gstin']} (Valid: {res['gstin_valid']})")
    print(f"Payment Gateways: {res['payment_gateways']}")
    print(f"Domain Age:      {res['domain_age'].get('age_text')}")
    print(f"Reviews:         {res['review_summary'].get('rating_label')} -> {res['review_summary'].get('summary')}")
    print(f"Signals:         {res['reasons'][:4]}")
