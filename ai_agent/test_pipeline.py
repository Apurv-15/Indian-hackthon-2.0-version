"""
Diagnostic script: test the analysis pipeline AFTER fixes.
"""
import sys, os, warnings
sys.path.insert(0, os.path.dirname(__file__))
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

from app import system

test_urls = [
    "https://www.amazon.in",
    "https://www.google.com",
    "http://testsafebrowsing.appspot.com/s/phishing.html",
    "https://paypa1-secure-login.xyz/account/verify",
    "https://g00gle-security.top/login",
    "https://amaz0n-deals.club/signin",
]

for url in test_urls:
    print(f"\n{'='*70}")
    print(f"TESTING URL: {url}")
    print(f"{'='*70}")
    result = system.analyze(url)
    print(f"  Risk Level:  {result['risk_level']}")
    print(f"  Risk Score:  {result['risk_score']:.4f}")
    print(f"  Confidence:  {result['confidence']:.2%}")
    print(f"  Threats:     {result['threat_types']}")
    print(f"  Agent1 URL Risk:     {result['detailed_results']['agent1'].get('url_risk', 'N/A')}")
    print(f"  Agent1 ML Risk:      {result['detailed_results']['agent1'].get('url_ml_risk', 'N/A')}")
    print(f"  Agent1 Domain Sim:   {result['detailed_results']['agent1'].get('domain_similarity', 'N/A')}")
    print(f"  Agent1 Risk Factors: {result['detailed_results']['agent1'].get('risk_factors', [])}")
    print(f"  Agent2 Phishing:     {result['detailed_results']['agent2'].get('phishing_probability', 'N/A')}")
    print(f"  Agent2 spam_ml:      {result['detailed_results']['agent2'].get('spam_ml_score', 'N/A')}")
    print(f"  Agent2 is_raw_url:   {result['detailed_results']['agent2'].get('is_raw_url', 'N/A')}")
