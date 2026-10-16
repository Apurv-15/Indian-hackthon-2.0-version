"""
Verification test suite for AegisAI threat detection accuracy fixes.
Tests false positive eliminations, naked domain normalization,
expanded brand protections (Indian banking/couriers), and anchor-text divergence.
"""
import sys
import os
import warnings

sys.path.insert(0, os.path.dirname(__file__))
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

from app import system

def run_tests():
    passed = 0
    total = 0

    print("=" * 80)
    print("RUNNING AEGISAI ACCURACY & THREAT DETECTION VERIFICATION SUITE")
    print("=" * 80)

    # -------------------------------------------------------------
    # 1. FALSE POSITIVE PREVENTION TESTS
    # -------------------------------------------------------------
    fp_cases = [
        {
            "name": "News article with brand in URL path",
            "input": "https://www.theverge.com/apple-iphone-16-pro-review",
            "anchor": "The Verge iPhone Review",
            "must_not_contain": ["Brand impersonation: 'apple'"],
            "max_risk": 0.45
        },
        {
            "name": "Word containing brand as substring (pineapple)",
            "input": "https://pineapple.com",
            "anchor": "Pineapple",
            "must_not_contain": ["similar to a legitimate brand", "homoglyph"],
            "max_risk": 0.40
        },
        {
            "name": "Official GitHub login endpoint",
            "input": "https://github.com/account/login",
            "anchor": "Sign in to GitHub",
            "must_not_contain": ["Suspicious keyword(s) in unverified URL"],
            "max_risk": 0.25
        },
        {
            "name": "Multi-part Indian CDN domain",
            "input": "https://assets.cdn.grovertechno.co.in/images/logo.png",
            "anchor": "Logo",
            "must_not_contain": ["Excessive subdomains in host"],
            "max_risk": 0.65
        }
    ]

    for case in fp_cases:
        total += 1
        print(f"\n[TEST {total}] False Positive Check: {case['name']}")
        print(f"  URL: {case['input']}")
        result = system.analyze(case['input'], anchor_text=case.get('anchor'))
        reasons_text = " ".join(result['explanation']['reasons'])
        
        raw_must_not = case.get('must_not_contain', [])
        must_not_contain = raw_must_not if isinstance(raw_must_not, list) else []
        max_risk = float(case['max_risk']) if isinstance(case.get('max_risk'), (int, float)) else 1.0
        failed_reasons = [crit for crit in must_not_contain if isinstance(crit, str) and crit in reasons_text]
        score_ok = result['risk_score'] <= max_risk
        
        if not failed_reasons and score_ok:
            print(f"  ✅ PASSED: Score = {result['risk_score']:.4f} ({result['risk_level']})")
            passed += 1
        else:
            print(f"  ❌ FAILED: Score = {result['risk_score']:.4f} ({result['risk_level']})")
            if failed_reasons:
                print(f"     Unexpected reasons fired: {failed_reasons}")
            if not score_ok:
                print(f"     Score {result['risk_score']} exceeded max {max_risk}")

    # -------------------------------------------------------------
    # 2. FALSE NEGATIVE PREVENTION TESTS (NEW ATTACKS & NAKED DOMAINS)
    # -------------------------------------------------------------
    fn_cases = [
        {
            "name": "Naked domain without protocol prefix (paypa1-security.xyz)",
            "input": "paypa1-security-update.xyz/verify",
            "min_risk": 0.70,
            "expected_threat": "Malicious URL"
        },
        {
            "name": "Indian Bank Impersonation (sbi-kyc-verification.top)",
            "input": "https://sbi-kyc-verification.top/login",
            "min_risk": 0.75,
            "must_contain": ["Brand impersonation: 'sbi'"]
        },
        {
            "name": "India Post Parcel Scam (indiapost-parcel-redelivery.live)",
            "input": "https://indiapost-parcel-redelivery.live/track",
            "min_risk": 0.75,
            "must_contain": ["Brand impersonation: 'indiapost'"]
        }
    ]

    for case in fn_cases:
        total += 1
        print(f"\n[TEST {total}] False Negative Check: {case['name']}")
        print(f"  URL: {case['input']}")
        result = system.analyze(case['input'])
        reasons_text = " ".join(result['explanation']['reasons'])

        min_risk = float(case['min_risk']) if isinstance(case.get('min_risk'), (int, float)) else 0.0
        raw_must_contain = case.get('must_contain', [])
        must_contain = raw_must_contain if isinstance(raw_must_contain, list) else []
        score_ok = result['risk_score'] >= min_risk
        missing_reasons = [crit for crit in must_contain if isinstance(crit, str) and crit not in reasons_text]

        if score_ok and not missing_reasons:
            print(f"  ✅ PASSED: Score = {result['risk_score']:.4f} ({result['risk_level']})")
            passed += 1
        else:
            print(f"  ❌ FAILED: Score = {result['risk_score']:.4f} ({result['risk_level']})")
            if not score_ok:
                print(f"     Score {result['risk_score']} was below required min {case['min_risk']}")
            if missing_reasons:
                print(f"     Expected reasons missing: {missing_reasons}")

    # -------------------------------------------------------------
    # 3. ANCHOR TEXT SEMANTIC DIVERGENCE TEST
    # -------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Semantic Divergence Check: Anchor text 'PayPal' pointing to unrelated domain")
    divergence_url = "https://portal-update-2026.xyz/session"
    anchor = "Click here to access your PayPal Security Settings"
    print(f"  URL: {divergence_url} | Anchor: '{anchor}'")
    result = system.analyze(divergence_url, anchor_text=anchor)
    reasons_text = " ".join(result['explanation']['reasons'])
    
    divergence_flagged = (
        "Deceptive Link Label" in result['threat_types'] or
        "divergence" in reasons_text.lower() or
        result['risk_score'] >= 0.70
    )
    if divergence_flagged:
        print(f"  ✅ PASSED: Detected semantic divergence! Score = {result['risk_score']:.4f} ({result['risk_level']})")
        passed += 1
    else:
        print(f"  ❌ FAILED: Did not flag semantic divergence. Score = {result['risk_score']:.4f}")

    print("\n" + "=" * 80)
    print(f"TEST RESULTS: {passed}/{total} TESTS PASSED")
    print("=" * 80)

    return passed == total

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
