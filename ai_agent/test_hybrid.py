import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import system

def test():
    print("Testing Hybrid AI Integration...")
    
    examples = [
        {
            "name": "Suspicious PayPal",
            "text": "URGENT: Your PayPal account has been limited. Click here to verify: http://paypal-security.xyz"
        },
        {
            "name": "Safe YouTube",
            "text": "Hey, check out this cool video! http://youtube.com/watch?v=123"
        }
    ]
    
    for ex in examples:
        print(f"\nAnalyzing: {ex['name']}")
        result = system.analyze(ex['text'])
        report = system.format_output(result)
        print(report)
        
        # Basic assertions
        if "paypal-security" in ex['text']:
            conn_score = result['detailed_results']['agent2'].get('connection_score', 1.0)
            print(f"Connection Score: {conn_score:.4f}")
            if conn_score < 0.5:
                print("✅ Correctly identified divergence for suspicious URL.")
            else:
                print("❌ Failed to identify divergence for suspicious URL.")

if __name__ == "__main__":
    try:
        test()
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
