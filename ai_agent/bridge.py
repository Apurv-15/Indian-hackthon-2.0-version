"""
Persistent Flask bridge server.
Models are loaded ONCE on startup and stay in memory.
The Next.js API route calls http://localhost:5001/analyze.
"""
import os, sys, warnings
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
warnings.filterwarnings("ignore")

import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from flask_cors import CORS
from app import system
from agents.agent5_store_trust import StoreTrustAgent

app = Flask(__name__)
CORS(app) # Allow cross-origin requests from the browser extension

store_trust_agent = StoreTrustAgent()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    user_input = data.get("input", "").strip()

    if not user_input:
        return jsonify({"error": "No input provided"}), 400

    try:
        result = system.analyze(user_input)

        # Map to the schema expected by the Next.js frontend
        risk_map = {"MINIMAL": "Safe", "LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}
        risk_level = risk_map.get(result["risk_level"], "Medium")
        print(f"🔍 [Extension Request] Scanned: {user_input[:80]} -> Result: {risk_level} ({result['risk_level']}) | Score: {result['risk_score']}", flush=True)

        return jsonify({
            "riskLevel": risk_level,
            "threatType": ", ".join(result["threat_types"]),
            "confidenceScore": round(result["confidence"] * 100, 1),
            "riskScore": round(result["risk_score"], 4),
            "explanation": " ".join([r.split(" — helper:")[0] for r in result["explanation"]["reasons"]]),
            "indicators": result["explanation"]["reasons"],
            "recommendations": result["explanation"]["actions"],
            "detailedScores": {
                "phishingProb": round(result["detailed_results"]["agent2"].get("phishing_probability", 0), 3),
                "spamProb": round(max(
                    result["detailed_results"]["agent2"].get("spam_probability", 0),
                    result["detailed_results"]["agent2"].get("spam_ml_score", 0)
                ), 3),
                "urlRisk": round(max(
                    result["detailed_results"]["agent1"].get("url_risk", 0),
                    result["detailed_results"]["agent1"].get("url_ml_risk", 0)
                ), 3),
                "sentimentLabel": result["detailed_results"]["agent2"].get("sentiment_label", "UNKNOWN"),
                "sentimentScore": round(result["detailed_results"]["agent2"].get("sentiment_score", 0), 3),
                "promptInjectionScore": round(result["detailed_results"]["agent4"].get("confidence", 0), 3),
                "promptInjectionDetected": result["detailed_results"]["agent4"].get("prompt_injection_detected", False),
                "attackCategories": result["detailed_results"]["agent4"].get("attack_categories", []),
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/store-trust", methods=["POST"])
def store_trust():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No url provided"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    try:
        result = store_trust_agent.analyze(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("🚀 AegisAI Python bridge running on http://localhost:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
