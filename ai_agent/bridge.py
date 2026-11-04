"""
Persistent Flask bridge server.
Models are loaded ONCE on startup and stay in memory.
Serves requests from Chrome Extension and Next.js frontend.
"""
import os, sys, warnings, logging
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
os.environ["PYTORCH_MPS_HIGH_WATERMARK_RATIO"] = "0.0"
os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["PYTORCH_DISABLE_MPS"] = "1"
warnings.filterwarnings("ignore")

import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as ExecTimeoutError
from flask import Flask, request, jsonify
from flask_cors import CORS
from app import system
from agents.agent5_store_trust import StoreTrustAgent

app = Flask(__name__)
# Restrict CORS to localhost and browser extension schemes
CORS(app, resources={r"/*": {"origins": ["http://localhost:*", "http://127.0.0.1:*", "chrome-extension://*"]}})

store_trust_agent = StoreTrustAgent()
executor = ThreadPoolExecutor(max_workers=4)

REQUEST_TIMEOUT_SECONDS = 25.0


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "AegisAI Bridge"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    user_input = data.get("input", "").strip()
    anchor_text = (data.get("anchor_text") or data.get("anchorText") or "").strip()
    page_url = (data.get("page_url") or data.get("pageUrl") or "").strip()

    if not user_input:
        return jsonify({"error": "No input provided"}), 400

    def _run_analysis():
        return system.analyze(user_input, anchor_text=anchor_text, page_url=page_url)

    try:
        future = executor.submit(_run_analysis)
        result = future.result(timeout=REQUEST_TIMEOUT_SECONDS)

        risk_map = {"MINIMAL": "Safe", "LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}
        risk_level = risk_map.get(result["risk_level"], "Medium")
        print(f"🔍 [Bridge] Scanned: {user_input[:80]} | Anchor: '{anchor_text[:30]}' -> Result: {risk_level} ({result['risk_level']}) | Score: {result['risk_score']}", flush=True)

        return jsonify({
            "riskLevel": risk_level,
            "threatType": ", ".join(result["threat_types"]),
            "confidenceScore": round(result["confidence"] * 100, 1),
            "safetyScore": result.get("safety_score", round((1.0 - result["risk_score"]) * 100, 1)),
            "riskScore": round(result["risk_score"], 4),
            "summary": result["explanation"].get("summary") or "Analysis complete.",
            "humanReasons": result["explanation"].get("human_reasons") or [r.split(" — helper:")[0] for r in result["explanation"]["reasons"][:3]],
            "actionAdvice": result["explanation"].get("action_advice") or (result["explanation"]["actions"][0] if result["explanation"].get("actions") else "Safe to proceed."),
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
    except ExecTimeoutError:
        print(f"⚠️ [Bridge] Timeout analyzing input: {user_input[:50]}", flush=True)
        return jsonify({"error": "Analysis request timed out"}), 504
    except Exception as e:
        print(f"❌ [Bridge Error] {traceback.format_exc()}", flush=True)
        return jsonify({"error": "Internal analysis error occurred"}), 500


@app.route("/store-trust", methods=["POST"])
def store_trust():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No url provided"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    def _run_trust():
        return store_trust_agent.analyze(url)

    try:
        future = executor.submit(_run_trust)
        result = future.result(timeout=18.0)
        return jsonify(result)
    except ExecTimeoutError:
        print(f"⚠️ [Bridge] Timeout analyzing store trust: {url}", flush=True)
        return jsonify({"error": "Store trust lookup timed out"}), 504
    except Exception as e:
        print(f"❌ [Bridge Store Trust Error] {traceback.format_exc()}", flush=True)
        return jsonify({"error": "Internal store trust error occurred"}), 500


if __name__ == "__main__":
    print("🚀 AegisAI Python bridge running on http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
