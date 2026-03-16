"""
Persistent Flask bridge server.
Models are loaded ONCE on startup and stay in memory.
The Next.js API route calls http://localhost:5001/analyze.
"""
import os, sys, warnings
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from app import system

app = Flask(__name__)


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
        risk_map = {"MINIMAL": "Safe", "LOW": "Low", "MEDIUM": "Medium", "HIGH": "High"}
        risk_level = risk_map.get(result["risk_level"], "Medium")

        return jsonify({
            "riskLevel": risk_level,
            "threatType": ", ".join(result["threat_types"]),
            "confidenceScore": round(result["confidence"] * 100, 1),
            "explanation": " ".join(result["explanation"]["reasons"]),
            "indicators": result["explanation"]["reasons"],
            "recommendations": result["explanation"]["actions"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("🚀 AegisAI Python bridge running on http://localhost:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
