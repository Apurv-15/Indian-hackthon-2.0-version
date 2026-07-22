import time
import os
import sys
import io
import json

# Fix encoding issue for Windows environment
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
import gradio as gr
from utils.preprocessor import TextPreprocessor
from agents.agent1_external import ExternalAnalysisAgent
from agents.agent2_content import ContentAnalysisAgent
from agents.agent3_synthesizer import SynthesizerAgent
from agents.agent4_prompt import PromptInjectionAgent

class ThreatDetectionSystem:
    def __init__(self):
        print("Initializing Threat Detection System...")
        import torch
        if torch.cuda.is_available():
            print(f"🛡️  System running on GPU: {torch.cuda.get_device_name(0)}")
        else:
            print("🛡️  System running on CPU (No CUDA detected)")
        self.preprocessor = TextPreprocessor()
        self.agent1 = ExternalAnalysisAgent()
        self.agent2 = ContentAnalysisAgent()
        self.agent3 = SynthesizerAgent()
        self.agent4 = PromptInjectionAgent()
        print("System initialized!")
    
    def analyze(self, user_input):
        """Main analysis pipeline"""
        start_time = time.time()
        
        # Step 1: Preprocess
        print("🔍 Preprocessing...")
        preprocessed = self.preprocessor.preprocess(user_input)
        
        # Step 2: Run agents
        print("🤖 Running Analysis Agents (External, Content, Prompt)...")
        agent1_results = self.agent1.analyze(preprocessed)
        agent2_results = self.agent2.analyze(preprocessed)
        agent4_results = self.agent4.analyze(user_input)
        
        # Step 3: Synthesize results
        print("🧠 Synthesizing report...")
        final_result = self.agent3.synthesize(agent1_results, agent2_results, agent4_results)
        final_result['processing_time'] = time.time() - start_time
        
        return final_result

    def format_output(self, result):
        """Format the analysis result into a readable report string"""
        risk_color = "🔴" if result['risk_level'] == "HIGH" else "🟠" if result['risk_level'] == "MEDIUM" else "🟡" if result['risk_level'] == "LOW" else "🟢"
        report = f"{risk_color} {result['risk_level']} RISK DETECTED\n"
        report += f"Confidence: {result['confidence']:.1%}\n"
        report += f"Type: {', '.join(result['threat_types'])}\n\n"
        report += "Forensic Reasons:\n" + "\n".join([f"- {r}" for r in result['explanation']['reasons']])
        return report

# Initialize the system globally for HF
system = ThreatDetectionSystem()

# --- Gradio UI Logic ---
def ui_analyze(text):
    if not text or not text.strip():
        return "Please enter some text", {}, {}
    
    result = system.analyze(text)
    report = system.format_output(result)
    
    return report, result['detailed_results'], result['explanation']['actions']

# --- Next.js Backend Compatibility API ---
# This endpoint is what the Vercel frontend calls
def api_analyze(text):
    try:
        if not text or not text.strip():
            return {"error": "No input provided"}
            
        result = system.analyze(text)
        
        # Map to the schema expected by the Next.js frontend
        risk_map = {"MINIMAL": "Safe", "LOW": "Low", "MEDIUM": "Medium", "HIGH": "High"}
        risk_level = risk_map.get(result["risk_level"], "Medium")

        return {
            "riskLevel": risk_level,
            "threatType": ", ".join(result["threat_types"]),
            "confidenceScore": round(result["confidence"] * 100, 1),
            "riskScore": round(result["risk_score"], 4),
            "explanation": " ".join(result["explanation"]["reasons"]),
            "indicators": result["explanation"]["reasons"],
            "recommendations": result["explanation"]["actions"],
            "detailedScores": {
                "phishingProb": round(result["detailed_results"]["agent2"].get("phishing_probability", 0), 3),
                "spamProb": round(result["detailed_results"]["agent2"].get("spam_probability", 0), 3),
                "urlRisk": round(result["detailed_results"]["agent1"].get("url_risk", 0), 3),
                "sentimentLabel": result["detailed_results"]["agent2"].get("sentiment_label", "UNKNOWN"),
                "sentimentScore": round(result["detailed_results"]["agent2"].get("sentiment_score", 0), 3),
                "promptInjectionScore": round(result["detailed_results"]["agent4"].get("confidence", 0), 3),
                "promptInjectionDetected": result["detailed_results"]["agent4"].get("prompt_injection_detected", False),
            },
        }
    except Exception as e:
        return {"error": str(e)}

# --- Theme and Layout ---
with gr.Blocks(theme="soft", title="🛡️ AegisAI Security") as demo:
    gr.Markdown("# 🛡️ AegisAI: Advanced Phishing & Fraud Detector")
    gr.Markdown("Drop an email body or URL here to get a full forensic breakdown.")
    
    with gr.Row():
        with gr.Column(scale=2):
            input_box = gr.Textbox(label="Message Content", lines=8, placeholder="Paste email content...")
            with gr.Row():
                clear_btn = gr.Button("Clear")
                submit_btn = gr.Button("Analyze Threat", variant="primary")
        
        with gr.Column(scale=3):
            out_report = gr.Textbox(label="Analysis Report", lines=10, interactive=False)
            out_actions = gr.JSON(label="Recommended Actions")
            out_scores = gr.JSON(label="Agent Confidence Scores")

    # Connect UI
    submit_btn.click(fn=ui_analyze, inputs=input_box, outputs=[out_report, out_scores, out_actions])
    clear_btn.click(lambda: ["", "", {}, {}], outputs=[input_box, out_report, out_scores, out_actions])

    # HIDDEN API ENDPOINT FOR VERCEL
    # Note: Hugging Face exposes this as an endpoint /run/predict or via api_name
    api_endpoint = gr.Button("API", visible=False)
    api_endpoint.click(fn=api_analyze, inputs=input_box, outputs=out_scores, api_name="analyze")

if __name__ == "__main__":
    demo.launch()
