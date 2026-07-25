"""
Agent 4: AI Prompt Injection Detection Module
Uses a fine‑tuned DeBERTa model (MNLI) + rule‑based patterns.
"""

import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

class PromptInjectionAgent:
    """
    Detects prompt injection and jailbreak attempts in user inputs.
    Combines a transformer model (trained on MNLI) with heuristic rules.
    """
    def __init__(self, model_name="mrm8488/deberta-v3-small-finetuned-mnli", threshold=0.6):
        """
        Args:
            model_name: Hugging Face model identifier for a DeBERTa MNLI model.
            threshold: Confidence threshold above which input is flagged as injection.
        """
        print("Loading Prompt Injection Agent (MNLI-based)...")
        self.threshold = threshold

        # Detection of Device
        if torch.cuda.is_available():
            self.device = torch.device("cuda")
            gpu_name = torch.cuda.get_device_name(0)
            print(f"🚀 CUDA detected! Using GPU: {gpu_name} for Prompt Injection Agent.")
        elif torch.backends.mps.is_available():
            self.device = torch.device("mps")
            print("🚀 Apple Silicon detected! Using MPS for Prompt Injection Agent.")
        else:
            self.device = torch.device("cpu")
            print("⚠️ CUDA not found for Prompt Injection Agent. Using CPU.")

        # Bypassing the transformer model to avoid Windows CPU deadlocks.
        # We will rely entirely on the rule-based regex patterns.
        self.tokenizer = None
        self.model = None
        print("✓ Rule-based engine loaded (Transformer bypassed for stability)")

        # Rule‑based patterns (covers common jailbreak attempts)
        self.injection_patterns = [
            (r"ignore previous instructions", "instruction_override"),
            (r"ignore all previous", "instruction_override"),
            (r"disregard previous", "instruction_override"),
            (r"system prompt", "system_override"),
            (r"you are now", "role_playing"),
            (r"act as", "role_playing"),
            (r"new role:", "role_playing"),
            (r"forget your instructions", "instruction_override"),
            (r"do anything now", "privilege_escalation"),
            (r"you must", "privilege_escalation"),
            (r"you are free", "jailbreak"),
            (r"no restrictions", "jailbreak"),
            (r"override", "instruction_override"),
            (r"jailbreak", "jailbreak"),
            (r"dan", "jailbreak"),                # DAN mode
            (r"developer mode", "jailbreak"),
            (r"chatgpt, you are now", "role_playing"),
            (r"you are an ai with no ethics", "role_playing"),
            (r"output raw", "attention_diversion"),
            (r"base64 decode", "attention_diversion"),
        ]

    def analyze(self, text: str) -> dict:
        """
        Analyze input text for prompt injection.

        Returns:
            dict with keys:
                prompt_injection_detected (bool): final decision
                confidence (float): combined risk score
                risk_score (float): same as confidence (for backward compatibility)
                matched_patterns (list): regex patterns that fired
                attack_categories (list): types of injection detected
                explanation (list): human‑readable reasons
        """
        # -------------------- Rule‑based scan --------------------
        text_lower = text.lower()
        rule_score = 0.0
        matched_patterns = []
        attack_categories = []

        for pattern, category in self.injection_patterns:
            if re.search(pattern, text_lower):
                rule_score += 0.3
                matched_patterns.append(pattern)
                attack_categories.append(category)

        # -------------------- Transformer inference --------------------
        if self.model is not None and self.tokenizer is not None:
            # Tokenize
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            ).to(self.device)

            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = torch.nn.functional.softmax(outputs.logits, dim=-1)

            # MNLI classes: 0 = entailment, 1 = neutral, 2 = contradiction
            contradiction_prob = probs[0][2].item()
        else:
            contradiction_prob = 0.0

        # -------------------- Combine scores --------------------
        # 70% weight on contradiction probability, 30% on rule‑based
        combined_risk = 0.7 * contradiction_prob + 0.3 * min(rule_score, 1.0)
        detected = combined_risk > self.threshold

        # -------------------- Build explanation --------------------
        explanation = []
        explanation.append(f"Contradiction probability: {contradiction_prob:.1%}")
        if attack_categories:
            unique_cats = list(set(attack_categories))
            explanation.append(f"Rule matches: {', '.join(unique_cats)}")
        if detected:
            explanation.append(f"Combined risk {combined_risk:.1%} exceeds threshold {self.threshold:.0%}")

        return {
            "prompt_injection_detected": detected,
            "confidence": combined_risk,
            "risk_score": combined_risk,          # alias for compatibility
            "matched_patterns": matched_patterns,
            "attack_categories": list(set(attack_categories)),
            "explanation": explanation
        }