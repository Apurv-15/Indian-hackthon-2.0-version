from transformers import AutoTokenizer, AutoModelForSequenceClassification, AutoModel, pipeline
import torch
import torch.nn.functional as F
import os
import pickle
import re

class ContentAnalysisAgent:
    def __init__(self):
        # Detection of Device
        if torch.cuda.is_available():
            self.device = torch.device("cuda")
            gpu_name = torch.cuda.get_device_name(0)
            print(f"🚀 CUDA detected! Using GPU: {gpu_name} for inference optimization.")
        elif torch.backends.mps.is_available():
            self.device = torch.device("mps")
            print("🚀 Apple Silicon detected! Using MPS for inference optimization.")
        else:
            self.device = torch.device("cpu")
            print("⚠️ CUDA not found. Falling back to CPU.")

        # Load local text ML models...
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        local_deberta_path = os.path.join(model_dir, 'fine_tuned_deberta')
        has_weights = (
            os.path.exists(os.path.join(local_deberta_path, "pytorch_model.bin")) or
            os.path.exists(os.path.join(local_deberta_path, "model.safetensors"))
        )

        if os.path.exists(local_deberta_path) and has_weights:
            self.model_name = local_deberta_path
            self.has_deberta = True
            print(f"Loading local fine-tuned DeBERTa model from {local_deberta_path}...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name, use_fast=True)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                num_labels=2,
                ignore_mismatched_sizes=True
            ).to(self.device)
            # Optimization: Use Half-precision if on MPS
            if self.device.type == "mps":
                self.model = self.model.half()
            self.model.eval()
        else:
            self.model_name = "microsoft/deberta-v3-small"
            self.has_deberta = False
            self.tokenizer = None
            self.model = None
            print("Notice: Local fine-tuned DeBERTa model not found. DeBERTa text classifier is bypassed to prevent random predictions.")

        print("Loading Hugging Face pipelines...")
        try:
            raise Exception("Skipping pipeline to avoid deadlock on Windows")
            self.sentiment_pipeline = pipeline("text-classification", model="distilbert/distilbert-base-uncased-finetuned-sst-2-english")
            self.has_pipelines = True
            print("Successfully loaded HF pipelines.")
        except Exception as e:
            print(f"Failed to load HF pipelines: {e}")
            self.has_pipelines = False

        print("Loading local text ML models...")
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        try:
            with open(os.path.join(model_dir, 'model_new.pkl'), 'rb') as f:
                self.scikit_model = pickle.load(f)
            with open(os.path.join(model_dir, 'vectorizer_new.pkl'), 'rb') as f:
                self.scikit_vectorizer = pickle.load(f)
            self.has_text_ml = True
            print("Successfully loaded text ML models.")
        except Exception as e:
            print(f"Failed to load text ML models: {e}")
            self.has_text_ml = False

        self.phishing_keywords = [
            'verify', 'account', 'bank', 'login', 'password', 'credit card',
            'ssn', 'social security', 'suspended', 'limited', 'unusual activity',
            'confirm identity', 'update information', 'click here', 'urgent'
        ]

        self.urgency_phrases = [
            'immediately', 'within 24 hours', 'as soon as possible',
            'urgent', 'action required', 'deadline', 'expire soon'
        ]

        self.prompt_injection_patterns = [
            'ignore previous instructions',
            'ignore all previous',
            'disregard previous',
            'system prompt',
            'you are now',
            'act as',
            'new role:',
            'forget your instructions'
        ]

    def analyze_phishing(self, text):
        """
        Analyze text for phishing indicators using pattern matching.
        """


        text_lower = text.lower()

        keyword_matches = []
        for keyword in self.phishing_keywords:
            if keyword in text_lower:
                keyword_matches.append(keyword)

        urgency_matches = []
        for phrase in self.urgency_phrases:
            if phrase in text_lower:
                urgency_matches.append(phrase)

        keyword_score = min(len(keyword_matches) / 5, 1.0)
        urgency_score = min(len(urgency_matches) / 3, 1.0)

        has_personal_info_request = any([
            'password' in text_lower and 'send' in text_lower,
            'credit card' in text_lower,
            'ssn' in text_lower,
            'social security' in text_lower
        ])

        if has_personal_info_request:
            personal_info_score = 0.8
        else:
            personal_info_score = 0.0

        phishing_score = (keyword_score * 0.4 + urgency_score * 0.3 + personal_info_score * 0.3)

        return phishing_score, keyword_matches, urgency_matches

    def analyze_prompt_injection(self, text):
        """Check for prompt injection attempts"""
        text_lower = text.lower()

        for pattern in self.prompt_injection_patterns:
            if pattern in text_lower:
                return True, [f"Prompt injection pattern detected: '{pattern}'"]

        return False, []

    def analyze_ai_generated(self, text):
        """Basic detection of AI-generated content patterns"""
        ai_indicators = [
            'as an ai', 'i am an ai', 'as a language model',
            'i cannot', 'i apologize', 'i am unable to',
            'unfortunately', 'i must inform you'
        ]

        text_lower = text.lower()
        matches = [ind for ind in ai_indicators if ind in text_lower]

        if len(matches) > 1:
            return 0.7, matches
        elif len(matches) > 0:
            return 0.4, matches
        else:
            return 0.0, []

    def analyze_with_transformer(self, text):
        """
        Use transformer model for contextual text classification.

        ALGORITHM: DeBERTa-v3-Small (Microsoft's Transformer)
        - State-of-the-art sequence classification
        - Captures nuanced semantic patterns
        - More accurate than traditional ML for complex social engineering

        Returns: Probability of malicious content (0-1) or None if bypassed
        """
        if not self.has_deberta or self.model is None or self.tokenizer is None:
            return None

        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512).to(self.device)

            with torch.inference_mode(): # Faster than no_grad
                outputs = self.model(**inputs)
                probabilities = F.softmax(outputs.logits.float(), dim=-1) # Cast back to float for softmax

            phishing_prob = probabilities[0][1].item()
            return phishing_prob

        except Exception as e:
            print(f"Transformer error: {e}")
            return None

    def analyze_connection(self, text, urls):
        """
        Analyze connection between email text and URLs.
        Heuristics-based to prevent PyTorch deadlocks on Windows CPU.
        """
        if not urls:
            return 1.0, "No URLs to analyze"

        text_lower = text.lower()
        connection_scores = []
        for url in urls:
            url_lower = url.lower()
            # Extract domain parts
            domain = url_lower.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]

            # Heuristic: If email mentions a brand, but the URL is not the official domain of that brand
            brands = {
                'paypal': 'paypal.com',
                'google': 'google.com',
                'microsoft': 'microsoft.com',
                'amazon': 'amazon.com',
                'apple': 'apple.com'
            }

            score = 1.0
            for brand, official in brands.items():
                if brand in text_lower:
                    # Brand is mentioned in text. Does the URL point to a domain containing the brand, but not the official one?
                    if brand in domain and official not in domain:
                        # High divergence (brand impersonation)
                        score = min(score, 0.1)
                    elif brand not in domain:
                        # Moderate divergence (URL doesn't match the brand mentioned)
                        score = min(score, 0.3)

            connection_scores.append(score)

        avg_score = sum(connection_scores) / len(connection_scores)
        if avg_score < 0.2:
            return avg_score, "High divergence: URL content does not match email context (Heuristic)"
        elif avg_score < 0.5:
            return avg_score, "Moderate divergence: URL seems loosely related to email context (Heuristic)"
        else:
            return avg_score, "Stable: URL matches email context (Heuristic)"

    def analyze(self, input_data):
        """Main analysis function with hybrid and connection logic"""
        text = input_data['cleaned_text']
        urls = input_data['urls']

        # Check if the input is a raw URL
        is_raw_url = False
        text_stripped = text.strip()
        if (text_stripped.startswith('http://') or text_stripped.startswith('https://')) and len(text_stripped.split()) == 1:
            is_raw_url = True

        if is_raw_url:
            return {
                'phishing_probability': 0.0,
                'prompt_injection': False,
                'prompt_injection_patterns': [],
                'ai_generated_probability': 0.0,
                'spam_probability': 0.0,
                'spam_ml_score': 0.0,
                'keyword_matches': [],
                'urgency_matches': [],
                'ai_patterns': [],
                'transformer_score': 0.0,
                'using_transformer': False,
                'sentiment_score': 0.0,
                'sentiment_label': "UNKNOWN",
                'connection_score': 1.0,
                'connection_message': "Safe: Input is a raw URL",
                'is_raw_url': True
            }

        # Benign baseline check for short / common messages
        benign_greetings = ['hi', 'hii', 'hiii', 'hello', 'hey', 'how are you', 'how is this', 'test']
        clean_msg = text.lower().strip().replace('?', '').replace('!', '')
        if clean_msg in benign_greetings and not urls:
            return {
                'phishing_probability': 0.01,
                'urgency_matches': [],
                'keyword_matches': [],
                'prompt_injection': False,
                'ai_generated_probability': 0.05,
                'spam_probability': 0.01,
                'connection_score': 1.0,
                'connection_message': "Safe: Benign conversational text",
                'sentiment_label': "POSITIVE",
                'sentiment_score': 0.99
            }

        phishing_score, keyword_matches, urgency_matches = self.analyze_phishing(text)
        prompt_injection, injection_patterns = self.analyze_prompt_injection(text)
        ai_generated_score, ai_patterns = self.analyze_ai_generated(text)
        transformer_score = self.analyze_with_transformer(text)

        # Hybrid Text Analysis: Combine model.pkl score with transformer_score
        spam_probability = 0.0
        spam_ml_prob = 0.0
        if self.has_text_ml:
            try:
                features = self.scikit_vectorizer.transform([text])
                spam_ml_prob = self.scikit_model.predict_proba(features)[0][1]
                # Fine-tune transformer score using the pickle model baseline
                if transformer_score is not None:
                    transformer_score = (transformer_score * 0.7) + (spam_ml_prob * 0.3)
                else:
                    transformer_score = spam_ml_prob
                spam_probability = spam_ml_prob
            except Exception as e:
                print(f"Text ML model unavailable (sklearn version mismatch), using fallback: {e}")
                self.has_text_ml = False  # disable to avoid repeated errors

        if transformer_score is None:
            transformer_score = 0.0

        # Connection Analysis
        connection_score, connection_msg = self.analyze_connection(text, urls)

        # Adjust combined phishing score based on connection divergence
        # If divergence is high (low connection), we increase the phishing probability
        connection_penalty = max(0, 0.5 - connection_score) if connection_score < 0.4 else 0
        combined_phishing = min(max(phishing_score, transformer_score) + connection_penalty, 1.0)

        if spam_probability < 0.3:
            spam_indicators = ['free', 'win', 'winner', 'prize', 'click here', 'offer', 'limited time', 'lottery', 'congratulations', 'cash', 'money', 'claim', 'award']
            spam_matches = [ind for ind in spam_indicators if ind in text.lower()]
            heuristic_spam = min(len(spam_matches) / 6, 1.0) # 1 match = 0.16 (Safe), 2 matches = 0.33 (Low), 3 matches = 0.5 (Medium)
            spam_probability = max(spam_probability, heuristic_spam)

        # Optional sentiment analysis using pipeline
        sentiment_score = 0.0
        sentiment_label = "UNKNOWN"
        if self.has_pipelines:
            try:
                sent_result = self.sentiment_pipeline(text[:512])[0]
                sentiment_label = sent_result['label']
                sentiment_score = sent_result['score'] if sentiment_label == 'NEGATIVE' else (1.0 - sent_result['score'])
            except Exception as e:
                print(f"Error predicting sentiment: {e}")

        results = {
            'phishing_probability': combined_phishing,
            'prompt_injection': prompt_injection,
            'prompt_injection_patterns': injection_patterns,
            'ai_generated_probability': ai_generated_score,
            'spam_probability': spam_probability,
            'spam_ml_score': spam_ml_prob,
            'keyword_matches': keyword_matches,
            'urgency_matches': urgency_matches,
            'ai_patterns': ai_patterns,
            'transformer_score': transformer_score,
            'using_transformer': True,
            'sentiment_score': sentiment_score,
            'sentiment_label': sentiment_label,
            'connection_score': connection_score,
            'connection_message': connection_msg
        }

        return results
