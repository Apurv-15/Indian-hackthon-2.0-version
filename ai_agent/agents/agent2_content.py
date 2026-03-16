from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch
import torch.nn.functional as F
import os
import pickle

class ContentAnalysisAgent:
    def __init__(self):
        self.model_name = "microsoft/deberta-v3-small"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name, 
            num_labels=2,  
            ignore_mismatched_sizes=True
        )
        
        self.model.eval()
        
        print("Loading Hugging Face pipelines...")
        try:
            self.mask_pipeline = pipeline("fill-mask", model="microsoft/deberta-v3-small")
            self.sentiment_pipeline = pipeline("text-classification", model="distilbert/distilbert-base-uncased-finetuned-sst-2-english")
            self.has_pipelines = True
            print("Successfully loaded HF pipelines.")
        except Exception as e:
            print(f"Failed to load HF pipelines: {e}")
            self.has_pipelines = False

        print("Loading local text ML models...")
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        try:
            with open(os.path.join(model_dir, 'model.pkl'), 'rb') as f:
                self.text_ml_model = pickle.load(f)
            with open(os.path.join(model_dir, 'vectorizer.pkl'), 'rb') as f:
                self.text_vectorizer = pickle.load(f)
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
        """Analyze text for phishing indicators"""
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
        """Use transformer model for classification"""
        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                probabilities = F.softmax(outputs.logits, dim=-1)
                
            phishing_prob = probabilities[0][1].item()
            
            return phishing_prob
            
        except Exception as e:
            print(f"Transformer error: {e}")
            return 0.5 
    
    def analyze(self, input_data):
        """Main analysis function"""
        text = input_data['cleaned_text']
        
        phishing_score, keyword_matches, urgency_matches = self.analyze_phishing(text)
        
        prompt_injection, injection_patterns = self.analyze_prompt_injection(text)
        
        ai_generated_score, ai_patterns = self.analyze_ai_generated(text)
        
        transformer_score = self.analyze_with_transformer(text)
        
        combined_phishing = max(phishing_score, transformer_score * 0.7)
        
        # Use ML model for spam detection if available, else fallback to keywords
        spam_probability = 0.0
        spam_ml_prob = 0.0
        if self.has_text_ml:
            try:
                features = self.text_vectorizer.transform([text])
                # MultinomialNB
                spam_ml_prob = self.text_ml_model.predict_proba(features)[0][1]
                spam_probability = spam_ml_prob
            except Exception as e:
                print(f"Error predicting text spam with ML model: {e}")
                
        if spam_probability == 0.0:
            spam_indicators = ['free', 'win', 'winner', 'prize', 'click here', 'offer', 'limited time']
            spam_matches = [ind for ind in spam_indicators if ind in text.lower()]
            spam_probability = min(len(spam_matches) / 5, 1.0)
            
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
            'sentiment_score': sentiment_score,
            'sentiment_label': sentiment_label
        }
        
        return results