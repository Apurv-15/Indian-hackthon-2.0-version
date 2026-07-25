"""\n╔═══════════════════════════════════════════════════════════════════════╗\n║                  AGENT 2: CONTENT ANALYSIS AGENT                       ║\n║           Email/Text Analysis with Hybrid ML Algorithms               ║\n╚═══════════════════════════════════════════════════════════════════════╝\n\nALGORITHMS USED:\n\n1. MULTINOMIAL NAIVE BAYES (MNB)\n   - Model File: model_new.pkl\n   - Vectorizer: vectorizer_new.pkl (TF-IDF)\n   - Purpose: Text classification for spam/phishing detection\n   - Training Data: phishing_email_dataset.csv + spam_detection_dataset.csv\n   - Implementation: scikit-learn MultinomialNB classifier\n   - Output: Probability scores for text classification\n   - Use Case: Fast, interpretable baseline model for text threats\n   - Advantages: Efficient, works well with sparse TF-IDF features\n\n2. LOGISTIC REGRESSION (via scikit-learn)\n   - Embedded in scikit-learn pipeline\n   - Purpose: Alternative probabilistic classifier\n   - Training Data: Same as MNB models\n   - Output: Baseline probability for comparative analysis\n   - Use Case: Provides secondary validation of threat probability\n\n3. DEBERTA-V3-SMALL (Transformer Neural Network)\n   - Model: microsoft/deberta-v3-small\n   - Purpose: Deep contextual understanding of phishing content\n   - Type: Transformer-based sequence classification\n   - Application: Detects semantic patterns beyond keyword matching\n   - Output: Contextual threat probability (0-1 scale)\n   - Advantages: Captures nuanced language patterns and social engineering tactics\n\n4. DISTILBERT (Sentiment Analysis)\n   - Model: distilbert/distilbert-base-uncased-finetuned-sst-2-english\n   - Purpose: Detect aggressive/urgent tone (pressure tactics)\n   - Type: BERT distillation for efficiency\n   - Output: Sentiment label + confidence score\n   - Use Case: Identifies social engineering pressure in emails\n\n5. SENTENCE-TRANSFORMERS (MiniLM Semantic Embeddings)\n   - Model: sentence-transformers/all-MiniLM-L6-v2\n   - Purpose: Semantic similarity between email text and URLs\n   - Algorithm: Mean pooling of token embeddings + cosine similarity\n   - Output: Connection score (0-1 scale)\n   - Use Case: Detects divergence attacks (text ≠ URL destination)\n\n6. HEURISTIC PATTERN MATCHING\n   - Keyword spotting (phishing keywords, urgency phrases)\n   - Regex patterns for common scam indicators\n   - Prompt injection pattern detection\n\"\"\"\n\nfrom transformers import AutoTokenizer, AutoModelForSequenceClassification, AutoModel, pipeline\nimport torch\nimport torch.nn.functional as F\nimport os\nimport pickle\nimport re\n\nclass ContentAnalysisAgent:
    def __init__(self):
        # Detection of Device
        self.device = torch.device("mps") if torch.backends.mps.is_available() else torch.device("cpu")
        print(f"Using device: {self.device} for inference optimization.")

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
        else:
            self.model_name = "microsoft/deberta-v3-small"
            self.has_deberta = False
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name, use_fast=False)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                num_labels=2,
                ignore_mismatched_sizes=True
            ).to(self.device)
            print("Notice: Local fine-tuned DeBERTa model not found. Using pre-trained microsoft/deberta-v3-small.")

        # New: sentence-transformers/all-MiniLM-L6-v2 using AutoModel/AutoTokenizer
        self.minilm_name = "sentence-transformers/all-MiniLM-L6-v2"
        self.minilm_tokenizer = AutoTokenizer.from_pretrained(self.minilm_name)
        self.minilm_model = AutoModel.from_pretrained(self.minilm_name).to(self.device)

        # Optimization: Use Half-precision if on MPS
        if self.device.type == "mps":
            if self.model:
                self.model = self.model.half()
            self.minilm_model = self.minilm_model.half()

        self.model.eval()
        self.minilm_model.eval()
        
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
        
        ALGORITHM: Heuristic Rule-Based Detection
        - Keyword spotting for known phishing indicators
        - Urgency phrase detection for pressure tactics
        - Personal information request detection
        
        Returns: Combined phishing score (0-1)
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
        
        Returns: Probability of malicious content (0-1)
        """
        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512).to(self.device)
            
            with torch.inference_mode(): # Faster than no_grad
                outputs = self.model(**inputs)
                probabilities = F.softmax(outputs.logits.float(), dim=-1) # Cast back to float for softmax
                
            phishing_prob = probabilities[0][1].item()
            return phishing_prob
            
        except Exception as e:
            print(f"Transformer error: {e}")
            return 0.5 
    
    def get_minilm_embeddings(self, text):
        """Get embeddings using all-MiniLM-L6-v2 with mean pooling (optimized)"""
        inputs = self.minilm_tokenizer(text, padding=True, truncation=True, return_tensors='pt', max_length=512).to(self.device)
        with torch.inference_mode():
            model_output = self.minilm_model(**inputs)
        
        # Mean Pooling
        attention_mask = inputs['attention_mask']
        token_embeddings = model_output[0].float() # Cast to float16 to float32 for pooling stability
        input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
        embeddings = torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(input_mask_expanded.sum(1), min=1e-9)
        return embeddings

    def analyze_connection(self, text, urls):
        """
        Analyze semantic connection between email text and URLs.
        
        ALGORITHM: Cosine Similarity of Dense Embeddings
        - Uses MiniLM embeddings to compute semantic similarity
        - Detects "divergence attacks" where text ≠ URL destination
        - Example: Email says "Click to update PayPal" but URL is malicious.ru
        
        Returns: (connection_score, message)
        - Score 1.0 = Perfect alignment
        - Score < 0.2 = High divergence (suspicious)
        """
        if not urls:
            return 1.0, "No URLs to analyze"
        
        text_emb = self.get_minilm_embeddings(text)
        
        connection_scores = []
        for url in urls:
            # Extract meaningful parts of the URL for semantic comparison
            url_parts = url.replace('http://', '').replace('https://', '').replace('www.', '')
            url_parts = re.sub(r'[/.\-_]', ' ', url_parts)
            url_emb = self.get_minilm_embeddings(url_parts)
            
            similarity = F.cosine_similarity(text_emb, url_emb).item()
            connection_scores.append(similarity)
        
        avg_connection = sum(connection_scores) / len(connection_scores)
        
        # A very low connection score (divergence) is an indicator of phishing
        if avg_connection < 0.2:
            return avg_connection, "High divergence: URL content does not match email context"
        elif avg_connection < 0.4:
            return avg_connection, "Moderate divergence: URL seems loosely related to email context"
        else:
            return avg_connection, "Stable: URL matches email context"

    def analyze(self, input_data):
        """Main analysis function with hybrid and connection logic"""
        text = input_data['cleaned_text']
        urls = input_data['urls']
        
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
                transformer_score = (transformer_score * 0.7) + (spam_ml_prob * 0.3)
                spam_probability = spam_ml_prob
            except Exception as e:
                print(f"Text ML model unavailable (sklearn version mismatch), using fallback: {e}")
                self.has_text_ml = False  # disable to avoid repeated errors
                
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