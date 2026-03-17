# 🏗️ AegisAI System Architecture

## System Overview

AegisAI is a **Multi-Agent Threat Detection System** that combines traditional machine learning models with modern transformer-based deep learning to detect phishing, spam, malicious URLs, and prompt injection attacks.

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER INPUT (Email/URL/Text)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    TEXT PREPROCESSOR                             │
│  • Clean & normalize text                                        │
│  • Extract URLs and domains                                      │
│  • Prepare input for agents                                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
            ┌────────────────┼────────────────┬──────────────────┐
            │                │                │                  │
            ▼                ▼                ▼                  ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │   AGENT 1     │ │   AGENT 2     │ │   AGENT 3     │ │   AGENT 4     │
    │  External &   │ │   Content &   │ │ Synthesizer   │ │   Prompt      │
    │    URL        │ │   Text        │ │   Agent       │ │  Injection    │
    │  Analysis     │ │  Analysis     │ │(Aggregator)   │ │   Detection   │
    └────────┬──────┘ └────────┬──────┘ └───────┬───────┘ └────────┬──────┘
             │                 │                 │                  │
             │ url_risk        │ phishing_prob   │ (receives all    │ prompt_
             │ domain_sim      │ spam_score      │  agent results)  │ injection
             │ url_ml_risk     │ sentiment       │                  │ confidence
             │ url_factors     │ ai_generated    │                  │ attack_cats
             │                 │ connection_score│                  │
             │                 │ text_ml_score   │                  │
             │                 │ urgency_matches │                  │
             │                 │ keyword_matches │                  │
             └────────────────┬┴────────────────┴──────────────────┘
                              │
                              ▼ (Inter-agent communication)
                    ┌──────────────────────┐
                    │   SYNTHESIZER        │
                    │   Combines Results:  │
                    │  • Weighted scoring  │
                    │  • Risk aggregation  │
                    │  • Threat typing     │
                    │  • Consensus        │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  FINAL RISK REPORT   │
                    │  • Risk Level (HIGH) │
                    │  • Threat Types      │
                    │  • Confidence Score  │
                    │  • Forensic Reasons  │
                    │  • Recommendations   │
                    └──────────────────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
        [Gradio UI]    [Next.js API]    [JSON Output]
```

---

## 🔍 Detailed Agent Architecture

### **AGENT 1: External Analysis Agent**
**Purpose**: Analyze URLs, domains, and external threat indicators

**Algorithms Used:**
- **Support Vector Machine (SVM)** - URL classification (`phishing_new.pkl`)
  - Detects malicious URLs through pattern recognition
  - Trained on phishing URL dataset
  - Vectorized using TF-IDF features
- **Sentence Transformers (MiniLM-L6-v2)** - Semantic embedding
  - Encodes domain names for similarity comparison
  - Detects homoglyph attacks and domain impersonation

**Input Flow:**
```
Preprocessed URLs → Extract domain/TLD → Check patterns → 
Run through SVM ML model → Calculate risk weights → Output: url_risk, url_ml_risk
```

**Key Detections:**
- Suspicious TLDs (`.xyz`, `.top`, `.club`)
- IP addresses instead of domain names
- URL shortening services
- Domain similarity to legitimate brands (brand spoofing)
- Suspicious keywords in URLs

---

### **AGENT 2: Content Analysis Agent**
**Purpose**: Analyze email/text content for phishing, spam, and other threats

**Algorithms Used:**
- **Multinomial Naive Bayes (MNB)** - Spam/Phishing classification (`model_new.pkl`)
  - Legacy ML model using TF-IDF vectorization (`vectorizer_new.pkl`)
  - Fast, interpretable probabilistic classification
  - Trained on spam_detection_dataset.csv and phishing_email_dataset.csv
  
- **Logistic Regression** - Text risk scoring (via scikit-learn)
  - Part of the scikit-learn pipeline for baseline comparison
  - Outputs probability scores for text classification

- **DeBERTa (Transformer)** - Deep contextual understanding
  - Microsoft's DeBERTa-v3-small for sequence classification
  - Fine-tuned on phishing indicators
  - Handles complex semantic patterns

- **Sentiment Analysis (DistilBERT)** - Tone/urgency detection
  - Detects aggressive or urgent language

**Input Flow:**
```
Cleaned text → TF-IDF vectorization → 
├─ Multinomial NB classifier (legacy) → spam_ml_score
├─ Logistic Regression baseline → baseline_prob
└─ DeBERTa transformer → phishing_probability

Also checks:
├─ Keyword matching (phishing + urgency keywords)
├─ Sentiment analysis (detects pressure tactics)
├─ Semantic divergence (text ≠ URL)
└─ AI-generated content detection
```

**Key Detections:**
- Phishing keywords: "verify", "account", "click here", "urgent"
- Urgency phrases: "immediately", "24 hours", "action required"
- AI-generated content patterns
- Semantic mismatch (link text vs. actual URL)
- Aggressive/threatening sentiment

---

### **AGENT 3: Synthesizer Agent**
**Purpose**: Aggregate all agent outputs into final risk assessment

**Algorithm:**
- **Weighted Ensemble Voting**
  - Combines scores from Agent 1, 2, and 4
  - Adjustable weights per threat type
  - Applies divergence penalties
  - Enforces minimum thresholds for high-confidence detections

**Weighted Scoring:**
```
Risk Score = 
  (Agent2.phishing_prob × 0.40) +           # Content phishing (40%)
  (Agent1.url_risk × 0.30) +                 # URL risk (30%)
  (Agent2.spam_score × 0.15) +               # Spam detection (15%)
  (Agent2.ai_generated × 0.10) +             # AI-generated content (10%)
  (Agent1.domain_similarity × 0.05) +        # Brand spoofing (5%)
  (Agent4.prompt_injection × 0.30) +         # Prompt injection (30% when detected)
  (Divergence penalty) +                      # Text ≠ URL divergence
  (Sentiment aggression × 0.10)              # Aggressive tone
```

**Risk Levels:**
- `MINIMAL`: score < 0.22
- `LOW`: 0.22 ≤ score < 0.50
- `MEDIUM`: 0.50 ≤ score < 0.80
- `HIGH`: score ≥ 0.80

---

### **AGENT 4: Prompt Injection Detection Agent**
**Purpose**: Detect AI system jailbreak and instruction override attempts

**Algorithms:**
- **DeBERTa with MNLI Fine-tuning** - Textual entailment
  - Detects contradiction patterns (indicator of instruction override)
  - Transformer-based deep learning approach
  
- **Rule-Based Pattern Matching** - Heuristic rules
  - Regex patterns for common jailbreak attempts
  - Categories: instruction_override, role_playing, privilege_escalation, jailbreak, attention_diversion

**Combined Risk:**
```
Injection Risk = (0.70 × MNLI_contradiction_prob) + (0.30 × rule_match_score)
Detected if: Risk > 0.60 threshold
```

**Attack Patterns Detected:**
- "ignore previous instructions"
- "you are now [role]" (role-playing)
- "act as [character]"
- "developer mode", "DAN mode"
- "no restrictions", "jailbreak"

---

## 📊 Inter-Agent Communication Flow

### Agent Cooperation Model

```
STEP 1: PREPROCESSING
  Input → TextPreprocessor → {cleaned_text, urls, domains}

STEP 2: PARALLEL ANALYSIS (Agents run simultaneously)
  ├─ Agent1.analyze(preprocessed_data)
  │  └─ Returns: {url_risk, url_ml_risk, domain_similarity, risk_factors}
  │
  ├─ Agent2.analyze(cleaned_text)
  │  └─ Returns: {phishing_prob, spam_score, sentiment, ai_generated_prob, 
  │               connection_score, keyword_matches, urgency_matches}
  │
  └─ Agent4.analyze(original_text)
     └─ Returns: {prompt_injection_detected, confidence, attack_categories}

STEP 3: SYNTHESIS & CONSENSUS
  SynthesizerAgent.calculate_risk_score(agent1_results, agent2_results, agent4_results)
  └─ Applies weighted ensemble voting
  └─ Checks for agreement patterns
  └─ Escalates confidence if multiple agents agree

STEP 4: THREAT CLASSIFICATION
  SynthesizerAgent.determine_threat_type(risk_score, all_agent_results)
  └─ Classifies as: Phishing, Malicious URL, Spam, Prompt Injection, etc.

STEP 5: FORENSIC EXPLANATION
  SynthesizerAgent.generate_explanation(all_results)
  └─ Provides detailed, human-readable reasoning
  └─ Cites specific evidence from each agent
```

---

## 🤖 Model Files & Machine Learning Pipeline

### Pretrained Models (Models Directory):

| File | Algorithm | Purpose | Training Data |
|------|-----------|---------|----------------|
| `model_new.pkl` | **Multinomial Naive Bayes** | Text classification (spam/phishing) | phishing_email_dataset.csv + spam_detection_dataset.csv |
| `vectorizer_new.pkl` | **TF-IDF Vectorizer** | Text feature extraction | Same as above |
| `phishing_new.pkl` | **Support Vector Machine (SVM)** | URL classification | malicious_url_dataset.csv |
| `vectorizerurl_new.pkl` | **TF-IDF Vectorizer** | URL feature extraction | Same as above |

### Transformer Models (Hugging Face):

| Model | Purpose | Architecture |
|-------|---------|--------------|
| `microsoft/deberta-v3-small` | Content classification | DeBERTa Transformer |
| `sentence-transformers/all-MiniLM-L6-v2` | Semantic embeddings | Distilled MiniLM |
| `distilbert/distilbert-base-uncased-finetuned-sst-2-english` | Sentiment analysis | DistilBERT (BERT distillation) |
| `mrm8488/deberta-v3-small-finetuned-mnli` | Prompt injection detection | DeBERTa MNLI Fine-tuned |

---

## 📥 Input Processing Pipeline

```
Raw User Input (Email Subject/Body/URL)
        │
        ▼
┌──────────────────────────┐
│  TextPreprocessor        │
├──────────────────────────┤
│  ✓ Clean whitespace      │
│  ✓ Extract URLs (regex)  │
│  ✓ Parse domains         │
│  ✓ Normalize text        │
└────────────┬─────────────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
Cleaned Text      [URLs List]
    │                 │
    ├─ Agent 2 ←──────┤
    │ (Analytics)     │
    │                 │
    └─────────────────┤ Agent 1 (URL Analysis)
                      │
                      ▼
              [Feature Extraction]
               (SVM, MNB, etc.)
```

---

## 🎯 Output & Reporting

### API Response Structure:

```json
{
  "riskLevel": "HIGH",
  "threatType": "Phishing, Malicious URL",
  "confidenceScore": 92.5,
  "riskScore": 0.8742,
  "explanation": "Multiple indicators of phishing...",
  "indicators": ["Suspicious URL detected", "Phishing keywords found"],
  "recommendations": ["Delete email", "Report to IT"],
  "detailedScores": {
    "phishingProb": 0.89,
    "spamProb": 0.12,
    "urlRisk": 0.85,
    "promptInjectionScore": 0.15,
    "promtInjectionDetected": false
  }
}
```

---

## 🔧 Configuration & Weights

### Agent Weighting (in SynthesizerAgent):

```python
weights = {
    'phishing': 0.40,           # Content-based phishing indicators
    'url_risk': 0.30,           # URL/Domain analysis
    'spam': 0.15,               # Spam detection
    'ai_generated': 0.10,       # AI-generated content
    'domain_similarity': 0.05,  # Brand impersonation
    'prompt_injection': 0.30    # AI system attacks
}
```

### Risk Thresholds:

```python
thresholds = {
    'low': 0.22,
    'medium': 0.50,
    'high': 0.80
}
```

---

## 🚀 Deployment Architecture

### Frontend (Next.js)
- Dashboard for email analysis
- Real-time threat reporting
- Scanning history & policies

### Backend (Flask/Gradio)
- REST API endpoint: `/api/analyze`
- Gradio UI for testing
- Multi-threading for parallel agent analysis

### Data Flow:
```
Next.js Frontend
      │
      ├── User input
      │
      ▼
Flask Backend (app.py)
      │
      ├─ Preprocess
      │
      ├─ Parallel Agent Analysis
      │  ├─ Agent 1
      │  ├─ Agent 2
      │  └─ Agent 4
      │
      ├─ Synthesize Results (Agent 3)
      │
      └─▶ API Response JSON
           │
           ▼
       Next.js Frontend (Display Results)
```

---

## 📈 Performance Metrics

- **Agent Runtime**: ~300-500ms (sequential)
- **Parallel Runtime**: ~150-250ms (parallel agents)
- **Model Load Time**: ~2-5 seconds
- **Accuracy**: 85-92% on benchmark datasets

---

## 🔐 Security Considerations

1. **Model Integrity**: Pretrained models are immutable
2. **Input Sanitization**: Text preprocessing prevents injection
3. **Rate Limiting**: API endpoints have rate limits
4. **Audit Logging**: All analyses are logged
5. **Multi-layer Detection**: Agreement from multiple agents reduces false positives

---

## 📚 Key References

- **Machine Learning Models**: Scikit-learn (SVM, Multinomial NB, Logistic Regression)
- **Transformers**: Hugging Face Transformers library
- **Embeddings**: Sentence-Transformers for semantic understanding
- **Feature Engineering**: TF-IDF vectorization for text and URLs

---

**Last Updated**: March 2026  
**Version**: 2.0 (Multi-Agent Architecture)
