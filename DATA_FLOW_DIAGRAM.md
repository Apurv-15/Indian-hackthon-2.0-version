# 🔄 AegisAI Data Flow & Architecture Diagrams

## Complete System Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER INPUT                                     │
│                  (Email Body / URL / Text Message)                      │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
                    ╔═════════════════════╗
                    ║   PREPROCESSOR      ║
                    ║                     ║
                    ║  • Clean text       ║
                    ║  • Extract URLs     ║
                    ║  • Parse domains    ║
                    ║  • Normalize        ║
                    ╚─────────┬───────────╝
                              │
                ┌─────────────┼─────────────┐
                │             │             │
                ▼             ▼             ▼
            Cleaned       URLs       Domains
             Text        List        List
                │             │             │
        ┌───────┼─────────────┼─────────────┼────────┐
        │       │             │             │        │
        ▼       ▼             ▼             ▼        ▼
     
      ┌──────────────────────────────────────────────────────┐
      │        PARALLEL MULTI-AGENT ANALYSIS                 │
      └──────────────────────────────────────────────────────┘
      
      ┌─────────────────────┐
      │    AGENT 1          │
      │  EXTERNAL ANALYSIS  │  ◄─── URLs, Domains
      │                     │
      │  ALGORITHMS:        │
      │  • SVM (Pickle)     │  ml_model: phishing_new.pkl
      │  • TF-IDF Features  │  vectorizer: vectorizerurl_new.pkl
      │  • Embeddings       │  transformer: sentence-transformers
      │  • Sequence Match   │  algorithm: SequenceMatcher
      │                     │
      │  OUTPUTS:           │
      │  ├─ url_risk        │  (0-1, from heuristics)
      │  ├─ url_ml_risk     │  (0-1, from SVM + TF-IDF)
      │  ├─ domain_similarity│ (0-1, fuzzy matching)
      │  └─ risk_factors    │  (list of reasons)
      └──────────┬──────────┘
                 │
     ┌───────────┴──────────────────────────┬─────────────────────┐
     │                                      │                     │
     ▼                                      ▼                     ▼
     
  ┌─────────────────────────┐   ┌─────────────────────────┐  ┌──────────────┐
  │    AGENT 2              │   │    AGENT 3              │  │   AGENT 4    │
  │  CONTENT ANALYSIS       │   │  SYNTHESIZER            │  │   PROMPT     │
  │                         │   │  (NOT YET SHOWN)        │  │  INJECTION   │
  │  ALGORITHMS:            │   │                         │  │              │
  │  • MNB (Pickle)         │   │                         │  │  ALGORITHMS: │
  │  • TF-IDF Features      │   │                         │  │  • DeBERTa   │
  │  • DeBERTa Transformer  │   │                         │  │    MNLI      │
  │  • DistilBERT (Sent)    │   │                         │  │  • Regex     │
  │  • MiniLM Embeddings    │   │                         │  │    Patterns  │
  │  • Pattern Matching     │   │                         │  │              │
  │                         │   │                         │  │  OUTPUTS:    │
  │  OUTPUTS:              │   │                         │  │  ├─ injection│
  │  ├─ phishing_prob      │   │                         │  │  │  _detected │
  │  ├─ spam_prob          │   │                         │  │  ├─ confidence│
  │  ├─ ai_generated       │   │                         │  │  └─ categories│
  │  ├─ sentiment_label    │   │                         │  └──────┬───────┘
  │  ├─ keyword_matches    │   │                         │         │
  │  ├─ urgency_matches    │   │                         │         │
  │  └─ connection_score   │   │                         │         │
  └──────────┬─────────────┘   │                         │         │
             │                 │                         │         │
             └─────────────────┴─────────────────────────┴─────────┘
                                 │
                                 ▼
                        ╔═════════════════════════════╗
                        ║      AGENT 3                ║
                        ║    SYNTHESIZER              ║
                        ║   (Aggregator)              ║
                        ║                             ║
                        ║  ALGORITHM:                 ║
                        ║  • Weighted Ensemble        ║
                        ║    Voting                   ║
                        ║                             ║
                        ║  INPUT:                     ║
                        ║  ├─ Agent 1 Results         ║
                        ║  ├─ Agent 2 Results         ║
                        ║  └─ Agent 4 Results         ║
                        ║                             ║
                        ║  SCORING:                   ║
                        ║  risk_score =               ║
                        ║  (url_risk × 0.30) +        ║
                        ║  (phishing × 0.40) +        ║
                        ║  (spam × 0.15) +            ║
                        ║  (ai_gen × 0.10) +          ║
                        ║  (domain_sim × 0.05) +      ║
                        ║  (injection × 0.30) +       ║
                        ║  divergence_penalty +       ║
                        ║  sentiment_aggression        ║
                        ║                             ║
                        ║  OUTPUT:                    ║
                        ║  ├─ risk_score (0-1)        ║
                        ║  ├─ risk_level              ║
                        ║  │  (MINIMAL/LOW/MED/HIGH) │
                        ║  ├─ threat_types            ║
                        ║  └─ forensic_explanation    ║
                        ╚──────────┬──────────────────╝
                                   │
                                   ▼
                    ╔═════════════════════════════╗
                    ║   FINAL THREAT REPORT       ║
                    ║                             ║
                    ║  {                          ║
                    ║    riskLevel: \"HIGH\",        ║
                    ║    threatType: \"Phishing\",  ║
                    ║    confidence: 0.92,        ║
                    ║    reasons: [...],          ║
                    ║    recommendations: [...]   ║
                    ║  }                          ║
                    ╚──────────┬──────────────────╝
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
          [Gradio UI]    [Next.js API]   [JSON Output]
```

---

## Algorithm Decision Flow (Per Agent)

### **AGENT 1: External Analysis Flow**

```
URL Input
    │
    ├─► Heuristic Pattern Check
    │   ├─ Suspicious TLD? → +0.3 risk
    │   ├─ IP address? → +0.4 risk
    │   ├─ Shortener service? → +0.3 risk
    │   ├─ Suspicious keywords? → +0.1 risk
    │   └─ Result: Initial Risk Score
    │
    ├─► ML Classification
    │   ├─ TF-IDF Vectorization
    │   └─ SVM Prediction → Probability (0-1)
    │
    ├─► String Similarity
    │   ├─ Extract domain
    │   ├─ SequenceMatcher.ratio() against known legit domains
    │   └─ Similarity Score (0-1)
    │
    ├─► Semantic Embeddings
    │   ├─ Encode URL patterns
    │   ├─ Encode phishing patterns
    │   └─ Cosine Similarity → Pattern Match
    │
    └─► FINAL OUTPUT
        ├─ url_risk (heuristic-based)
        ├─ url_ml_risk (SVM prediction)
        ├─ domain_similarity (fuzzy match)
        └─ risk_factors (list of detected issues)
```

### **AGENT 2: Content Analysis Flow**

```
Text Input
    │
    ├─► Pattern Analysis (Fast)
    │   ├─ Keyword spotting (phishing, urgency, personal info)
    │   ├─ Urgency phrase detection
    │   ├─ Personal information requests
    │   └─ Pattern Score (0-1)
    │
    ├─► Legacy ML Classification (TF-IDF + MNB)
    │   ├─ TF-IDF Vectorization
    │   ├─ Multinomial Naive Bayes Prediction
    │   └─ Probability Score (0-1)
    │
    ├─► Deep Learning (DeBERTa Transformer)
    │   ├─ Tokenize text
    │   ├─ Run through transformer
    │   └─ Classification Score (0-1)
    │
    ├─► Ensemble Combination
    │   ├─ DeBERTa weight: 70%
    │   ├─ MNB weight: 30%
    │   └─ Combined Phishing Score
    │
    ├─► Sentiment Analysis
    │   ├─ DistilBERT encoding
    │   ├─ Positive/Negative classification
    │   └─ Urgency Detection
    │
    ├─► Semantic Connection Analysis
    │   ├─ MiniLM encoding (text)
    │   ├─ MiniLM encoding (URLs)
    │   ├─ Cosine Similarity → Connection Score
    │   └─ Divergence Detection
    │
    └─► FINAL OUTPUT
        ├─ phishing_probability
        ├─ spam_probability
        ├─ ai_generated_probability
        ├─ sentiment_label & score
        ├─ keyword_matches
        ├─ urgency_matches
        └─ connection_score
```

### **AGENT 4: Prompt Injection Detection Flow**

```
Text Input
    │
    ├─► Rule-Based Pattern Matching (Fast)
    │   ├─ Check 20+ regex patterns
    │   ├─ Categorize detected patterns
    │   ├─ Count matches
    │   └─ Rule Score (0 to 3.0, capped at 1.0)
    │
    ├─► Transformer Inference (DeBERTa MNLI)
    │   ├─ Tokenize input
    │   ├─ Run through model
    │   ├─ Get class probabilities:
    │   │   ├─ [0] Entailment (coherent)
    │   │   ├─ [1] Neutral (unrelated)
    │   │   └─ [2] Contradiction (SUSPICIOUS!)
    │   └─ Contradiction Probability
    │
    ├─► Ensemble Combination
    │   ├─ Transformer (70%): contradiction_prob
    │   ├─ Rule-based (30%): pattern_score
    │   ├─ Combined Risk = (0.70 × contr) + (0.30 × rules)
    │   └─ Risk Score (0-1 scale)
    │
    └─► FINAL OUTPUT
        ├─ prompt_injection_detected (boolean)
        ├─ confidence (0-1 scale)
        ├─ matched_patterns (list)
        ├─ attack_categories (list)
        └─ explanation (human-readable)
```

---

## Agent Communication & Consensus Model

```
Agent 1 Report          Agent 2 Report          Agent 4 Report
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│ url_risk:0.8 │       │ phishing:0.75│       │ injection:   │
│ domain_sim:  │       │ spam: 0.2    │       │ 0.15         │
│ 0.6          │       │ ai_gen: 0.1  │       │ patterns:    │
│              │       │ sentiment:   │       │ [pattern1]   │
│              │       │ NEGATIVE     │       │              │
│              │       │ connection:  │       │              │
│              │       │ 0.35 (HIGH   │       │              │
│              │       │ DIVERGENCE)  │       │              │
└──┬───────────┘       └───┬──────────┘       └──┬───────────┘
   │                       │                     │
   └───────────────────────┼─────────────────────┘
                           │
                    AGENT 3 CONSENSUS:
                   (Weighted Voting)
                           │
            ┌──────────────┴──────────────┐
            │                             │
            ▼                             ▼
     ╔═════════════════╗         ╔══════════════════╗
     ║  CONSENSUS      ║         ║  EVIDENCE        ║
     ║  Score = 0.874  ║         ║                  ║
     ║  Level = HIGH   ║         ║  • Agent 1       ║
     ║  Types =        ║         ║    agrees on     ║
     ║  [Phishing,     ║         ║    URL risk      ║
     ║  Malicious URL] ║         ║  • Agent 2       ║
     ║                 ║         ║    with content  ║
     ║                 ║         ║    signals       ║
     ║                 ║         ║  • Agent 4       ║
     ║  Confidence:    ║         ║    low-risk on   ║
     ║  92% (multiple  ║         ║    injection     ║
     ║   agents agree) ║         ║  • Text ≠ URL    ║
     ║                 ║         ║    (divergence)  ║
     ╚═════════════════╝         ╚══════════════════╝
            │
            ▼
    FINAL THREAT REPORT
    └─ Risk Level: HIGH
    └─ Type: Phishing Attack + Malicious URL
    └─ Confidence: 92%
    └─ Forensic Reasons:
       • Malicious URL structure detected by SVM model
       • Phishing keywords found (verify account, click here)
       • Domain similar to legitimate brand (85% match)
       • Urgent/threatening sentiment detected
       • Email text misaligned with URL destination
    └─ Recommendations:
       • Delete email immediately
       • Report to IT security
       • Block sender domain
```

---

## Model Interaction Timeline

```
T=0ms    User submits text/URL
          │
T=5ms     Preprocessing (fast)
          │
T=10ms    ┌─ Agent 1: URL Analysis (parallel)
T=150ms   │  ├─ Heuristics (1ms)
          │  ├─ SVM ML (20ms)
          │  └─ Embeddings (30ms)
          │
          ├─ Agent 2: Content Analysis (parallel)
          │  ├─ Pattern Matching (2ms)
          │  ├─ TF-IDF + MNB (15ms)
          │  ├─ DeBERTa Transformer (80ms)
          │  ├─ Sentiment (30ms)
          │  └─ MiniLM Similarity (20ms)
          │
          └─ Agent 4: Prompt Injection (parallel)
             ├─ Rule Patterns (1ms)
             └─ DeBERTa MNLI (20ms)
          │
T=160ms   Agent 3: Synthesize Results
          ├─ Load agent outputs
          ├─ Apply weights
          ├─ Calculate risk score
          ├─ Determine threat type
          └─ Generate explanation
          │
T=200ms   ◄─ Final Report Ready
```

---

## Scoring Aggregation (Agent 3 Detailed)

```
INPUT SCORES FROM AGENTS:
┌────────────────────────────────────────────┐
│ Agent 1:                                   │
│ • url_risk = 0.75                          │
│ • url_ml_risk = 0.82                       │
│ • domain_similarity = 0.60                 │
│                                            │
│ Agent 2:                                   │
│ • phishing_probability = 0.80              │
│ • spam_probability = 0.15                  │
│ • ai_generated_probability = 0.08          │
│ • connection_score = 0.35 (divergence!)    │
│ • sentiment: NEGATIVE (0.88)                │
│                                            │
│ Agent 4:                                   │
│ • prompt_injection_detected = false        │
│ • confidence = 0.15                        │
└────────────────────────────────────────────┘
                    │
                    ▼
WEIGHTED CALCULATION:
┌────────────────────────────────────────────┐
│ Risk Score =                               │
│                                            │
│ max(0.75, 0.82) × 0.30          = 0.246   │  (URL 30%)
│ 0.80 × 0.40                      = 0.320   │  (Phishing 40%)
│ 0.15 × 0.15                      = 0.0225  │  (Spam 15%)
│ 0.08 × 0.10                      = 0.008   │  (AI-Gen 10%)
│ 0.60 × 0.05                      = 0.030   │  (Domain Sim 5%)
│ 0.15 × 0.30                      = 0.045   │  (Injection 30%)
│ (0.4 - 0.35) × 0.5               = 0.025   │  (Divergence Penalty)
│ 0.88 × 0.10                      = 0.088   │  (Negative Sentiment)
│                                            │
│ TOTAL RISK SCORE              = 0.7745     │
│ (Capped at 1.0)               = 0.7745     │
└────────────────────────────────────────────┘
                    │
                    ▼
RISK LEVEL CLASSIFICATION:
┌────────────────────────────────────────────┐
│ Threshold MINIMAL: < 0.22                  │
│ Threshold LOW:     0.22 - 0.50             │
│ Threshold MEDIUM:  0.50 - 0.80             │
│                                            │
│ Score 0.7745 falls in MEDIUM range         │
│ BUT: Prompt injection has "max" constraint │
│ If injection detected → force HIGH         │
│                                            │
│ FINAL LEVEL: MEDIUM (HIGH tendency)        │
│ Confidence: 88% (multiple agents agree)    │
└────────────────────────────────────────────┘
```

---

**Last Updated**: March 2026  
**Version**: 2.0 - Complete Multi-Agent Architecture
