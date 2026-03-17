# 🧠 AegisAI Algorithm Reference Guide

## Overview
This document lists all machine learning algorithms and techniques used in the AegisAI threat detection system.

---

## Core ML Algorithms

### 1. **Multinomial Naive Bayes (MNB)**
- **Model File**: `ai_agent/models/model_new.pkl`
- **Vectorizer**: `ai_agent/models/vectorizer_new.pkl` (TF-IDF)
- **Location in Code**: [Agent 2 - Content Analysis](ai_agent/agents/agent2_content.py)
- **Purpose**: Fast probabilistic text classification for spam/phishing
- **Training Data**: 
  - `phishing_email_dataset.csv`
  - `spam_detection_dataset.csv`
- **Features**: TF-IDF weighted term frequencies
- **Output**: Probability of spam/phishing (0-1)
- **Advantages**: 
  - Fast inference
  - Interpretable probabilistic model
  - Works well with sparse features
- **Why Used**: Baseline model for quick threat assessment

---

### 2. **Support Vector Machine (SVM)**
- **Model File**: `ai_agent/models/phishing_new.pkl`
- **Vectorizer**: `ai_agent/models/vectorizerurl_new.pkl` (TF-IDF)
- **Location in Code**: [Agent 1 - External Analysis](ai_agent/agents/agent1_external.py#L24-L30)
- **Purpose**: URL/domain classification for malicious detection
- **Training Data**: `malicious_url_dataset.csv`
- **Features**: TF-IDF features extracted from URLs
- **Output**: Probability of malicious URL (0-1)
- **Advantages**:
  - Excellent with high-dimensional sparse data
  - Robust to feature scaling
  - Strong generalization
- **Why Used**: Captures sophisticated URL patterns not visible to heuristics

---

### 3. **Logistic Regression**
- **Part Of**: Scikit-learn pipeline (alongside MNB)
- **Location in Code**: [Agent 2 - As fallback baseline](ai_agent/agents/agent2_content.py#L40-48)
- **Purpose**: Alternative probabilistic classifier for comparison
- **Training Data**: Same as Multinomial NB
- **Output**: Baseline probability for comparative validation
- **Advantages**:
  - Linear interpretability
  - Fast training and inference
  - Probabilistic output
- **Why Used**: Provides secondary validation and ensemble diversity

---

## Deep Learning / Transformer Models

### 4. **DeBERTa-v3-Small**
- **Model**: `microsoft/deberta-v3-small`
- **Location in Code**: 
  - [Agent 2 - Content Analysis](ai_agent/agents/agent2_content.py#L17-19)
  - [Agent 4 - Prompt Injection Detection](ai_agent/agents/agent4_prompt.py)
- **Purpose**: Deep contextual understanding of text threats
- **Architecture**: Transformer-based sequence classifier
- **Task**: 
  - Content phishing detection (Agent 2)
  - Natural Language Inference - MNLI (Agent 4)
- **Output**: Logit scores for classification
- **Advantages**:
  - Captures semantic nuances and context
  - Fine-tuned MNLI version detects semantic contradictions
  - Superior to traditional NLP for complex patterns
- **Why Used**: Handles sophisticated social engineering tactics

---

### 5. **DeBERTa MNLI Fine-tuned** (mrm8488/deberta-v3-small-finetuned-mnli)
- **Model**: `mrm8488/deberta-v3-small-finetuned-mnli` (via HuggingFace Hub)
- **Location in Code**: [Agent 4 - Prompt Injection](ai_agent/agents/agent4_prompt.py#L45)
- **Purpose**: Detect prompt injection via contradiction detection
- **Task**: Natural Language Inference (Textual Entailment)
- **MNLI Classes**:
  - 0 = Entailment (coherent)
  - 1 = Neutral (unrelated)
  - 2 = Contradiction (indicator of instruction override)
- **Output**: Probability distribution over 3 classes
- **Key Features**:
  - Detects contradictions between user input and system instructions
  - Identifies jailbreak patterns semantic-ally
  - Catches sophisticated prompt injections
- **Why Used**: Semantic approach catches subtle instruction override attempts

---

### 6. **DistilBERT (Sentiment Analysis)**
- **Model**: `distilbert/distilbert-base-uncased-finetuned-sst-2-english`
- **Location in Code**: [Agent 2 - Sentiment Analysis Pipeline](ai_agent/agents/agent2_content.py#L32)
- **Purpose**: Detect aggressive/urgent tone (pressure tactics)
- **Architecture**: BERT distillation (smaller, faster)
- **Task**: Sentiment classification
- **Output**: Label (POSITIVE/NEGATIVE) + confidence score
- **Why Used**: Identifies social engineering urgency and threats

---

### 7. **Sentence-Transformers MiniLM-L6-v2**
- **Model**: `sentence-transformers/all-MiniLM-L6-v2`
- **Location in Code**: 
  - [Agent 1 - Domain Similarity](ai_agent/agents/agent1_external.py#L13)
  - [Agent 2 - Connection Analysis](ai_agent/agents/agent2_content.py#L20-22, #L163-188)
- **Purpose**: Semantic similarity via dense embeddings
- **Architecture**: Distilled BERT with mean pooling
- **Output**: 384-dimensional embeddings
- **Applications**:
  - Brand similarity detection (homoglyph attacks)
  - Email text vs URL semantic alignment
- **Similarity Metric**: Cosine similarity
- **Why Used**: Captures semantic meaning for divergence attacks detection

---

## Feature Engineering Techniques

### **TF-IDF Vectorization**
- **Library**: `scikit-learn.feature_extraction.text.TfidfVectorizer`
- **Location**: 
  - Text: `vectorizer_new.pkl` (Agent 2)
  - URLs: `vectorizerurl_new.pkl` (Agent 1)
- **Purpose**: Convert text/URLs to numerical feature vectors
- **Algorithm**:
  - Term Frequency: How often word appears in document
  - Inverse Document Frequency: How rare word is across corpus
  - Combination: De-emphasizes common words, emphasizes unique terms
- **Why Used**: Works well with naive Bayes and SVM classifiers

---

## Heuristic & Pattern-Based Detection

### **Keyword Spotting**
- **Location**: [Agent 1](ai_agent/agents/agent1_external.py#L35-47), [Agent 2](ai_agent/agents/agent2_content.py#L54-65)
- **Method**: String matching against known threat indicators
- **Examples**:
  - Phishing: "verify", "account", "click here", "urgent"
  - Spam: "free", "win", "lottery", "prize"
  - Urgency: "immediately", "within 24 hours", "action required"

### **Regex Pattern Matching**
- **Location**: 
  - URLs: [Agent 1](ai_agent/agents/agent1_external.py) - IP addresses, shorteners, suspicious TLDs
  - Prompt Injection: [Agent 4](ai_agent/agents/agent4_prompt.py#L58-78)
- **Patterns**:
  - IP detection: `\d+\.\d+\.\d+\.\d+`
  - URL extraction: `http[s]?://...`
  - Jailbreak attempts: 20+ patterns

### **String Similarity Matching**
- **Algorithm**: Difflib SequenceMatcher
- **Location**: [Agent 1](ai_agent/agents/agent1_external.py#L106-116)
- **Purpose**: Fuzzy domain matching (homoglyph detection)
- **Example**: "gogle.com" vs "google.com"
- **Output**: Similarity ratio (0-1)

### **Cosine Similarity**
- **Algorithm**: Cosine similarity between embedding vectors
- **Location**: 
  - Domain similarity: [Agent 1](ai_agent/agents/agent1_external.py)
  - Connection analysis: [Agent 2](ai_agent/agents/agent2_content.py#L183)
- **Formula**: cos(θ) = (A · B) / (||A|| × ||B||)
- **Output**: Similarity score (0-1)

---

## Ensemble & Integration Methods

### **Weighted Ensemble Voting** (Agent 3 - Synthesizer)
- **Location**: [Agent 3 - Synthesizer](ai_agent/agents/agent3_synthesizer.py)
- **Purpose**: Aggregate multiple models into consensus decision
- **Weights**:
  - Phishing (Agent 2): 40%
  - URL Risk (Agent 1): 30%
  - Spam (Agent 2): 15%
  - AI-Generated (Agent 2): 10%
  - Domain Similarity (Agent 1): 5%
  - Prompt Injection (Agent 4): 30%
- **Aggregation**: Weighted sum + threshold classification
- **Output**: Final risk score (0-1) and threat type

### **Hybrid TF-IDF + Transformer Ensemble** (Agent 2)
- **Location**: [Agent 2](ai_agent/agents/agent2_content.py#L242-263)
- **Weighting**: DeBERTa (70%) + Multinomial NB (30%)
- **Rationale**: 
  - Transformer captures context
  - MNB provides stable baseline from training data
  - Combination reduces both false positives and negatives

### **Transformer + Rule-Based Ensemble** (Agent 4)
- **Location**: [Agent 4](ai_agent/agents/agent4_prompt.py)
- **Weights**: 
  - MNLI Contradiction Score: 70%
  - Rule-based Pattern Score: 30%
- **Combined Risk**: 0.70 × contradiction_prob + 0.30 × rule_score
- **Threshold**: Risk > 0.60 = Injection detected

---

## Data Preprocessing

### **Text Preprocessing** (Preprocessor Module)
- **Location**: [utils/preprocessor.py](ai_agent/utils/preprocessor.py)
- **Steps**:
  1. Whitespace normalization (collapse multiple spaces)
  2. URL extraction (regex pattern)
  3. Domain parsing (from URL)
  4. Text lowercasing (for pattern matching)

---

## Model Performance Considerations

| Algorithm | Speed | Accuracy | Interpretability | Use Case |
|-----------|-------|----------|------------------|----------|
| Multinomial NB | ⚡⚡⚡ Fast | 75-80% | ⭐⭐⭐ High | Baseline, quick inference |
| SVM | ⚡⚡ Medium | 82-88% | ⭐⭐ Medium | URL classification |
| Logistic Regression | ⚡⚡⚡ Fast | 70-75% | ⭐⭐⭐ High | Validation, comparison |
| DeBERTa Transformer | ⚡ Slower | 85-92% | ⭐ Low | Complex patterns, SOTA |
| DistilBERT | ⚡⚡ Medium | 80-85% | ⭐ Low | Sentiment, pressure detection |
| MiniLM Embeddings | ⚡⚡ Medium | - | ⭐ Low | Semantic similarity |

---

## Model Training Data

| Model | Dataset | Records | Balanced | Purpose |
|-------|---------|---------|----------|---------|
| MNB + TF-IDF | `phishing_email_dataset.csv` | ~5000 | Yes | Email phishing |
| MNB + TF-IDF | `spam_detection_dataset.csv` | ~10000 | Yes | Spam emails |
| SVM | `malicious_url_dataset.csv` | ~3000 | Yes | Malicious URLs |

---

## References

- **Scikit-learn**: https://scikit-learn.org/ (NB, SVM, TF-IDF, LR)
- **Hugging Face Transformers**: https://huggingface.co/transformers/ (DeBERTa, DistilBERT, MiniLM)
- **Sentence-Transformers**: https://www.sbert.net/ (Semantic embeddings)
- **MNLI**: https://nlp.stanford.edu/projects/snli/ (Natural Language Inference)

---

**Last Updated**: March 2026  
**Version**: 2.0 - Hybrid ML Architecture
