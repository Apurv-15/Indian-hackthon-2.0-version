# 🛡️ AegisAI — Multi-Agent Threat Detection, Phishing Shield & Store Legitimacy Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15.0-black.svg)](https://nextjs.org/)
[![Chrome Extension](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-green.svg)](https://developer.chrome.com/docs/extensions/mv3/)
[![HuggingFace Transformers](https://img.shields.io/badge/HuggingFace-DeBERTa%20%7C%20DistilBERT-yellow.svg)](https://huggingface.co/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**AegisAI** is a real-time, hybrid multi-agent cybersecurity intelligence platform designed to protect consumers and enterprises from modern web threats: **phishing emails, zero-day malicious URLs, adversarial prompt injections, and counterfeit e-commerce stores**.

It combines a **Manifest V3 High-Performance Browser Extension**, a **Flask/Gunicorn Python Inference Bridge**, and a **Next.js 15 Threat Intelligence Dashboard** powered by a **5-Agent Machine Learning & Transformer Consensus Pipeline**.

---

## 📑 Table of Contents
- [System Architecture](#-system-architecture)
- [The 5-Agent Risk Scoring Engine](#-the-5-agent-risk-scoring-engine)
- [High-Performance Browser Extension](#-high-performance-browser-extension)
- [Zero-Cost Review Scraper (`curl_cffi` Engine)](#-zero-cost-review-scraper-curl_cffi-engine)
- [Advanced E-Commerce Store Legitimacy Classification](#-advanced-e-commerce-store-legitimacy-classification)
- [Latency Optimization: How We Achieve Real-Time Inference](#-latency-optimization-how-we-achieve-real-time-inference)
- [Accuracy Engineering: Progression & Empirical Benchmarks](#-accuracy-engineering-progression--empirical-benchmarks)
- [Repository Structure](#-repository-structure)
- [Quick Start Guide](#-quick-start-guide)
- [Complete Documentation Suite](#-complete-documentation-suite)

---

## 🏛️ System Architecture

```
                                  [ User Browsing / Link Interaction / Email Input ]
                                                          │
                       ┌──────────────────────────────────┴──────────────────────────────────┐
                       ▼                                                                     ▼
         [ Chrome Browser Extension (MV3) ]                                    [ Next.js Threat Dashboard ]
         - Event-Driven Hover/Click Interception                               - Manual Threat Investigation
         - 200-Entry LRU Cache (0ms Instant Hits)                              - Deep Forensic Timeline
         - Floating Glassmorphic Trust Shield Badge                            - Live System Telemetry
                       │                                                                     │
                       └──────────────────────────────────┬──────────────────────────────────┘
                                                          ▼
                                      [ Python WSGI Bridge (Gunicorn / Flask) ]
                                      - Port 5001 (`http://127.0.0.1:5001`)
                                      - Preprocessing & URL Scoping Normalization
                                                          │
                                     ┌────────────────────┴────────────────────┐
                                     │     Threaded Concurrent Execution       │
                                     ▼                                         ▼
                     ┌───────────────────────────────┐         ┌───────────────────────────────┐
                     │ Agent 1: External URL Analyst │         │   Agent 2: Content Analyst    │
                     │ - Char N-gram Logistic / SVM  │         │ - Hybrid: MNB (30%) +         │
                     │ - SequenceMatcher Spoofing    │         │   DeBERTa-v3 (70%)            │
                     │ - Host/Subdomain Whitelist    │         │ - DistilBERT Threat Sentiment │
                     └───────────────┬───────────────┘         │ - MiniLM Semantic Divergence  │
                                     │                         └───────────────┬───────────────┘
                                     │                                         │
                                     ├─────────────────────────────────────────┤
                                     ▼                                         ▼
                     ┌───────────────────────────────┐         ┌───────────────────────────────┐
                     │  Agent 4: Prompt Injection    │         │ Agent 5: Store Trust Analyst  │
                     │ - DeBERTa-v3 MNLI Model       │         │ - MCA CIN / Entity Registry   │
                     │ - 20+ Heuristic Rule Engine   │         │ - Gateway Merchant KYC Audit  │
                     │ - Adversarial Jailbreak Guard │         │ - Multi-Source TLS Scraping   │
                     └───────────────┬───────────────┘         └───────────────┬───────────────┘
                                     │                                         │
                                     └────────────────────┬────────────────────┘
                                                          ▼
                                        ┌───────────────────────────────────┐
                                        │    Agent 3: Synthesizer Agent     │
                                        │ - Weighted Ensemble Risk Formula  │
                                        │ - Anchor-Text Divergence Penalty  │
                                        │ - Natural Language Explanations   │
                                        └─────────────────┬─────────────────┘
                                                          ▼
                                            [ Unified Threat Verdict JSON ]
```

---

## 🧠 The 5-Agent Risk Scoring Engine

### 1. Agent 1: External URL & Domain Analyst (`agent1_external.py`)
- **Primary Function**: Spots deceptive domains, typosquatting, homoglyph substitutions (`g00gle.com`), malicious top-level domains (TLDs like `.xyz`, `.top`, `.club`, `.bid`), and IP-based hostnames.
- **Algorithms**:
  - **Character N-Gram Classifier**: Scikit-Learn TF-IDF (`char_wb`, n-grams 3 to 5) feeding a tuned Logistic Regression / SVM baseline.
  - **Fuzzy String Matching**: Python `difflib.SequenceMatcher` calculating token distance against top target brands (Google, PayPal, Apple, Amazon, Microsoft, Netflix, SBI, HDFC).
  - **Host vs. Path Scoping**: Strictly isolates `netloc` to prevent news URLs (e.g. `theverge.com/apple-iphone-review`) from triggering brand impersonation alerts.
- **Runtime**: **~20ms–50ms**.

### 2. Agent 2: Content & Semantic Analyst (`agent2_content.py`)
- **Primary Function**: Evaluates communication text for urgency, credential theft, and emotional coercion.
- **Algorithms**:
  - **Hybrid Ensemble**: 30% Classical Multinomial Naive Bayes (MNB) + 70% `microsoft/deberta-v3-small` for deep bidirectional context.
  - **Urgency & Threat Sentiment**: DistilBERT (`distilbert-base-uncased-finetuned-sst-2-english`) detecting aggressive and coercive phrasing (*"Account suspended in 2 hours"*).
  - **Semantic Divergence**: Sentence-Transformers `all-MiniLM-L6-v2` calculating cosine distance between email body context and target URL semantics.
- **Runtime**: **~80ms–150ms**.

### 3. Agent 3: Synthesizer & Consensus Engine (`agent3_synthesizer.py`)
- **Primary Function**: Acts as Chief Risk Officer, combining verdicts from all agents with dynamic contextual adjustments.
- **Risk Aggregation Equation**:
  $$\text{Risk Score} = (0.30 \times R_{\text{URL}}) + (0.40 \times R_{\text{Phish}}) + (0.15 \times R_{\text{Spam}}) + (0.10 \times R_{\text{AI}}) + (0.05 \times R_{\text{Spoof}}) + \Delta_{\text{Divergence}} + \Delta_{\text{Urgency}}$$
- **Risk Level Scale**:
  - `MINIMAL` ($< 0.22$) | `LOW` ($0.22 - 0.50$) | `MEDIUM` ($0.50 - 0.80$) | `HIGH` ($\ge 0.80$)
- **Runtime**: **~5ms**.

### 4. Agent 4: Prompt Injection & Adversarial Guard (`agent4_injection.py`)
- **Primary Function**: Protects downstream LLMs and autonomous agents from malicious prompt injection, jailbreaks, and system override attempts.
- **Algorithms**:
  - **Natural Language Inference (NLI)**: Fine-tuned `mrm8488/deberta-v3-small-finetuned-mnli` evaluating whether user input contradicts or overrides safety guidelines.
  - **Pattern Rules Engine**: 20+ regex patterns catching system prompt extraction, DAN mode persona switches, and privilege escalation payloads.
- **Runtime**: **~20ms**.

### 5. Agent 5: Store Trust & Consumer Sentiment Analyst (`agent5_store_trust.py`)
- **Primary Function**: Verifies legitimacy of e-commerce storefronts across 4 pillars: Corporate Entity verification (MCA CIN), Payment Gateway KYC onboarding, ICANN domain age, and multi-source consumer sentiment analysis.
- **Runtime**: **~120ms (cached) to ~1.2s (live multi-portal review scrape)**.

---

## ⚡ High-Performance Browser Extension

The AegisAI browser extension provides **real-time, zero-friction protection** without degrading browser rendering performance.

### 🚀 Key Technical Features:
1. **Event-Driven Non-Blocking Scraping**:
   - Uses capture-phase listeners on `mouseover` and `click` on hyperlink elements (`<a>`).
   - Rather than crawling and analyzing hundreds of links on page load, links are inspected **only when the user interacts with them**.
2. **Two-Tier LRU & TTL Caching**:
   - `background.js` maintains a **200-entry in-memory LRU cache**. Repeated hovers or clicks on the same link resolve in **0ms** without sending network packets.
   - Store trust evaluations feature a **5-minute TTL cache**, preventing re-scraping across multi-page checkouts.
3. **Anchor-Text Divergence Interception**:
   - Detects the deceptive attack where visible text says `https://paypal.com` but destination points to `http://evil-phish.xyz`.
   - Halts the click navigation and renders an immediate alert dialog.
4. **Adaptive Glassmorphic Badge UI**:
   - Floats unobtrusively on e-commerce sites (Shopify, WooCommerce, Magento).
   - Constrained to `max-height: calc(85vh - 80px)` with `overflow-y: auto` to prevent viewport clipping on small laptop screens.
5. **Live Backend Heartbeat**:
   - Extension popup checks `http://127.0.0.1:5001/health` on open, displaying a real-time status indicator (`● Bridge: 5001 Online`).

---

## 🔥 Zero-Cost Review Scraper (`curl_cffi` Engine)

Rather than paying for commercial scraping APIs (e.g. Firecrawl, ScraperAPI), AegisAI features a **100% Free & Open-Source Review Extraction Engine**.

- **TLS Fingerprint Impersonation**: Traditional scraping libraries (`urllib`, `requests`, `axios`) receive instant 403 Forbidden responses from Cloudflare. AegisAI leverages `curl_cffi` with `impersonate="chrome120"` to replicate legitimate browser TLS handshakes and JA3 fingerprints.
- **Parallel Multi-Source Extraction**: Runs concurrent queries across:
  - **Consumer Complaints India** (`consumercomplaints.in`)
  - **MouthShut India** (`mouthshut.com`)
  - **Trustpilot** (`trustpilot.com`)
  - **DuckDuckGo HTML Engine**
- **4-Stage Sanitization Pipeline**:
  1. *Entity Unescape*: Decodes HTML entities (`&#x27;` $\to$ `'`, `&amp;` $\to$ `&`).
  2. *Tag Stripping*: Cleans residual structural tags.
  3. *Noise Rejection*: Discards boilerplate landing copy (*"Do you agree with TrustScore?"*).
  4. *Buyer-Intent Filtering*: Verifies the presence of concrete e-commerce terms (`ordered`, `refund`, `support`, `delivery`, `fake`, `defective`).

---

## 🇮🇳 Advanced E-Commerce Store Legitimacy Classification

Tailored specifically for the nuances of modern digital retail:

```
                                    [ Storefront URL ]
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             [ Enterprise Brand? ]                        [ Startup / SMB Store ]
        (Croma, Reliance, Tata, etc.)                              │
                       │                                           ▼
                       │ Yes                         ┌───────────────────────────┐
                       ▼                             │  1. Check MCA CIN / Legal │
           [ ESTABLISHED: 95-99% ]                   │  2. Payment Gateway KYC?  │
             Verified Parent Entity                  │  3. Delivery History?     │
                                                     └─────────────┬─────────────┘
                                                                   │
                                 ┌─────────────────────────────────┼─────────────────────────────────┐
                                 ▼                                 ▼                                 ▼
                     [ STARTUP_VERIFIED ]                 [ REPLICA_VERIFIED ]                  [ SCAM ALERT ]
                         (74% - 88%)                          (68% - 75%)                          (< 45%)
                   - Razorpay / Cashfree KYC            - Master / 7A Copy Seller            - Personal UPI QR Only
                   - Clear Support Contact Info         - Verified Physical Delivery         - Non-Delivery Complaints
                   - Zero Fraud Complaints              - Zero Non-Delivery Frauds           - Hidden Registration
```

### 1. 🏛️ Corporate Business Entity & MCA CIN Registry
Major Indian enterprises (Croma, Reliance Digital, Tata Cliq, Nykaa, Lenskart) do not print 15-digit GSTIN numbers on their landing pages. Instead of returning false "GSTIN Not Found" alerts, AegisAI maps enterprise domains to verified Ministry of Corporate Affairs (MCA) parent records (e.g. `croma.com` $\to$ `Infiniti Retail Ltd - A Tata Enterprise`).

### 2. 🚀 `STARTUP_VERIFIED` Status Tier (74%–88% Trust)
Emerging D2C brands cannot be judged solely by domain age (a 6-month-old brand is not inherently a scam). AegisAI validates:
- **Payment Gateway KYC**: Merchant onboarding on Razorpay, Cashfree, PayU, or Shopify Payments requires verified business PAN and bank account records.
- **Support Infrastructure**: Verified customer email, telephone helpline, and physical postal PIN code.

### 3. 📦 `REPLICA_VERIFIED` Status Tier (68%–75% Trust)
Recognizes legitimate 1st Copy / 7A Replica storefronts. If a store sells replica sneakers or electronics but **reliably fulfills customer shipments** with functional payment systems, it is marked with a distinctive purple badge rather than being penalized as a financial fraud site.

---

## ⚡ Latency Optimization: How We Achieve Real-Time Inference

| Optimization Strategy | Implementation Details | Impact on Wall-Clock Time |
| :--- | :--- | :--- |
| **True Parallel Execution** | `concurrent.futures.ThreadPoolExecutor` runs Agents 1, 2, and 4 in parallel. | Pipeline bound by max agent time (**~150ms**), down from **~450ms** sequential. |
| **Two-Tier Fast Path** | Top-1M domain whitelisting and regex heuristics bypass heavy neural passes for known safe domains. | Benign sites resolve in **< 5ms**. |
| **LRU Cache Service Worker** | 200-item memory cache in `background.js` for visited URLs. | Second interaction takes **0ms** (zero network overhead). |
| **Distilled Model Architectures** | Selected `deberta-v3-small`, `distilbert`, and `all-MiniLM-L6-v2` (384-dim). | **4x speedup** vs base/large transformer models. |
| **Warm-Loaded Singletons** | Models load once at server startup; tokenizer multiprocessing contention disabled (`TOKENIZERS_PARALLELISM=false`). | Zero per-request disk I/O and no PyTorch thread lockups. |

---

## 📈 Accuracy Engineering: Progression & Empirical Benchmarks

### 🔬 Empirical Evaluation Results (Un-Leaked 80/20 Stratified Split)

From our systematic evaluation testbed (`evaluate_unleaked.py` & `evaluate_stability_difficulty.py` across 5 random seeds: 42, 100, 2024, 777, 999):

| Task & Model | Accuracy | Precision | Recall | F1-Score | Stability ($\sigma$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **URL Classifier** (Char N-Gram Logistic / SVM) | **89.50%** | **90.48%** | **88.37%** | **89.41%** | $\pm 0.008$ |
| **Content Classifier** (Phishing + Spam Dataset) | **91.25%** | **92.10%** | **90.20%** | **91.14%** | $\pm 0.006$ |
| **Ensemble Multi-Agent Pipeline** (Hybrid + DeBERTa) | **94.80%** | **95.60%** | **94.00%** | **94.79%** | $\pm 0.004$ |
| **Prompt Injection Detection** (DeBERTa MNLI + Rules) | **85.00%** | **88.20%** | **81.50%** | **84.71%** | $\pm 0.012$ |

### 🛠️ Key Accuracy Breakthroughs:
1. **Host-vs-Path Isolation**: Solved false brand-impersonation alerts on legitimate technology reviews (e.g. `theverge.com/apple-iphone-review` is no longer flagged for containing `"apple"`).
2. **Substring Homoglyph False Positive Elimination**: Removed substring collision false positives (`pineapple.com` is no longer flagged as an Apple spoof).
3. **Anchor-Text Divergence**: Catches hidden redirection attacks where visual link text differs from the destination target.
4. **Indian ccTLD Subdomain Normalization**: Properly handles multi-part TLDs (e.g., `.co.in`, `.ac.in`), preventing CDN URLs (`assets.cdn.grovertechno.co.in`) from triggering excessive subdomain penalties.

---

## 📁 Repository Structure

```
├── README.md                           # Main Project Documentation
├── QUICK_REFERENCE.md                  # Quick Viva & Review Cheat Sheet
├── ARCHITECTURE.md                     # Comprehensive Architecture Deep-Dive
├── ALGORITHM_REFERENCE.md              # Mathematical & ML Model Specifications
├── DATA_FLOW_DIAGRAM.md                # Data Flow Traces & Visual Decision Trees
├── AGENT_COMMUNICATION_PATTERNS.md     # Protocol Contracts & Inter-Agent Schemas
├── start.sh                            # One-Click Startup Script (macOS / Linux)
├── start.ps1                           # One-Click Startup Script (Windows PowerShell)
├── requirements.txt                    # Python Dependencies
├── package.json                        # Next.js Frontend Dependencies
│
├── ai_agent/                           # Python Multi-Agent Inference Engine
│   ├── app.py                          # ThreatDetectionSystem Engine Core
│   ├── bridge.py                       # Flask / Gunicorn WSGI Microservice (Port 5001)
│   ├── agents/                         # Individual AI Agent Modules
│   │   ├── agent1_external.py          # Agent 1: URL, Homoglyph, Cosine & SVM
│   │   ├── agent2_content.py           # Agent 2: MNB + DeBERTa + DistilBERT + MiniLM
│   │   ├── agent3_synthesizer.py       # Agent 3: Consensus Weighting & Forensic Reasoning
│   │   ├── agent4_injection.py         # Agent 4: DeBERTa MNLI Prompt Injection Guard
│   │   └── agent5_store_trust.py       # Agent 5: Indian Store Legitimacy & Review Engine
│   ├── models/                         # Serialized Model Artifacts & Pretrained Weights
│   ├── data/                           # Training & Benchmark Datasets
│   ├── evaluate_latency.py             # Wall-Clock Timing & Parallel Speed Benchmark
│   ├── evaluate_pipeline.py            # End-to-End Ensemble Pipeline Evaluation
│   ├── evaluate_unleaked.py            # Stratified Un-Leaked Train/Test Metric Tests
│   ├── evaluate_stability_difficulty.py# 5-Seed Stability & Dataset Hardness Quantification
│   └── test_fixes.py                   # Regression & False Positive Verification Suite
│
├── extension/                          # Chrome Browser Extension (Manifest V3)
│   ├── manifest.json                   # Extension Manifest V3 Configuration
│   ├── background.js                   # Service Worker, 200-Entry LRU Cache & Network Interceptor
│   ├── content.js                      # Event-Driven DOM Interceptor & Badge Renderer
│   ├── content.css                     # Glassmorphic Stylesheet & Viewport Protections
│   ├── popup.html                      # Extension Popup Dashboard HTML
│   └── popup.js                        # Extension Popup Logic & Health Check
│
└── src/                                # Next.js 15 Frontend Threat Dashboard
    ├── app/                            # React App Router Pages & API Routes
    └── components/                     # Threat Radar, Signal Gauges & Log Cards
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Node.js**: v18.0 or higher
- **Python**: v3.10 or higher
- **Google Chrome** (for testing the extension)

### 2. One-Command Launch (Recommended)
Clone the repository and run the startup script:

```bash
# Clone the repository
git clone https://github.com/your-username/AegisAI.git
cd AegisAI

# On macOS / Linux:
chmod +x start.sh
./start.sh

# On Windows:
.\start.ps1
```

> **Automated Startup Behavior:**
> 1. Detects Python virtual environment (`.venv`) and installs missing dependencies.
> 2. Clears stale background processes occupying port `5001`.
> 3. Starts the Gunicorn/Flask bridge (`bridge.py`) on `http://127.0.0.1:5001`.
> 4. Waits for `/health` probe confirmation that all AI models are loaded in memory.
> 5. Launches Next.js dev server on `http://localhost:3000`.

### 3. Load the Chrome Browser Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** (top-left button).
4. Select the `extension` folder inside this repository.
5. The **AegisAI Shield** icon will appear in your Chrome toolbar.

---

## 📚 Complete Documentation Suite

For granular technical dives, consult the specialized documentation guides:

| Guide | Content Covered |
| :--- | :--- |
| ⚡ [**QUICK_REFERENCE.md**](QUICK_REFERENCE.md) | Viva & Exam cheat sheet, model runtime comparisons, parameter tuning guide. |
| 🏗️ [**ARCHITECTURE.md**](ARCHITECTURE.md) | High-level topology, component interaction, and system data contracts. |
| 🧠 [**ALGORITHM_REFERENCE.md**](ALGORITHM_REFERENCE.md) | Formulas, loss functions, embedding dimensions, and hyperparameters. |
| 📊 [**DATA_FLOW_DIAGRAM.md**](DATA_FLOW_DIAGRAM.md) | Visual sequence diagrams and decision trees for URL and Store workflows. |
| 🤝 [**AGENT_COMMUNICATION_PATTERNS.md**](AGENT_COMMUNICATION_PATTERNS.md) | In-depth agent contracts, failover recovery, and consensus mechanics. |

---

## ⚖️ License
This project is licensed under the **MIT License**.
