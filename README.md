# 🛡️ AegisAI - Multi-Agent Threat Detection & Phishing Shield

AegisAI is a premium, real-time threat-monitoring and phishing prevention system. It features a Next.js threat dashboard, a Flask-based Python inference bridge serving multi-agent models, and a high-performance browser extension that intercepts and analyzes links instantly.

---

## 🚀 High-Performance Browser Extension

The AegisAI browser extension provides **on-the-fly, zero-latency phishing protection** as you browse. 

### ⚡ Sub-Millisecond Scraping & Speed Features
- **Event-Driven Scraping**: The extension hooks into page-level `mouseover` (hover) and `click` events using capture-phase event listeners. Scraping is triggered automatically *only* when users interact with links, avoiding unnecessary bulk scraping or page performance degradation.
- **Background Async Analysis**: When a link is hovered, a non-blocking asynchronous request is dispatched to the service worker (`background.js`), which queries the backend. The UI remains fully responsive.
- **Sub-Millisecond Cache**: A local in-memory cache (`Map`) in the background script stores previous analysis verdicts. Repeated hover/click actions on the same URL are resolved in **0ms** without hitting the network or backend.
- **Batch Scanning (`scanAllLinks`)**: Allows users to scan all links on a webpage with a single click, appending risk badges directly onto target page anchors.
- **Active Click Interception**: If a link is flagged as **HIGH RISK**, the extension blocks navigation in the capture phase, requiring explicit user confirmation before navigating.

---

## 🧠 Multi-Agent Risk Scoring Engine

The backend relies on a **4-Agent Ensemble System** combining legacy machine learning models (fast & interpretable) and modern Deep Learning Transformers (highly semantic).

```
User Input / Link 
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│              Preprocessed & Tokenized                   │
└─────────────────────────┬───────────────────────────────┘
                          │ (Parallel Execution)
     ┌────────────────────┼────────────────────┐
     ▼                    ▼                    ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Agent 1    │     │   Agent 2    │     │   Agent 4    │
│ External/URL │     │   Content    │     │ Prompt Inj.  │
│ (SVM, Cosine)│     │ (NB, DeBERTa)│     │(DeBERTa-MNLI)│
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       └───────────┐        │        ┌───────────┘
                   ▼        ▼        ▼
             ┌──────────────────────────┐
             │         Agent 3          │
             │    Synthesizer Agent     │ (Weighted Ensemble Score)
             └──────────────┬───────────┘
                            ▼
                    [Final Threat Report]
```

### The 5-Agent Breakdown
1. **Agent 1 (External Analyst)**: Uses **SVM + TF-IDF**, **SequenceMatcher** (fuzzy string matching), Cosine Similarity, and regex heuristics to compute `url_risk` and spot domain spoofing (homoglyph/typosquatting).
2. **Agent 2 (Content Analyst)**: Uses a hybrid ensemble of **Multinomial Naive Bayes / Logistic Regression** (30%) + **DeBERTa-v3-Small** (70%), along with **DistilBERT** for urgency/threat sentiment and **MiniLM-L6-v2** embeddings to check text-to-URL semantic divergence.
3. **Agent 4 (Prompt Injection Detector)**: Leverages a fine-tuned **DeBERTa-v3 MNLI** model paired with rule-based heuristics (70% model + 30% rules) to detect prompt injection/jailbreak attempts.
4. **Agent 5 (Store Trust Analyst)**: Evaluates e-commerce storefront authenticity, suspicious discounting, refund policy presence, whois domain age, and fake social proof cues.
5. **Agent 3 (Synthesizer)**: Combines individual scores using a weighted consensus logic.

### ⚖️ Weighted Scoring Algorithm & Multipliers
The Synthesizer (`Agent 3`) aggregates scores based on the following model weights:

| Threat Category | Weight | Description |
| :--- | :--- | :--- |
| **Phishing Probability** | `0.40` | Overall semantic phishing likelihood |
| **URL Risk** | `0.30` | Heuristics & ML evaluations of the target link |
| **Prompt Injection** | `0.30` | Malicious prompt hijack attempts (High impact) |
| **Spam Probability** | `0.15` | Mass mail content indicators |
| **AI-Generated Content** | `0.10` | Automated scam copy generation markers |
| **Domain Similarity** | `0.05` | Likelihood of brand typosquatting or impersonation |

#### 🛡️ Adjustments & Multipliers:
- **Trust Multiplier (`0.5x`)**: If the domain matches a trusted whitelist, content-based threats (phishing, spam, AI content) are scaled down by half to prevent false positives.
- **Semantic Divergence Penalty**: If there is a mismatch between the link text and the destination URL (e.g., text says "PayPal Log In" but destination is "scam-domain.xyz"), a penalty is applied, increasing the risk score by up to `0.20`.
- **Urgency/Hostility Booster**: If an aggressive or high-pressure tone is detected via sentiment analysis, the threat score receives a `+0.10` bump.
- **Safety override**: Any detected prompt injection immediately overrides the score to a minimum of `0.70` (High Risk).

#### 📊 Risk Classification:
- **HIGH RISK**: Score $\ge 0.8$ 🔴 (Blocks navigation and issues modal warnings)
- **MEDIUM RISK**: Score $\ge 0.5$ 🟠
- **LOW RISK**: Score $\ge 0.22$ 🟡
- **MINIMAL/SAFE**: Score $< 0.22$ 🟢

---

## 🛠️ Technology Stack

- **Frontend**: Next.js 15 (App Router), React, TailwindCSS, Lucide Icons
- **Backend Bridge**: Python 3.10+, Flask, Flask-CORS, Gradio
- **Machine Learning**: HuggingFace Transformers (`deberta-v3`, `distilbert`, `minilm`), Scikit-Learn (`MultinomialNB`, `SGDClassifier`, `TF-IDF`), PyTorch
- **Browser Extension**: Manifest V3, Web Extensions API, Chrome Storage, Service Workers

---

## 📦 Getting Started

### 1. Prerequisites
- Node.js 18+ & `npm`/`pnpm`
- Python 3.10+
- A Google Cloud Project with the Gmail API enabled (for dashboard integration)

### 2. Installation
Clone the repository and install the Next.js dependencies:
```bash
pnpm install
```

Install the Python backend dependencies:
```bash
pip install -r requirements.txt
```

### 3. Running the System

Start the Flask bridge server (loads the AI models into memory once for low-latency inference):
```bash
python ai_agent/bridge.py
```

Start the Next.js threat dashboard:
```bash
pnpm dev
```

### 4. Installing the Browser Extension
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** (top-left).
4. Select the `extension` folder inside this repository.
5. Hover over any link or right-click to analyze suspicious content!
