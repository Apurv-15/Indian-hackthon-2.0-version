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

The backend relies on a **5-Agent Ensemble System** combining legacy machine learning models (fast & interpretable) and modern Deep Learning Transformers (highly semantic).

```
User Input / Link / Storefront
              │
              ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Preprocessed & Tokenized                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Parallel Execution)
        ┌───────────────────┬───────┴───────────┬───────────────────┐
        ▼                   ▼                   ▼                   ▼
 ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
 │   Agent 1    │    │   Agent 2    │    │   Agent 4    │    │   Agent 5    │
 │ External/URL │    │   Content    │    │ Prompt Inj.  │    │ Store Trust  │
 │ (SVM, Cosine)│    │ (NB, DeBERTa)│    │(DeBERTa-MNLI)│    │ (Scam Signals│
 └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
        │                   │                   │                   │
        └─────────────┐     │                   │     ┌─────────────┘
                      ▼     ▼                   ▼     ▼
               ┌─────────────────────────────────────────┐
               │                 Agent 3                 │
               │            Synthesizer Agent            │ (Weighted Ensemble Score)
               └────────────────────┬────────────────────┘
                                    ▼
                          [Final Threat Report]
```

### The 5-Agent Breakdown
1. **Agent 1 (External Analyst)**: Uses **SVM + TF-IDF**, **SequenceMatcher** (fuzzy string matching), Cosine Similarity, WHOIS age heuristics, and PhishTank / OpenPhish lookup checks to compute `url_risk` and spot domain spoofing (homoglyph/typosquatting).
2. **Agent 2 (Content Analyst)**: Uses a hybrid ensemble of **Multinomial Naive Bayes / Logistic Regression** (30%) + **DeBERTa-v3-Small** (70%), along with **DistilBERT** for urgency/threat sentiment and **MiniLM-L6-v2** embeddings to check text-to-URL semantic divergence.
3. **Agent 4 (Prompt Injection Detector)**: Leverages a fine-tuned **DeBERTa-v3 MNLI** model paired with rule-based heuristics (70% model + 30% rules) to detect prompt injection/jailbreak attempts.
4. **Agent 5 (Store Trust Analyst)**: Evaluates e-commerce storefront authenticity, suspicious discounting (>70% off), missing contact/refund policies, WHOIS domain creation freshness, payment gateway red flags, and fake review patterns.
5. **Agent 3 (Synthesizer)**: Combines individual scores using a weighted consensus logic with dynamic contextual multipliers.

### ⚖️ Weighted Scoring Algorithm & Multipliers
The Synthesizer (`Agent 3`) aggregates scores based on the following model weights:

| Threat Category | Weight | Description |
| :--- | :--- | :--- |
| **Phishing Probability** | `0.35` | Overall semantic phishing likelihood |
| **URL Risk** | `0.25` | Heuristics & ML evaluations of target link |
| **Prompt Injection** | `0.20` | Malicious prompt hijack attempts |
| **Store Trust Risk** | `0.15` | E-commerce scam and fake storefront likelihood |
| **Spam Probability** | `0.10` | Mass mail content indicators |
| **AI-Generated Content** | `0.05` | Automated scam copy generation markers |
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

## 🆕 Recent Updates & Key Advancements (v2.0)

AegisAI has been upgraded with critical accuracy, threat intelligence, and architectural improvements:

### 1. 🎯 Live Semantic Divergence Interception
- **Anchor Text & Context Forwarding**: The browser extension now captures and transmits HTML `anchorText` and `pageUrl` during both on-hover scans and batch scans.
- **Deceptive Label Detection**: When an anchor label claims to be a trusted entity (e.g., *"Click here for PayPal Security Verification"*) but links to an unauthorized or third-party domain, Agent 2 and Agent 3 automatically apply a **Critical Divergence Penalty**, escalating the threat level to High/Critical.

### 2. 🛡️ Complete Elimination of False Positives
- **Hostname-Isolated Brand Matching**: Brand impersonation checks are now strictly confined to the domain hostname tokens. Tech reviews, blog posts, and news articles containing brand names in their path/query (e.g. `theverge.com/apple-iphone-16-pro-review`) are no longer falsely flagged.
- **Homoglyph & Leetspeak Token Parser**: Integrated character-level translation (`1->l`, `0->o`, `3->e`, `4->a`) to detect obfuscated domains (`paypa1`, `g00gle`, `amaz0n`) with 95%+ confidence while protecting legitimate dictionary roots (e.g. `pineapple.com`).
- **Authenticated Endpoint Exemption**: Legitimate authentication and account endpoints on verified domains (e.g. `github.com/account/login`) are exempted from generic keyword penalties.
- **Hostname-Only Subdomain Counting**: Subdomain depth analysis now targets only the domain host, ignoring dot-heavy query strings or static asset paths.

### 3. 🇮🇳 Expanded Indian Banking, Courier & Public Sector Protection
- Added verified brand registries for high-volume phishing targets:
  - **Banking & Fintech**: State Bank of India (`sbi`), HDFC Bank (`hdfc`), ICICI Bank (`icici`), Axis Bank (`axis`), Kotak Mahindra (`kotak`), Paytm (`paytm`), PhonePe (`phonepe`).
  - **Government & Public Utilities**: India Post (`indiapost`), Income Tax e-Filing (`incometax`), UIDAI / Aadhaar (`uidai`).
  - **Logistics, Couriers & Crypto**: Shiprocket (`shiprocket`), BlueDart (`bluedart`), Binance (`binance`), MetaMask (`metamask`).

### 4. ⚡ Protocol Auto-Normalization & Performance
- **Naked URL Support**: The preprocessor automatically detects and normalizes raw domain inputs (e.g., `paypa1-security.xyz/verify`) into fully qualified URLs so they are routed through Agent 1's full threat pipeline instead of plain text embeddings.
- **Sub-100ms Hover Latency**: Replaced blocking HTTP probes with in-memory host resolution caching and tight 1.5s timeout fallbacks.
- **Unified One-Click Startup**: Added automated `start.sh` (Linux/macOS) and `start.ps1` (Windows) scripts with automated cache clearing, model readiness polling, and graceful process teardown.

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

#### ⚡ Quick Start (Recommended — One Command)

You can launch both the **Python AI Inference Engine** and the **Next.js Threat Dashboard** simultaneously using the automated startup script:

**On Linux / macOS:**
```bash
# Ensure execution permissions (first time only)
chmod +x start.sh

# Run the unified system
./start.sh
```

**On Windows (PowerShell):**
```powershell
.\start.ps1
```

> **What `start.sh` does automatically:**
> 1. Cleans up previous `.pycache`, `.next`, and log caches.
> 2. Detects your virtual environment (`.venv` / `venv` / system `python3`).
> 3. Launches the Flask AI bridge server on port `5001` in the background.
> 4. Health-checks `http://localhost:5001/health` until ML transformer models are loaded into memory.
> 5. Launches the Next.js dev server (`npm run dev`) on `http://localhost:3000`.
> 6. Handles graceful shutdown of all backend processes upon `Ctrl+C`.

---

#### 🛠️ Manual Startup (Alternative)

If you prefer running services in separate terminal windows:

**Terminal 1 — Python AI Inference Bridge:**
```bash
python ai_agent/bridge.py
```

**Terminal 2 — Next.js Dashboard:**
```bash
npm run dev
# or: pnpm dev
```


### 4. Installing the Browser Extension
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** (top-left).
4. Select the `extension` folder inside this repository.
5. Hover over any link or right-click to analyze suspicious content!
