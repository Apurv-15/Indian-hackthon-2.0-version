# 🛡️ AegisAI - Multi-Agent Threat Detection & Phishing Shield

AegisAI is a premium, real-time threat-monitoring, store legitimacy verification, and phishing prevention system. It features a Next.js threat dashboard, a Flask/Gunicorn Python inference bridge serving multi-agent models, and a high-performance browser extension that intercepts, analyzes, and displays deep legitimacy signals for web links and e-commerce stores.

---

## 🚀 High-Performance Browser Extension

The AegisAI browser extension provides **on-the-fly, zero-latency phishing protection & store trust verification** as you browse.

### ⚡ Sub-Millisecond Scraping & Speed Features
- **Event-Driven Scraping**: Hooks into page-level `mouseover` (hover) and `click` events using capture-phase event listeners. Scraping is triggered automatically *only* when users interact with links, avoiding unnecessary bulk scraping or page performance degradation.
- **Background Async Analysis**: When a link is hovered, a non-blocking asynchronous request is dispatched to the service worker (`background.js`), which queries the backend bridge. The UI remains fully responsive.
- **Bounded LRU & TTL Caching**: A local 200-entry LRU cache in `background.js` stores previous link verdicts, while store trust lookups are cached with a 5-minute Time-To-Live (TTL). Repeated hover/click actions on the same URL are resolved in **0ms** without network overhead.
- **Automated E-Commerce Detection**: Automatically detects online storefronts (Shopify, WooCommerce, Magento, Custom Cart infrastructure) and injects a warm-themed floating **Store Trust Shield Badge**.
- **Viewport-Bounded Glassmorphic UI**: The floating store badge is constrained to `max-height: calc(85vh - 80px)` with `overflow-y: auto` and a custom warm scrollbar, preventing popup overflow past the browser top edge regardless of screen resolution.
- **Live Health Status Dot**: The extension popup automatically queries `http://127.0.0.1:5001/health` on open and displays a dynamic green/red connection status dot (`● Bridge: 5001 Online`).

---

## 🧠 Multi-Agent Risk Scoring Engine

The backend relies on a **5-Agent Ensemble System** combining legacy machine learning models (fast & interpretable) and modern Deep Learning Transformers (highly semantic).

```
User Input / Link / Storefront
              │
              ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Preprocessed & Tokenized                        │
└───────────────────┬────────────────────────────────────┘
                                    │ (Parallel Execution)
        ┌───────────────────┬───────┴───────────┬───────────────────┐
        ▼                   ▼                   ▼                   ▼
 ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
 │   Agent 1    │    │   Agent 2    │    │   Agent 4    │    │   Agent 5    │
 │ External/URL │    │   Content    │    │ Prompt Inj.  │    │ Store Trust  │
 │ (SVM, Cosine)│    │ (NB, DeBERTa)│    │(DeBERTa-MNLI)│    │ (Scam/D2C/7A)│
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
3. **Agent 4 (Prompt Injection Detector)**: Leverages a fine-tuned **DeBERTa-v3 MNLI** model paired with rule-based heuristics to detect prompt injection and jailbreak attempts.
4. **Agent 5 (Store Trust & Consumer Sentiment Analyst)**: Evaluates online stores across 4 critical pillars: Corporate Registration & MCA CINs, Payment Gateway KYC Onboarding, ICANN Domain Age, and Multi-Source Consumer Review Sentiment.
5. **Agent 3 (Synthesizer)**: Combines individual scores using a weighted consensus logic with dynamic contextual multipliers.

---

## 📚 Complete Project Documentation & Deep Dives

For in-depth technical references, architecture diagrams, and algorithm specifications, check out our comprehensive guide suite:

| Document | Description |
| :--- | :--- |
| ⚡ [**QUICK_REFERENCE.md**](QUICK_REFERENCE.md) | **Review Cheat Sheet**: System overview, 4-agent summary, risk formula & quick troubleshooting. |
| 🏗️ [**ARCHITECTURE.md**](ARCHITECTURE.md) | **System Architecture**: High-level topology, agent communication flow, input processing pipeline. |
| 🧠 [**ALGORITHM_REFERENCE.md**](ALGORITHM_REFERENCE.md) | **ML Algorithm Deep Dive**: MNB, SVM, DeBERTa, DistilBERT, MiniLM embeddings, TF-IDF, and ensemble formulas. |
| 📊 [**DATA_FLOW_DIAGRAM.md**](DATA_FLOW_DIAGRAM.md) | **Data Flow & ASCII Traces**: Step-by-step visual decision trees per agent and timeline analysis. |
| 🤝 [**AGENT_COMMUNICATION_PATTERNS.md**](AGENT_COMMUNICATION_PATTERNS.md) | **Agent Contracts & Protocols**: Data contracts, error handling, parallel execution, and consensus strategies. |

---

## 🔥 Zero-Cost Firecrawl Alternative (`curl_cffi` Engine)

Rather than paying for expensive Firecrawl / Scraper API subscriptions, AegisAI features a **100% Free & Open-Source Review Extraction Engine** powered by **`curl_cffi`** (Browser TLS Impersonation).

### 🌐 How We Replaced Firecrawl For Free:
- **TLS Fingerprint Impersonation**: Traditional scraping libraries (`requests`, `urllib`, `axios`) get blocked by Cloudflare and anti-bot systems with 403 Forbidden errors when scraping review portals. `curl_cffi` impersonates real Chrome browser TLS fingerprints (`impersonate="chrome120"`), bypassing anti-bot shields without CAPTCHAs.
- **Parallel Multi-Source Complaint Extraction**: Uses Python's `concurrent.futures.ThreadPoolExecutor` to run concurrent parallel searches across:
  - **Consumer Complaints India** (`consumercomplaints.in`)
  - **MouthShut India** (`mouthshut.com`)
  - **Trustpilot** (`trustpilot.com`)
  - **DuckDuckGo HTML Engine**
- **Template Noise & Boilerplate Filtering Engine**:
  Search engine snippets often return useless landing page slogans like *"Do you agree with TrustScore? Voice your opinion today"* or `"&amp;&#x27;"` raw HTML encodings. AegisAI implements a 4-step cleanup pipeline:
  1. **HTML Entity Unescaping**: Converts `&#x27;` $\to$ `'`, `&amp;` $\to$ `&`, `&quot;` $\to$ `"`.
  2. **Tag Stripping**: Strips residual HTML markup.
  3. **Pattern Noise Rejection**: Filters out generic site meta-templates (`"voice your opinion"`, `"trustscore"`, `"read reviews, company details"`, `"submit your complaint"`).
  4. **Keyword Relevance Validation**: Requires snippets to contain actual buyer experience terms (`ordered`, `delivered`, `quality`, `support`, `tracking`, `fake`, `scam`, `refund`).
  - *If no clean review quote remains, the extension automatically hides the "Detailed Snippets" toggle to keep the UI clean.*

---

## 🇮🇳 Advanced E-Commerce Store Legitimacy Classification

Store Trust Agent (Agent 5) provides specialized intelligence for the Indian e-commerce landscape:

### 1. 🏛️ Corporate Business Entity & MCA CIN Verification
- **Replaced Misleading "GSTIN Not Found"**: Top Indian brands (Croma, Reliance Digital, Tata Cliq, Lenskart, Nykaa, Boat, Snitch, Bewakoof, etc.) do not print 15-digit GSTINs on their public homepages (they print GSTIN only on tax invoices).
- **Multi-Tier Entity Engine**:
  - **Enterprise Brand Registry**: Maps domains to verified corporate parent entities (e.g. `croma.com` $\to$ `Infiniti Retail Ltd (A Tata Enterprise)`, `reliancedigital.in` $\to$ `Reliance Retail Ltd`).
  - **21-Digit MCA CIN Regex**: Identifies Indian Ministry of Corporate Affairs Corporate Identity Numbers (`U31900MH2006PLC166524`).
  - **Legal Suffix Extraction**: Scrapes footers for registered corporate suffixes (`Pvt Ltd`, `Private Limited`, `Limited`, `LLP`).
  - **GSTIN Checksum**: Luhn mod-36 validation fallback for SMB storefronts.
- **UI Metric Pill**: Displays `Business Entity: Infiniti Retail Ltd (A Tata Enterprise) ✓` with full **0.95–0.99 Trust**.

### 2. 📦 Master Copy / 7A Replica Delivery Verification (`REPLICA_VERIFIED`)
- **Separation of Authenticity vs. Delivery Trust**: Buyers looking for 1st Copy / 7A Replicas (e.g. ₹2,500 AirPods Max or ₹3,000 Jordan shoes) want to know: *"Will this store actually ship the order, or is it a non-delivery scam site?"*
- **`REPLICA_VERIFIED` Status Tier (68%–75% Trust)**:
  - Detects replica indicators (`master copy`, `1st copy`, `7a quality`, `first copy`, `ua quality`, `imported quality`).
  - Checks external consumer databases specifically for **non-delivery / fraud complaints** (*"money deducted no order"*, *"never delivered"*).
  - If the store **actually delivers orders** and has active payment gateways, it receives **`REPLICA_VERIFIED`** status (**~70% Trust**) instead of being tanked to a scam tier!
- **Badge Styling**: Purple **`📦 Master Copy — Delivery Verified`** badge with COD inspection recommendations.

### 3. 🚀 Reliable D2C Startup Verification Engine (`STARTUP_VERIFIED`)
- **Fair Scoring for Emerging Startups (74%–88% Trust)**: Emerging Indian D2C startups (3–12 months old) lack 20-year domain histories but are 100% reliable merchants.
- **4 Startup Legitimacy Verification Pillars**:
  1. **Payment Gateway Merchant Onboarding**: Razorpay, Cashfree, PayU, PhonePe, and Shopify Payments require merchant bank account verification, PAN, and business KYC before allowing payment processing.
  2. **Verified Support Infrastructure**: Verified customer support email (`support@brand.com`), working phone number, and physical office address with a 6-digit Indian PIN code.
  3. **Social Media Verification**: Active linked brand handles (`instagram.com`, `facebook.com`, `youtube.com`).
  4. **Clean Track Record**: Zero non-delivery/scam complaints across consumer databases.
- **Badge Styling**: Green **`🚀 Verified D2C Startup — 78% Trust`** badge with transparent merchant KYC confirmation.

---

## ⚖️ Weighted Risk Scoring & Risk Levels

| Threat Category | Weight | Description |
| :--- | :--- | :--- |
| **Phishing Probability** | `0.35` | Overall semantic phishing likelihood |
| **URL Risk** | `0.25` | Heuristics & ML evaluations of target link |
| **Prompt Injection** | `0.20` | Malicious prompt hijack attempts |
| **Store Trust Risk** | `0.15` | E-commerce scam and fake storefront likelihood |
| **Spam Probability** | `0.10` | Mass mail content indicators |
| **AI-Generated Content** | `0.05` | Automated scam copy generation markers |
| **Domain Similarity** | `0.05` | Likelihood of brand typosquatting or impersonation |

#### 📊 Store Trust Classifications:
- **ESTABLISHED** (90%–99% Trust 🟢): Enterprise marketplaces & verified corporate brands (Amazon, Flipkart, Croma, Reliance).
- **STARTUP_VERIFIED** (74%–88% Trust 🚀): Verified D2C startups with gateway KYC, support email/phone/pincode & active social presence.
- **REPLICA_VERIFIED** (68%–75% Trust 📦): 1st Copy / 7A Replica sellers with verified order delivery history.
- **SOME_SIGNALS** (50%–69% Trust 🟡): Growing independent stores with basic policies.
- **FEW / NO SIGNALS** (< 45% Trust 🚨): Unverified stores with manual personal UPI QR codes, missing contact info, or non-delivery scam complaints.

---

## 🛠️ Technology Stack

- **Frontend**: Next.js 15 (App Router), React, TailwindCSS, Lucide Icons
- **Backend Bridge**: Python 3.10+, Flask, Gunicorn (WSGI), Flask-CORS
- **Review Scraper**: `curl_cffi` (Browser TLS Impersonation), `requests`, `urllib3`
- **Machine Learning**: HuggingFace Transformers (`deberta-v3`, `distilbert`), Scikit-Learn (`MultinomialNB`, `SGDClassifier`, `TF-IDF`), PyTorch
- **Browser Extension**: Manifest V3, Web Extensions API, Service Workers, In-Memory LRU Cache

---

## 📦 Getting Started

### 1. Prerequisites
- Node.js 18+ & `npm`/`pnpm`
- Python 3.10+ (Virtual environment recommended)

### 2. Installation
Clone the repository and install the Next.js dependencies:
```bash
npm install
```

Install the Python backend dependencies (includes `curl-cffi`, `gunicorn`, `flask-cors`, `torch`, `transformers`):
```bash
pip install -r requirements.txt
```

### 3. Running the System

#### ⚡ Quick Start (Recommended — One Command)

Launch both the **Python AI Inference Bridge** and the **Next.js Threat Dashboard** using the automated startup script:

**On Linux / macOS:**
```bash
# Ensure execution permissions
chmod +x start.sh

# Run the unified system
./start.sh
```

> **What `start.sh` does automatically:**
> 1. Cleans up previous `.pycache` and log caches.
> 2. Kills any stray background processes on port `5001`.
> 3. Detects your virtual environment (`.venv` / `venv` / system `python3`).
> 4. Launches Gunicorn WSGI server (`bridge:app`) on `127.0.0.1:5001` with single-process multi-threading (`--workers 1 --threads 4`) to prevent macOS Metal compiler crashes.
> 5. Health-checks `http://127.0.0.1:5001/health` until ML models are loaded into memory.
> 6. Launches the Next.js dev server (`npm run dev`).
> 7. Handles graceful teardown of all backend processes upon `Ctrl+C`.

---

### 4. Installing the Browser Extension
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** (top-left).
4. Select the `extension` folder inside this repository.
5. Visit any website or e-commerce store (`croma.com`, `boat-lifestyle.com`, `bossgadgets.in`) to view live risk scores and store trust badges!
