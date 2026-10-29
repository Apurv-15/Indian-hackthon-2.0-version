# Plan: Increase Render / Analysis Speed Without Quality Loss

## Goal
Reduce end-to-end latency of the analysis and store-trust rendering pipeline (Python bridge + Next.js + extension badge) while preserving model accuracy (DeBERTa/MiniLM/SVM ensemble) and trust scoring fidelity. User phrasing "video clips" has no match in repo — interpreted as "render speed of analysis results / store-trust badge clips and dashboard cards". Plan holds quality constant and optimizes speed via parallelism, caching, I/O reduction, and model runtime tuning.

## Context
- No video pipeline exists in repo (`rg video|ffmpeg|remotion` returns 0 hits). Nearest analogue is clip/badge render: store-trust floating badge, extension popup, and `/api/analyze` → `bridge.py` → `app.py` → agents 1/2/3/4/5.
- Current bottlenecks (verified in code):
  - `ai_agent/app.py:analyze()` runs Agent1 → Agent2 → Agent4 **sequentially** despite `evaluate_latency.py` showing parallel is faster (150-250 ms vs 300-500 ms claimed).
  - `bridge.py` uses `ThreadPoolExecutor(max_workers=4)` with 25 s / 18 s timeouts, single gunicorn worker (`--workers 1 --threads 4`).
  - Agent1: `SentenceTransformer` encode for every call + live HTTP + DNS per URL + PhishTank file I/O.
  - Agent2: DeBERTa-v3-small inference on CPU per request (`torch.inference_mode` but no ONNX/quantization, max_length 512 always).
  - Agent5: slowest path — `fetch_page` × 8+ sub-pages + `_next` chunks + `fetch_domain_age` (rdap.org) + `fetch_customer_reviews` (Trustpilot + 2× DDG) each with own `ThreadPoolExecutor(2/4/8)` and 3.5-6 s timeouts. Total 6-12 s wall clock typical.
  - Frontend: `src/app/api/analyze/route.ts` does serial `fetch` with 30 s `AbortSignal.timeout`, no streaming, no client cache beyond `scan-history.ts` localStorage.

## Constraints
- **Quality invariant**: No drop in phishing/spam/prompt/style accuracy, no drop in store-trust tier accuracy. Must gate rollout on `evaluate_pipeline.py` / `evaluate_unleaked.py` / `evaluate_stability_difficulty.py`.
- **No extra paid services** (Firecrawl, SafeBrowsing optional only if key present).
- **CPU-only on macOS** (`PYTORCH_DISABLE_MPS=1`) — optimizations must work on CPU.
- **Extension security**: CSP, CORS restricted to `localhost:*` + `chrome-extension://*` must stay.

## Affected Boundaries
- `ai_agent/app.py`, `ai_agent/bridge.py`, `ai_agent/agents/*`, `ai_agent/utils/preprocessor.py`
- `src/app/api/analyze/route.ts`, `src/services/threat-engine.ts`, `src/services/scan-history.ts`
- `extension/background.js`, `extension/content.js`
- `gunicorn` start script `start.sh`, `requirements.txt`

## Design Decisions

### D1: Parallelize hot path (P0)
- Change `app.py:ThreatDetectionSystem.analyze` to `ThreadPoolExecutor(max_workers=3)` for Agent1/2/4 (pattern already in `evaluate_latency.py:132-138`). Synthesizer stays serial.
- For Agent5, collapse nested pools into one top-level I/O pool: fetch main page → immediately dispatch `fetch_domain_age`, `fetch_customer_reviews` (Trustpilot/DDG) concurrently with sub-page fetches instead of after. Eliminates ~3 s sequential wait.
- Bridge: raise `max_workers` to 8 or `min(8, 2*cpu+2)`, enable `requests.Session` pooling.

### D2: Add two-level caching (P0, quality-neutral)
- Bridge LRU+TTL cache keyed by `hash(normalized_input + anchor + pageUrl)` for `/analyze` (e.g., 500 entries, 10 min TTL, cache hit returns in <5 ms). Must include `detailed_results` so frontend render is instant.
- Keep extension's 200-entry LRU + 5 min TTL for store-trust, add **request dedup + abort**: debounce hover 80 ms, cache pending Promise, AbortController for superseded fetch.
- Cache RDAP domain age 24 h (JSON file like `data/phishtank_cache.json`), and `check_url_live` DNS cache already 15 min — extend to host→`_live_cache` with size cap.

### D3: Reduce Agent5 I/O fan-out (P0)
- Cap sub-page fetches to top 5 (not 8): `checkout`, `cart`, 2 best policy links, 1 fallback. Timeout 3.5 → 2.0-2.5 s. Reuse single `curl_cffi` session with `impersonate="chrome120"` and keep-alive.
- Limit `_next/static/chunks` inspection to ≤2 hottest chunks, skip if `platform != Custom` Shopify/WooCommerce (already has gateway signals).
- DDG queries: single query `f"{domain} reviews complaints"` instead of 2, with `target_domain` validation kept (`_clean_and_filter_snippet`).

### D4: Model runtime tuning (P1, quality-neutral)
- Keep DeBERTa weights unchanged. Optimize runtime: export to ONNX Runtime (CPU, int8 dynamic quantization) or use `torch.compile`/`optimum` if available. Fallback: keep pytorch but add `tokenizer(..., max_length=256 or 512 auto)` — truncate benign/short inputs to 256 tokens (saves 30-40% time), long phishing to 512.
- Cache MiniLM embeddings for `phishing_patterns` (already cached) + memoize `model.encode([text])` for duplicate `cleaned_text` within 10 min.
- Agent4 transformer stays disabled (`use_transformer=False`) — no change. If enabled, gate behind rule-score < threshold to avoid double cost on obvious injections.

### D5: Frontend perceived render speed (P1)
- `src/app/api/analyze/route.ts`: add `cache: "no-store"` but client-side SWR with 5 min dedup. Stream response: return `NextResponse.json` as today, add loading skeleton in `src/app/scanner/page.tsx` + `src/app/dashboard/page.js` using `React.Suspense` / `useDeferredValue`.
- Lazy-load review snippets tab in store badge (render badge shell immediately, fetch snippets async).
- Add `preload="metadata"` and `IntersectionObserver` if any video component is later introduced — addresses literal "video clips" without impacting current non-video paths.

### D6: Gunicorn / infra (P1)
- Change `--workers 1 --threads 4` → `--workers 1 --threads 8 --preload` (macOS safe) or `--workers 2` on Linux CI. Document in `start.sh`.
- Add health-check warmup call to `system.analyze("hello")` after models load so first real request avoids cold-start (already measured as slowest in `evaluate_latency.py`).

## Edge Cases
- Cache poisoning: normalize input (trim, lowercase host, strip UTM params) before hashing; include model version in key.
- Stale RDAP/phishtank: background refresh job, not blocking request; serve cached if fetch fails.
- Rate-limited DDG/Trustpilot: on 429/timeout, return partial result with `has_meaningful_results=false` rather than error (already does for store-unreachable).
- Extension rapid hover: dedup prevents N× bridge calls for same URL within 200 ms.

## Failure Modes
- Parallel agents raise exception → bridge `future.result()` surfaces 500; add per-future try/except returning `{"error": "agent X failed"}` with degraded score so synthesizer still produces result.
- ONNX export mismatch → fallback to pytorch path automatically; CI must assert `evaluate_pipeline.py` accuracy delta < 0.5%.

## Rollout / Migration
1. Feature-flag `PARALLEL_ANALYZE=1` and `BRIDGE_CACHE=1` env vars, default on in dev, off in prod for canary.
2. Ship in order: D1 → D2 → D3 → D6 → D4 → D5. Each behind flag so rollback is single env change.
3. No DB migration; only new `data/rdap_cache.json` file gitignored.

## Validation
- Before/after: `python ai_agent/evaluate_latency.py` (N=50) — target p50 parallel < 200 ms for `/analyze`, p95 < 350 ms. Store-trust p50 < 2.5 s (down from ~6 s).
- Accuracy guard: `python ai_agent/evaluate_pipeline.py` + `evaluate_unleaked.py` must show no regression > 0.5% F1; `evaluate_agent4.py` if touching Agent4.
- Manual: extension hover on 5 known stores (croma.com, boat-lifestyle, mrktrends.in, amazon.in, fresh D2C) — badge appears in <300 ms cached, <2.5 s cold.
- Frontend: Lighthouse performance score before/after on `/scanner`.

## Tasks (Ordered)
1. Instrument baseline: run `evaluate_latency.py` and log cold/warm, bridge concurrency; capture trace of Agent5 (`fetch_page` timings).
2. Implement parallel `app.py:analyze` (ThreadPoolExecutor 3) + bridge worker bump + Session pooling.
3. Add bridge LRU+TTL cache for `/analyze` and RDAP 24 h cache; extension dedup/abort + hover debounce.
4. Trim Agent5 fan-out (5 pages, 2.5 s timeout, single query, 2 chunks max) and parallelize domain_age/reviews with page fetches.
5. Tune model runtime: adaptive truncation (256/512), embedding memo, optional ONNX path with fallback.
6. Frontend skeleton + SWR dedup + lazy review tab.
7. Update `start.sh` gunicorn flags and add warmup ping; document flags.
8. Run validation suite and record results in PR description.

## Open Question
- **What does "video clips" refer to?** Repo has no `video|mp4|ffmpeg|remotion|camera` asset. Recommendation assumes you mean "analysis result clips / store-trust badge rendering" and general dashboard render speed. If you actually plan to add video generation/playback (e.g., showcase reels or screen-captured threat demos), confirm: codec, resolution, expected clip count per page, and whether you need client-side transcoding (FFmpeg.wasm) vs CDN-hosted MP4/WebM. Answer determines whether to add lazy `<video>` loading, `IntersectionObserver`, and WebCodecs work — out of scope for this plan unless confirmed.

## Out of Scope
- Changing model weights or retraining (`train_models.py`).
- Adding new paid APIs.
- Full rewrite to async `aiohttp` (defer unless ThreadPool proves insufficient).
