const API_URL = "http://localhost:5001/analyze";
const STORE_TRUST_API_URL = "http://localhost:5001/store-trust";
const HEALTH_URL = "http://localhost:5001/health";

// Bounded LRU Caches
const MAX_CACHE_SIZE = 200;
const cache = new Map();
const storeTrustCache = new Map();

function setBoundedCache(map, key, value, ttlMs = null) {
  if (map.size >= MAX_CACHE_SIZE) {
    const oldestKey = map.keys().next().value;
    map.delete(oldestKey);
  }
  const entry = { value, expiry: ttlMs ? Date.now() + ttlMs : null };
  map.set(key, entry);
}

function getBoundedCache(map, key) {
  if (!map.has(key)) return null;
  const entry = map.get(key);
  if (entry.expiry && Date.now() > entry.expiry) {
    map.delete(key);
    return null;
  }
  return entry.value;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "health") {
    fetch(HEALTH_URL, { method: "GET" })
      .then(resp => resp.json())
      .then(data => sendResponse({ online: data.status === "ok" }))
      .catch(() => sendResponse({ online: false }));
    return true;
  }

  if (request.action === "analyze") {
    const input = request.input;
    const anchorText = request.anchorText || "";
    const pageUrl = request.pageUrl || "";
    const normalizedAnchor = anchorText.trim().toLowerCase().slice(0, 40);
    let pageHost = "unknown";
    try { if (pageUrl) pageHost = new URL(pageUrl).hostname; } catch(e) {}
    const cacheKey = `${pageHost}::${input}::${normalizedAnchor}`;

    const cachedData = getBoundedCache(cache, cacheKey);
    if (cachedData) {
      sendResponse(cachedData);
      return true;
    }

    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input, anchor_text: anchorText, page_url: pageUrl })
    })
    .then(response => response.json())
    .then(data => {
      if (!data.error) setBoundedCache(cache, cacheKey, data, 10 * 60 * 1000); // 10 min TTL
      sendResponse(data);
    })
    .catch(error => {
      console.error("API error:", error);
      sendResponse({ error: "Backend bridge unreachable." });
    });
    return true;
  }

  if (request.action === "storeTrust") {
    const url = request.url;
    const cachedTrust = getBoundedCache(storeTrustCache, url);
    if (cachedTrust) {
      sendResponse(cachedTrust);
      return true;
    }

    fetch(STORE_TRUST_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    })
    .then(response => response.json())
    .then(data => {
      if (!data.error) setBoundedCache(storeTrustCache, url, data, 30 * 60 * 1000); // 30 min TTL
      sendResponse(data);
    })
    .catch(error => {
      console.error("Store trust API error:", error);
      sendResponse({ error: "Backend bridge unreachable." });
    });
    return true;
  }
});

// Context menu for manual scanning
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "analyze-text",
    title: "Analyze for Phishing Risk",
    contexts: ["selection", "link"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "analyze-text") {
    const textToAnalyze = info.selectionText || info.linkUrl;
    if (textToAnalyze && tab?.id) {
      chrome.tabs.sendMessage(tab.id, { action: "showModal", text: textToAnalyze });
    }
  }
});
