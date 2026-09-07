const API_URL = "http://localhost:5001/analyze";
const STORE_TRUST_API_URL = "http://localhost:5001/store-trust";
const cache = new Map();
const storeTrustCache = new Map();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze") {
    const input = request.input;
    const anchorText = request.anchorText || "";
    const pageUrl = request.pageUrl || "";
    const cacheKey = `${input}::${anchorText}`;

    if (cache.has(cacheKey)) {
        console.log("Serving from cache:", cacheKey);
        sendResponse(cache.get(cacheKey));
        return true;
    }

    fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        input: input,
        anchor_text: anchorText,
        page_url: pageUrl
      })
    })
    .then(response => response.json())
    .then(data => {
      cache.set(cacheKey, data);
      sendResponse(data);
    })
    .catch(error => {
      console.error("API error:", error);
      sendResponse({ error: "API unreachable. Make sure the backend bridge is running." });
    });
    return true; // Keep message channel open for async response
  }


  if (request.action === "storeTrust") {
    const url = request.url;

    fetch(STORE_TRUST_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
      sendResponse(data);
    })
    .catch(error => {
      console.error("API error:", error);
      sendResponse({ error: "API unreachable. Make sure the backend bridge is running." });
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
    if (textToAnalyze) {
        chrome.tabs.sendMessage(tab.id, { action: "showModal", text: textToAnalyze });
    }
  }
});
