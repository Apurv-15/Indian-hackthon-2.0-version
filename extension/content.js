console.log("AegisAI Phishing Shield Content Script Loaded.");

const SCAN_MARKER_CLASS = "aegis-scan-marker";
const RISK_COLORS = {
  "High": "#ff4d4d",
  "Medium": "#ffa333",
  "Low": "#ffff66",
  "Safe": "#4dff4d"
};

// Create a tooltip element
const tooltip = document.createElement("div");
tooltip.id = "aegis-tooltip";
tooltip.style.cssText = `
  position: absolute;
  z-index: 999999;
  background: rgba(10, 15, 30, 0.95);
  color: #fff;
  padding: 12px 16px;
  border-radius: 12px;
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  font-size: 13px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(8px);
  border: 1px solid rgba(255, 255, 255, 0.1);
  display: none;
  pointer-events: none;
  max-width: 300px;
  line-height: 1.5;
`;
document.body.appendChild(tooltip);

// Function to update tooltip content
function updateTooltip(x, y, data) {
  if (data.error) {
    tooltip.innerHTML = `<span style="color: #ff4d4d">Error: ${data.error}</span>`;
  } else {
    tooltip.innerHTML = `
      <div style="font-weight: bold; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center;">
        <span>AegisAI Analysis</span>
        <span style="color: ${RISK_COLORS[data.riskLevel] || '#fff'}; font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(0,0,0,0.3);">${data.riskLevel} Risk</span>
      </div>
      <div><strong>Verdict:</strong> ${data.threatType || 'Unknown'}</div>
      <div><strong>Confidence:</strong> ${data.confidenceScore}%</div>
      <div style="margin-top: 6px; font-size: 11px; color: #ccc;">${data.explanation}</div>
    `;
    tooltip.style.borderTop = `3px solid ${RISK_COLORS[data.riskLevel] || 'transparent'}`;
  }
  tooltip.style.display = "block";
  tooltip.style.left = x + 15 + "px";
  tooltip.style.top = y + 15 + "px";
}

// Global listener for clicking to intercept high-risk links
document.addEventListener("click", (e) => {
    const target = e.target.closest("a");
    if (target && target.dataset.aegisResult) {
        const data = JSON.parse(target.dataset.aegisResult);
        if (data.riskLevel === "High") {
            const proceed = confirm(`🚨 AegisAI WARNING 🚨\n\nThis link appears to be a HIGH RISK phishing threat.\n\nType: ${data.threatType}\nConfidence: ${data.confidenceScore}%\n\nReason: ${data.explanation}\n\nAre you sure you want to proceed?`);
            if (!proceed) {
                e.preventDefault();
                e.stopPropagation();
            }
        }
    }
}, true); // Use capture phase

// Global listener for hovering
document.addEventListener("mouseover", (e) => {
  const target = e.target.closest("a");
  if (target && target.href && !target.dataset.aegisScanned) {
      // Don't scan internal or empty links
      if (target.href.startsWith("javascript:") || target.href.startsWith("#")) return;

      target.style.position = "relative";
      const marker = document.createElement("span");
      marker.className = SCAN_MARKER_CLASS;
      marker.innerHTML = "🔍";
      marker.style.cssText = "margin-left: 4px; font-size: 0.8em; cursor: help; opacity: 0.7;";
      target.appendChild(marker);
      target.dataset.aegisScanned = "true";

      // Scan automatically on hover
      chrome.runtime.sendMessage({ action: "analyze", input: target.href }, (response) => {
          if (response) {
            target.dataset.aegisResult = JSON.stringify(response);
            marker.innerHTML = getRiskEmoji(response.riskLevel);
            marker.style.color = RISK_COLORS[response.riskLevel];
            marker.style.opacity = "1";
            target.style.borderBottom = `2px solid ${RISK_COLORS[response.riskLevel]}`;
          }
      });
  }

  // Show tooltip if target has result
  const link = e.target.closest("a");
  if (link && link.dataset.aegisResult) {
    const data = JSON.parse(link.dataset.aegisResult);
    updateTooltip(e.pageX, e.pageY, data);
  }
});

document.addEventListener("mousemove", (e) => {
    if (tooltip.style.display === "block") {
        tooltip.style.left = e.pageX + 15 + "px";
        tooltip.style.top = e.pageY + 15 + "px";
    }
});

document.addEventListener("mouseout", (e) => {
  const link = e.target.closest("a");
  if (link) {
    tooltip.style.display = "none";
  }
});

function getRiskEmoji(risk) {
    switch(risk) {
        case "High": return "🔴";
        case "Medium": return "🟠";
        case "Low": return "🟡";
        case "Safe": return "🟢";
        default: return "⚪";
    }
}

// Function to scan all unscanned links on the page
function scanAllLinks() {
    const links = document.querySelectorAll("a:not([data-aegis-scanned='true'])");
    links.forEach(target => {
        if (!target.href || target.href.startsWith("javascript:") || target.href.startsWith("#")) return;

        target.style.position = "relative";
        const marker = document.createElement("span");
        marker.className = SCAN_MARKER_CLASS;
        marker.innerHTML = "🔍";
        marker.style.cssText = "margin-left: 4px; font-size: 0.8em; cursor: help; opacity: 0.7;";
        target.appendChild(marker);
        target.dataset.aegisScanned = "true";

        chrome.runtime.sendMessage({ action: "analyze", input: target.href }, (response) => {
            if (response && !response.error) {
                target.dataset.aegisResult = JSON.stringify(response);
                marker.innerHTML = getRiskEmoji(response.riskLevel);
                marker.style.color = RISK_COLORS[response.riskLevel];
                marker.style.opacity = "1";
                target.style.borderBottom = `2px solid ${RISK_COLORS[response.riskLevel]}`;
            }
        });
    });
}

// Handle messages from background or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "showModal") {
        alert("Analyzing: " + request.text + "\n(Integration in progress...)");
        sendResponse({ status: "done" });
    } else if (request.action === "scanAllLinks") {
        scanAllLinks();
        sendResponse({ status: "started" });
    }
    return true;
});
