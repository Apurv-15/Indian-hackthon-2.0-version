console.log("AegisAI Phishing Shield Content Script Loaded.");

const SCAN_MARKER_CLASS = "aegis-scan-marker";
const RISK_COLORS = {
  "Critical": "#ff1a1a",
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
        if (data.riskLevel === "High" || data.riskLevel === "Critical") {
            const proceed = confirm(`🚨 AegisAI WARNING 🚨\n\nThis link appears to be a ${data.riskLevel.toUpperCase()} RISK phishing threat.\n\nType: ${data.threatType}\nConfidence: ${data.confidenceScore}%\n\nReason: ${data.explanation}\n\nAre you sure you want to proceed?`);
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
  // Don't scan links inside AegisAI's own UI elements
  if (target && (target.closest('#aegis-store-badge') || target.closest('#aegis-tooltip') || target.classList.contains('aegis-no-scan'))) {
      return;
  }
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
      try {
          if (!chrome.runtime?.id) return;
          const anchorText = (target.innerText || target.title || target.getAttribute("aria-label") || "").trim();
          const pageUrl = window.location.href;
          chrome.runtime.sendMessage({ action: "analyze", input: target.href, anchorText: anchorText, pageUrl: pageUrl }, (response) => {
              if (chrome.runtime.lastError) {
                  console.warn("AegisAI extension context invalidated or reloaded.");
                  return;
              }
              if (response) {
                target.dataset.aegisResult = JSON.stringify(response);
                marker.innerHTML = getRiskEmoji(response.riskLevel);
                marker.style.color = RISK_COLORS[response.riskLevel];
                marker.style.opacity = "1";
                const isHighRisk = response.riskLevel === "High" || response.riskLevel === "Critical";
                target.style.borderBottom = `${isHighRisk ? '3px' : '2px'} solid ${RISK_COLORS[response.riskLevel]}`;
                if (isHighRisk) {
                  target.style.color = RISK_COLORS[response.riskLevel];
                  target.style.fontWeight = "bold";
                  target.title = `🚨 ${response.riskLevel.toUpperCase()} RISK — ${response.threatType}`;
                }
                if (target.matches(':hover')) {
                  updateTooltip(e.pageX, e.pageY, response);
                }
              }
          });
      } catch (err) {
          console.warn("AegisAI extension context disconnected.");
      }
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
        case "Critical":
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

        try {
            if (!chrome.runtime?.id) return;
            const anchorText = (target.innerText || target.title || target.getAttribute("aria-label") || "").trim();
            const pageUrl = window.location.href;
            chrome.runtime.sendMessage({ action: "analyze", input: target.href, anchorText: anchorText, pageUrl: pageUrl }, (response) => {
                if (chrome.runtime.lastError) return;
                if (response && !response.error) {
                    target.dataset.aegisResult = JSON.stringify(response);
                    marker.innerHTML = getRiskEmoji(response.riskLevel);
                    marker.style.color = RISK_COLORS[response.riskLevel];
                    marker.style.opacity = "1";
                    const isHighRisk = response.riskLevel === "High" || response.riskLevel === "Critical";
                    target.style.borderBottom = `${isHighRisk ? '3px' : '2px'} solid ${RISK_COLORS[response.riskLevel]}`;
                    if (isHighRisk) {
                      target.style.color = RISK_COLORS[response.riskLevel];
                      target.style.fontWeight = "bold";
                      target.title = `🚨 ${response.riskLevel.toUpperCase()} RISK — ${response.threatType}`;
                    }
                }
            });
        } catch (err) {
            // Silently ignore invalidated context
        }
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

// ==========================================
// E-COMMERCE STORE TRUST AUTO-DETECTION & FLOATING SHIELD
// ==========================================
function isEcommerceSite() {
    const pageHtml = document.documentElement.innerHTML.toLowerCase();
    const hasCart = !!document.querySelector('[id*="cart"], [class*="cart"], a[href*="cart"], button[name*="add-to-cart"]');
    const hasCheckout = !!document.querySelector('[id*="checkout"], [class*="checkout"], a[href*="checkout"]');
    const hasShopify = pageHtml.includes('cdn.shopify.com') || pageHtml.includes('shopify-features');
    const hasWoo = pageHtml.includes('woocommerce') || pageHtml.includes('wp-content/plugins/woocommerce');
    const hasPrice = pageHtml.includes('₹') || pageHtml.includes('rs.') || pageHtml.includes('inr');
    
    // Ignore search engines and social platforms
    const host = window.location.hostname;
    if (host.includes('google.') || host.includes('bing.') || host.includes('youtube.') || host.includes('facebook.') || host.includes('instagram.')) {
        return false;
    }

    return (hasShopify || hasWoo || (hasCart && hasCheckout) || (hasCart && hasPrice));
}

function injectStoreTrustBadge() {
    if (!isEcommerceSite() || document.getElementById('aegis-store-badge')) return;

    try {
        if (!chrome.runtime?.id) return;
        chrome.runtime.sendMessage({ action: 'storeTrust', url: window.location.href }, (data) => {
            if (chrome.runtime.lastError || !data || data.error) return;

            const badgeContainer = document.createElement('div');
            badgeContainer.id = 'aegis-store-badge';

            const score = Math.round((data.trust_score || 0) * 100);
            let scoreColor = '#4dff4d';
            let shieldIcon = '🛡️';
            if (data.trust_level === 'NO_SIGNALS' || data.trust_level === 'UNKNOWN') {
                scoreColor = '#ff4d4d';
                shieldIcon = '🚨';
            } else if (data.trust_level === 'FEW_SIGNALS' || data.trust_level === 'SOME_SIGNALS') {
                scoreColor = '#ffa333';
                shieldIcon = '⚠️';
            }

            const escapeHtml = (value) => String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');

            const buildReviewSection = (reviewSummary) => {
                if (!reviewSummary?.has_meaningful_results) {
                    return '';
                }

                const reviewColor = '#111827';

                const links = Array.isArray(reviewSummary.sources)
                    ? reviewSummary.sources.filter(source => source?.name && source?.url)
                    : [];

                const linksHtml = links.length
                    ? `
                        <div style="margin-top: 12px; padding-top: 8px; border-top: 1px solid #d5c8b7; font-size: 11px;">
                            <span style="color: #111827; font-weight: 700;">Search Feedback: </span>
                            <div style="display: flex; gap: 8px; margin-top: 5px; flex-wrap: wrap;">
                                ${links.map(source => `<a class="aegis-no-scan" href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer" style="color: #0f172a; font-weight: 600; text-decoration: underline; pointer-events: auto;">${escapeHtml(source.name)}</a>`).join('')}
                            </div>
                        </div>
                    `
                    : '';

                const takeaways = Array.isArray(reviewSummary.takeaways) ? reviewSummary.takeaways : [];
                const snippets = Array.isArray(reviewSummary.snippets) ? reviewSummary.snippets : [];
                
                const takeawaysHtml = takeaways.length > 0
                    ? `<ul style="margin: 8px 0 8px 16px; padding: 0; font-size: 11.5px; color: #111827; line-height: 1.5; font-weight: 500;">
                        ${takeaways.map(t => `<li style="margin-bottom: 4px;">${escapeHtml(t)}</li>`).join('')}
                       </ul>`
                    : '';

                const snippetsHtml = snippets.length > 0
                    ? `<div style="margin-top: 10px;">
                        <button id="aegis-expand-reviews-btn" style="background: #e8ded0; border: 1.5px solid #c7b9a5; color: #111827; padding: 5px 12px; border-radius: 7px; font-size: 11px; cursor: pointer; font-weight: 700;">
                            📖 Read Detailed Snippets (${snippets.length}) ▼
                        </button>
                        <div id="aegis-detailed-snippets" style="display: none; margin-top: 8px; padding: 10px 12px; background: #f0e8dc; border: 1px solid #d5c7b5; border-radius: 8px; font-size: 11px; color: #111827; max-height: 130px; overflow-y: auto; line-height: 1.5;">
                            ${snippets.map((s, idx) => `<div style="margin-bottom: 6px; padding-bottom: 6px; border-bottom: 1px solid #dfd2c0; font-style: italic; color: #111827;">"${escapeHtml(s)}"</div>`).join('')}
                        </div>
                       </div>`
                    : '';

                return `
                    <div class="aegis-card-section-title">Customer Feedback & Reviews</div>
                    <div style="font-size: 12px; color: #111827; background: #f2ede4; border: 1.5px solid #dcd1c1; padding: 12px 14px; border-radius: 12px; margin-bottom: 8px;">
                        <div style="font-weight: 800; color: #111827; font-size: 12.5px; margin-bottom: 5px;">
                            ${escapeHtml(reviewSummary.rating_label || 'Analyzed')}
                        </div>
                        <div style="line-height: 1.5; color: #111827; font-size: 12px; font-weight: 500;">${escapeHtml(reviewSummary.summary || '')}</div>
                        ${takeawaysHtml}
                        ${snippetsHtml}
                        ${linksHtml}
                    </div>
                `;
            };

            const reviewSectionHtml = buildReviewSection(data.review_summary);

            badgeContainer.innerHTML = `
                <div class="aegis-trust-card" id="aegis-trust-card">
                    <div class="aegis-card-header">
                        <div style="font-weight: 800; font-size: 14px; color: #111827; display: flex; align-items: center; gap: 7px;">
                            <span>${shieldIcon}</span>
                            <span>AegisAI Store Trust</span>
                        </div>
                        <span style="background: #e8ded0; border: 1.5px solid #c9bca9; padding: 3px 10px; border-radius: 14px; font-weight: 800; color: #111827; font-size: 11.5px;">
                            ${score}% Trust
                        </span>
                    </div>

                    <div class="aegis-card-section-title">Business Verification</div>
                    <div class="aegis-metric-pill">
                        <span style="color: #374151; font-weight: 600;">GSTIN Status</span>
                        <strong style="color: #111827; font-weight: 700;">${data.gstin_valid ? 'Valid Checksum' : (data.gstin ? 'Invalid Format' : 'Not Found')}</strong>
                    </div>

                    <div class="aegis-metric-pill">
                        <span style="color: #374151; font-weight: 600;">Payment Gateways</span>
                        <strong style="color: #111827; font-weight: 700;">${(data.payment_gateways && data.payment_gateways.length) ? data.payment_gateways.join(', ') : (data.signals?.has_upi_only ? 'UPI Only' : 'Standard')}</strong>
                    </div>

                    <div class="aegis-metric-pill">
                        <span style="color: #374151; font-weight: 600;">Domain Age</span>
                        <strong style="color: #111827; font-weight: 700;">${data.domain_age?.age_text || 'Active'}</strong>
                    </div>

                    ${reviewSectionHtml}
                </div>

                <div class="aegis-badge-btn" id="aegis-badge-toggle">
                    <span>${shieldIcon}</span>
                    <span>Store Trust: <strong style="color: #111827; font-weight: 800;">${score}%</strong></span>
                </div>
            `;

            document.body.appendChild(badgeContainer);

            const toggleBtn = document.getElementById('aegis-badge-toggle');
            const card = document.getElementById('aegis-trust-card');
            const expandReviewsBtn = document.getElementById('aegis-expand-reviews-btn');
            const detailedSnippets = document.getElementById('aegis-detailed-snippets');
            
            toggleBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                card.style.display = (card.style.display === 'block') ? 'none' : 'block';
            });

            if (expandReviewsBtn && detailedSnippets) {
                expandReviewsBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const isOpen = detailedSnippets.style.display === 'block';
                    detailedSnippets.style.display = isOpen ? 'none' : 'block';
                    expandReviewsBtn.textContent = isOpen 
                        ? `📖 Read Detailed Snippets (${data.review_summary?.snippets?.length || 0}) ▼`
                        : `📖 Hide Detailed Snippets ▲`;
                });
            }

            document.addEventListener('click', (e) => {
                if (!badgeContainer.contains(e.target)) {
                    card.style.display = 'none';
                }
            });
        });
    } catch (e) {
        // Silently skip if context invalidated
    }
}

// Run auto-detector after DOM content settles
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(injectStoreTrustBadge, 1500));
} else {
    setTimeout(injectStoreTrustBadge, 1500);
}
