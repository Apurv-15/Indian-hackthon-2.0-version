document.addEventListener('DOMContentLoaded', () => {
    chrome.runtime.sendMessage({ action: "health" }, (res) => {
        const footerStatus = document.getElementById('footer-status');
        if (footerStatus) {
            if (res && res.online) {
                footerStatus.innerHTML = `<span style="color: #166534;">●</span> Bridge: 5001 Online`;
            } else {
                footerStatus.innerHTML = `<span style="color: #991b1b;">●</span> Bridge: Offline`;
            }
        }
    });
});

document.getElementById('scan-page').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Check if we can inject into this tab (not chrome:// or other restricted pages)
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
        alert('Cannot scan special browser pages.');
        return;
    }

    chrome.tabs.sendMessage(tab.id, { action: "scanAllLinks" }, (response) => {
        if (chrome.runtime.lastError) {
            console.error(chrome.runtime.lastError);
            alert('Could not start scan. Please refresh the page and try again.');
        } else {
            window.close(); // Close popup after starting scan
        }
    });
});

const TRUST_COLORS = {
    ESTABLISHED: 'var(--safe)',
    STARTUP_VERIFIED: '#10b981',
    REPLICA_VERIFIED: '#6366f1',
    SOME_SIGNALS: 'var(--medium)',
    FEW_SIGNALS: 'var(--medium)',
    NO_SIGNALS: 'var(--high)',
    UNKNOWN: 'var(--high)'
};

const TRUST_LABELS = {
    ESTABLISHED: 'Established',
    STARTUP_VERIFIED: '🚀 Verified D2C Startup',
    REPLICA_VERIFIED: '📦 Master Copy — Delivery Verified',
    SOME_SIGNALS: 'Some Trust Signals',
    FEW_SIGNALS: 'Few Trust Signals',
    NO_SIGNALS: 'No Trust Signals',
    UNKNOWN: 'Unreachable'
};

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function buildReviewSection(reviewSummary) {
    if (!reviewSummary || (!reviewSummary.summary && (!reviewSummary.sources || reviewSummary.sources.length === 0))) {
        return '';
    }

    const reviewText = reviewSummary.summary || '';
    const evidenceText = typeof reviewSummary.review_confidence === 'number'
        ? `<div style="margin-top: 4px; color: var(--subtext); font-size: 10px;">Evidence confidence: ${Math.round(reviewSummary.review_confidence * 100)}% (${reviewSummary.evidence_sources_checked || 0} source${reviewSummary.evidence_sources_checked === 1 ? '' : 's'} checked)</div>`
        : '';
    const reviewColor =
        reviewSummary.sentiment === 'HIGH_RISK'
            ? 'var(--high)'
            : (reviewSummary.sentiment === 'MIXED' ? 'var(--medium)' : 'var(--safe)');

    const links = Array.isArray(reviewSummary.sources)
        ? reviewSummary.sources.filter(source => source?.name && source?.url)
        : [];

    const linksHtml = links.length
        ? `
            <div style="margin-top: 8px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,0.08); font-size: 10px;">
                <span style="color: var(--subtext);">Review Sources: </span>
                <div style="display: flex; gap: 8px; margin-top: 5px; flex-wrap: wrap;">
                    ${links.map(source => `<a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer" style="color: #38bdf8; text-decoration: underline;">${escapeHtml(source.name)}${source.checked ? ' ✓' : ' (not checked)'}</a>`).join('')}
                </div>
            </div>
        `
        : '';

    const takeaways = Array.isArray(reviewSummary.takeaways) ? reviewSummary.takeaways : [];
    const snippets = Array.isArray(reviewSummary.snippets) ? reviewSummary.snippets : [];
    
    const takeawaysHtml = takeaways.length > 0
        ? `<ul style="margin: 6px 0 6px 14px; padding: 0; font-size: 10.5px; color: var(--subtext); line-height: 1.4;">
            ${takeaways.map(t => `<li style="margin-bottom: 2px;">${escapeHtml(t)}</li>`).join('')}
           </ul>`
        : '';

    const snippetsHtml = snippets.length > 0
        ? `<div style="margin-top: 6px;">
            <button id="popup-expand-reviews-btn" style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #38bdf8; padding: 3px 8px; border-radius: 6px; font-size: 10px; cursor: pointer; font-weight: 600;">
                📖 Read Detailed Snippets (${snippets.length}) ▼
            </button>
            <div id="popup-detailed-snippets" style="display: none; margin-top: 6px; padding: 6px 8px; background: rgba(0,0,0,0.3); border-radius: 6px; font-size: 10px; color: var(--subtext); max-height: 100px; overflow-y: auto; line-height: 1.4;">
                ${snippets.map((s, idx) => `<div style="margin-bottom: 4px; padding-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,0.05); font-style: italic;">"${escapeHtml(s)}"</div>`).join('')}
            </div>
           </div>`
        : '';

    return `
        <div class="status-label">Customer Reviews & Sentiment</div>
        <div style="font-size: 11px; background: rgba(255,255,255,0.03); padding: 8px; border-radius: 6px; margin-bottom: 8px;">
            <strong style="color: ${reviewColor}">${escapeHtml(reviewSummary.rating_label || 'Analyzed')}</strong>
            <div style="color: #e2e8f0; margin-top: 3px; line-height: 1.4;">${escapeHtml(reviewText)}</div>
            ${evidenceText}
            ${takeawaysHtml}
            ${snippetsHtml}
            ${linksHtml}
        </div>
    `;
}

document.getElementById('check-store').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const button = document.getElementById('check-store');
    const resultBox = document.getElementById('trust-result');

    if (!tab.url || !tab.url.startsWith('http')) {
        alert('Open a store website first.');
        return;
    }

    button.disabled = true;
    button.textContent = 'Checking...';
    resultBox.style.display = 'block';
    resultBox.innerHTML = '<span style="color: var(--subtext)">Analyzing store…</span>';

    chrome.runtime.sendMessage({ action: 'storeTrust', url: tab.url }, (data) => {
        button.disabled = false;
        button.textContent = 'Check This Store';

        if (!data || data.error) {
            resultBox.innerHTML = `<span style="color: var(--high)">${(data && data.error) || 'Check failed.'}</span>`;
            return;
        }

        const color = TRUST_COLORS[data.trust_level] || 'var(--subtext)';
        const label = TRUST_LABELS[data.trust_level] || data.trust_level;
        const reasons = (data.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');
        const recs = (data.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');

        const entityBadge = escapeHtml(data.business_entity || (data.gstin_valid ? 'GSTIN Verified' : 'Standard Store'));
        const paymentBadges = (data.payment_gateways && data.payment_gateways.length) ? data.payment_gateways.join(', ') : (data.signals?.has_upi_only ? '<span style="color: var(--high)">⚠️ UPI Only</span>' : 'Standard');
        const domainAgeText = data.domain_age?.age_text || 'Active';
        const reviewSectionHtml = buildReviewSection(data.review_summary);

        resultBox.innerHTML = `
            <div class="trust-score-line" style="color: ${color}; font-size: 14px; font-weight: bold; margin-bottom: 8px;">${label} — ${Math.round((data.trust_score || 0) * 100)}% Trust</div>
            
            <div style="background: rgba(255,255,255,0.05); padding: 8px; border-radius: 8px; margin-bottom: 8px; font-size: 11px;">
                <div>🏛️ <strong>Entity:</strong> ${entityBadge}</div>
                <div style="margin-top: 4px;">💳 <strong>Payments:</strong> ${paymentBadges}</div>
                <div style="margin-top: 4px;">📅 <strong>Age:</strong> ${domainAgeText}</div>
            </div>

            ${reviewSectionHtml}

            <div class="status-label">Legitimacy Signals</div>
            <ul>${reasons}</ul>
            <div class="status-label">Recommendations</div>
            <ul>${recs}</ul>
        `;

        const expandBtn = document.getElementById('popup-expand-reviews-btn');
        const snippetsBox = document.getElementById('popup-detailed-snippets');
        if (expandBtn && snippetsBox) {
            expandBtn.addEventListener('click', () => {
                const isOpen = snippetsBox.style.display === 'block';
                snippetsBox.style.display = isOpen ? 'none' : 'block';
                expandBtn.textContent = isOpen
                    ? `📖 Read Detailed Snippets (${data.review_summary?.snippets?.length || 0}) ▼`
                    : `📖 Hide Detailed Snippets ▲`;
            });
        }
    });
});
