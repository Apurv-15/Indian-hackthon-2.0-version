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
    SOME_SIGNALS: 'var(--medium)',
    FEW_SIGNALS: 'var(--medium)',
    NO_SIGNALS: 'var(--high)',
    UNKNOWN: 'var(--high)'
};

const TRUST_LABELS = {
    ESTABLISHED: 'Established',
    SOME_SIGNALS: 'Some Trust Signals',
    FEW_SIGNALS: 'Few Trust Signals',
    NO_SIGNALS: 'No Trust Signals',
    UNKNOWN: 'Unreachable'
};

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
        const reasons = (data.reasons || []).map(r => `<li>${r}</li>`).join('');
        const recs = (data.recommendations || []).map(r => `<li>${r}</li>`).join('');

        resultBox.innerHTML = `
            <div class="trust-score-line" style="color: ${color}">${label} — ${Math.round((data.trust_score || 0) * 100)}%</div>
            <div class="status-label">Signals</div>
            <ul>${reasons}</ul>
            <div class="status-label">Recommendations</div>
            <ul>${recs}</ul>
        `;
    });
});
