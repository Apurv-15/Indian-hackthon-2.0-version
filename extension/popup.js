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
