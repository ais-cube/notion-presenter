document.addEventListener('DOMContentLoaded', () => {
  const startBtn = document.getElementById('startBtn');
  const statusEl = document.getElementById('status');
  const themeSelect = document.getElementById('themeSelect');

  // Security: strict Notion URL pattern (only https, only notion domains)
  const NOTION_URL_RE = /^https:\/\/[a-z0-9-]+\.notion\.(site|so)\//i;

  // Security: whitelisted values — reject anything else
  const ALLOWED_SPLITS = Object.freeze(['divider', 'h1', 'h2', 'h1h2']);
  const ALLOWED_THEMES = Object.freeze(['light', 'dark', 'notion', 'gradient']);

  /** Safely set status text (capped length, no HTML). */
  function setStatus(text, type) {
    statusEl.textContent = String(text).substring(0, 200);
    statusEl.className = `status ${type}`;
  }

  // Check if we're on a Notion page
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    const url = tab?.url || '';
    if (!NOTION_URL_RE.test(url)) {
      startBtn.disabled = true;
      setStatus('Open a published Notion page first', 'error');
    }
  });

  startBtn.addEventListener('click', () => {
    const splitModeEl = document.querySelector('input[name="splitMode"]:checked');
    const splitMode = splitModeEl?.value;
    const theme = themeSelect.value;
    const showToc = document.getElementById('showToc').checked;

    // Security: validate before sending
    if (!ALLOWED_SPLITS.includes(splitMode)) {
      setStatus('Invalid split mode', 'error');
      return;
    }
    if (!ALLOWED_THEMES.includes(theme)) {
      setStatus('Invalid theme', 'error');
      return;
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];

      // Security: re-validate URL before sending message to content script
      if (!tab?.id || !NOTION_URL_RE.test(tab.url || '')) {
        setStatus('Not a Notion page', 'error');
        return;
      }

      chrome.tabs.sendMessage(tab.id, {
        action: 'startPresentation',
        splitMode,
        theme,
        showToc
      }, (response) => {
        if (chrome.runtime.lastError) {
          setStatus('Error: reload the Notion page and try again', 'error');
          return;
        }
        // Security: validate response shape
        if (response?.success === true && typeof response.slideCount === 'number') {
          setStatus(`${response.slideCount} slides ready!`, 'success');
          window.close();
        } else {
          setStatus(response?.error || 'Could not parse slides', 'error');
        }
      });
    });
  });
});
