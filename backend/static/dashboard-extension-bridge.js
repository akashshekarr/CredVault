// AppVault Extension Bridge — drop into user_dashboard.html
// This script connects the portal page to the AppVault browser extension.
// It does three things:
//   1. Detects whether the extension is installed
//   2. Shows a "Connect Extension" / "Extension Paired" UI in the header
//   3. Exposes window.AppVaultBridge.openWithExtension(appName, appUrl) for the
//      "Open ChatGPT" button to use instead of plain window.open.

(function () {
  'use strict';

  // The extension ID. For local dev (unpacked), copy it from chrome://extensions
  // and set it once via DevTools console:
  //   localStorage.setItem('appvault_ext_id', 'abcdef1234567890abcdef1234567890');
  // For production, hardcode the Chrome Web Store ID below.
  const HARDCODED_EXT_ID = ''; // <- fill in once published to Web Store

  function getExtId() {
    return HARDCODED_EXT_ID || localStorage.getItem('appvault_ext_id') || '';
  }

  function sendToExtension(payload) {
    return new Promise((resolve) => {
      const id = getExtId();
      if (!id || !window.chrome?.runtime?.sendMessage) {
        resolve({ ok: false, error: 'Extension not configured or chrome.runtime unavailable' });
        return;
      }
      try {
        chrome.runtime.sendMessage(id, payload, (resp) => {
          if (chrome.runtime.lastError) {
            resolve({ ok: false, error: chrome.runtime.lastError.message });
            return;
          }
          resolve(resp || { ok: false, error: 'No response' });
        });
      } catch (e) {
        resolve({ ok: false, error: String(e.message || e) });
      }
    });
  }

  // ── Public API used by the dashboard's "Open" button ────────────────────────
  async function openWithExtension(appName, appUrl) {
    const status = await sendToExtension({ action: 'status' });
    if (!status?.ok || !status.paired) {
      // Fall back: open in a new tab without autofill
      window.open(appUrl, '_blank', 'noopener');
      return { fellBack: true };
    }
    const r = await sendToExtension({ action: 'open', app_name: appName, app_url: appUrl });
    if (!r?.ok) {
      window.open(appUrl, '_blank', 'noopener');
      return { fellBack: true, error: r?.error };
    }
    return { fellBack: false };
  }

  // ── Pairing UI (in-header pill) ─────────────────────────────────────────────

  async function startPairing() {
    if (!getExtId()) {
      const id = prompt(
        'Enter the AppVault extension ID.\n\n' +
        'Find it at chrome://extensions (with Developer mode on).\n' +
        'Looks like: abcdef1234567890abcdef1234567890'
      );
      if (!id) return;
      localStorage.setItem('appvault_ext_id', id.trim());
    }
    // Mint pairing code on the server (uses session cookie — user must be logged in)
    let codeResp;
    try {
      const r = await fetch('/api/extension/pair', { method: 'POST' });
      codeResp = await r.json();
      if (!r.ok) throw new Error(codeResp.error || 'Failed to generate pairing code');
    } catch (e) {
      alert('Pairing failed: ' + e.message);
      return;
    }
    // Send code to the extension
    const sent = await sendToExtension({ action: 'pair', code: codeResp.code });
    if (!sent?.ok) {
      alert('Could not send code to extension: ' + (sent?.error || 'unknown error') +
            '\n\nMake sure the AppVault extension is installed and the extension ID is correct.');
      return;
    }
    refreshPill();
  }

  async function unpair() {
    if (!confirm('Unpair this device from AppVault?')) return;
    await sendToExtension({ action: 'unpair' }).catch(() => {});
    refreshPill();
  }

  function injectStyles() {
    if (document.getElementById('appvault-bridge-styles')) return;
    const s = document.createElement('style');
    s.id = 'appvault-bridge-styles';
    s.textContent = `
      .av-pill{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:600;
        padding:5px 10px;border-radius:999px;cursor:pointer;border:1px solid var(--border-soft);
        background:var(--surface);color:var(--text-dim);font-family:'Space Grotesk',sans-serif;
        margin-right:8px;transition:all 0.18s}
      .av-pill:hover{border-color:var(--cyan);color:var(--cyan)}
      .av-pill.paired{color:#8FF1BC;border-color:rgba(79,227,155,0.3);background:rgba(79,227,155,0.08)}
      .av-pill.paired:hover{border-color:rgba(79,227,155,0.55);color:#8FF1BC}
      .av-dot{width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 6px currentColor}
    `;
    document.head.appendChild(s);
  }

  async function refreshPill() {
    injectStyles();
    let pill = document.getElementById('av-pill');
    if (!pill) {
      const userArea = document.querySelector('.user-area');
      if (!userArea) return;
      pill = document.createElement('button');
      pill.id = 'av-pill';
      pill.className = 'av-pill';
      userArea.insertBefore(pill, userArea.firstChild);
    }
    const status = await sendToExtension({ action: 'status' });
    if (status?.ok && status.paired) {
      pill.className = 'av-pill paired';
      pill.innerHTML = '<span class="av-dot"></span> Extension paired';
      pill.title = 'Click to unpair';
      pill.onclick = unpair;
    } else if (status?.ok && !status.paired) {
      pill.className = 'av-pill';
      pill.innerHTML = '⚡ Pair Extension';
      pill.title = 'Connect the AppVault extension';
      pill.onclick = startPairing;
    } else {
      // Extension not detected at all — offer install hint
      pill.className = 'av-pill';
      pill.innerHTML = '⬇ Install Extension';
      pill.title = 'AppVault extension not detected. Click for instructions.';
      pill.onclick = () => {
        if (!getExtId()) {
          startPairing(); // will prompt for ID
        } else {
          alert('AppVault extension not detected.\n\n' +
                'Make sure the extension is loaded and the ID matches.\n' +
                'Current ID: ' + getExtId());
        }
      };
    }
  }

  // Expose the API for use by the dashboard's openCredModal / showCredentials
  window.AppVaultBridge = {
    openWithExtension,
    refreshPill,
    isAvailable: () => !!getExtId(),
  };

  // Run pill on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', refreshPill);
  } else {
    refreshPill();
  }
})();