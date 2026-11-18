// Harmless same-origin proof. No network, credentials, cookies, or data access.
// document.currentScript ties execution to one injected comment, even when old
// scanner comments remain. CSP script-src 'self' stays enabled on Site A.
(() => {
  const marker = document.currentScript?.dataset.webguardMarker;
  if (/^webguard-stored-[a-f0-9]{32}$/.test(marker || '')) {
    alert('WebGuard stored XSS: ' + marker);
  }
})();
