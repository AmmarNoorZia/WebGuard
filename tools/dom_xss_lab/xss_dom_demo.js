// Harmless, marker-specific execution proof. No network or private data access.
(() => {
  const marker = document.currentScript?.dataset.webguardMarker;
  if (/^webguard-dom-[a-f0-9]{32}$/.test(marker || '')) {
    alert('WebGuard DOM XSS: ' + marker);
  }
})();
