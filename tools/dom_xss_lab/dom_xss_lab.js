// Local teaching exercise. No requests, credentials, or cookie access.
(() => {
  const section = document.querySelector('[data-webguard-dom="v1"]');
  const value = decodeURIComponent(window.location.hash.slice(1));
  const input = document.getElementById('dom-input');
  input.value = value;
  document.getElementById('dom-form').addEventListener('submit', event => {
    event.preventDefault();
    window.location.hash = encodeURIComponent(input.value);
    window.location.reload();
  });
  if (section.dataset.rendering === 'unsafe') {
    // A ONLY: attacker-controlled fragment becomes parser input. Unlike inert
    // innerHTML script tags, document.write can execute same-origin scripts
    // while this parser-blocking script runs, without relaxing script-src self.
    document.write('<div id="dom-result">' + value + '</div>');
  } else {
    // B: the identical input is displayed as text and never parsed as HTML.
    const result = document.createElement('div');
    result.id = 'dom-result';
    result.textContent = value;
    document.getElementById('dom-output').appendChild(result);
  }
  section.dataset.webguardDomReady = 'true';
})();
