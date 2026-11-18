WebGuard v0.4.0 — Stored XSS Scanner

This checkpoint preserves the working Reflected XSS scanner and adds the
completed Stored XSS scanner to the existing authenticated scan, findings,
history, and PDF reporting flow. Release preparation changes documentation
only; it does not change scanner behavior or introduce another feature.

- Stored XSS requires independent retrieval of the saved comment and execution
  of its unique marker in a fresh Google Chrome context, with CSP enabled.
- Tests remain restricted to HTTP loopback targets on ports 5001 and 5002;
  redirects and unrelated browser requests are blocked.
- Scanner-created comments are removed through token-protected cleanup.
- Reflected XSS remains available through its existing API and UI option.
- Existing Supabase JWT checks, ownership filters, RLS, atomic scan persistence,
  and the shared PDF generator are reused. No new SQL migration is required.
- Reproducible comments-lab support, regression tests, and Windows commands are
  included in [STORED_XSS_SETUP.md](STORED_XSS_SETUP.md).

Validation for this release checkpoint (November 18, 2026):

| Check | Result |
| --- | --- |
| Backend pytest with browser/UI options enabled | 110 passed, 7 skipped, plus 6 passing unittest subtests. |
| Actual Desktop labs with installed Google Chrome | 3 passed; both Reflected and Stored XSS confirmed on A and not detected on B. |
| Required backend unittest command | 14 passed. |
| Website A regression suite | 21 passed. |
| Website B regression suite | 17 passed. |
| React production build | Passed with the existing Vite bundle-size advisory. |
| Repository credential and exclusion audit | No local environment credential values, private keys, or live tokens found in release files; runtime data remains ignored. |

Four fixture/UI tests were skipped because existing applications occupied the
required ports; those processes were left running. The other three skipped
tests are opt-in live-lab tests, which passed in the separate actual-lab run.
The earlier full fixture/UI run passed 114 tests, including refreshed scan
history, Findings, both PDF downloads, and light/dark themes; its details remain
in the implementation handoff. Live Supabase persistence and deployed RLS were
not reverified using a signed-in user session; API/database contracts use mocks.

This release includes the PDF reporting source and tests. Generated PDFs,
screenshots, logs, databases, virtual environments, and `.env` files are excluded
from Git. The unrelated pre-existing `backend/scanners/discovery.py` scratch
script remains untracked and is not part of this checkpoint.

The release branch starts from the fetched latest `main`, including the merged
v0.3.0 milestone. Publish it with a normal push and annotated `v0.4.0` tag; do not
force-push or replace an existing tag. The separate Desktop lab folders are not
part of this Git repository; their additive comments-support installer is.
