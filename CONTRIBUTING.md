# Contributing

Use Node.js 24, install with `npm ci`, and run `npm test`, `npm run typecheck`, `npm run build` and the real browser acceptance in `scripts/acceptance.mjs`. Keep tests under tests/; private local reproduction records are not committed. Never include real customer evidence or secrets in tests, screenshots or issues.

For a cleanup bug, provide a minimal synthetic reproducer and the expected cleaned output. Reproduce first, add a failing regression, then fix the same shared engine. Do not disable checks or preserve unsupported data silently. UI changes must preserve keyboard access, review invalidation and clear raw/clean labels. Parser and ZIP changes require input/output bounds and source immutability checks.

Pillow 12.3 and Python 3 are needed only to regenerate the synthetic example PNG/JPEG fixtures with `python scripts/generate-fixtures.py`; they are not app-runtime dependencies. Third-party notice regeneration uses `node scripts/notices.mjs` and the pinned npm lockfile.
