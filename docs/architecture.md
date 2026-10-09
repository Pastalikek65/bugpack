# Architecture

React renders a local evidence workspace. Text inputs are decoded with fatal UTF-8 validation. A separate worker invokes pure TypeScript HAR/log redaction and ZIP generation. Image headers are inspected before decoding; the worker uses a fresh OffscreenCanvas, opaque pixel masks and PNG re-encoding. Each operation owns a worker, has a deadline, and terminates it on success, failure or cancellation.

The Node.js CLI uses the same pure redaction engine as the browser workers. Policies are versioned local JSON, validate before use and cannot disable baseline credential cleanup. Export uses the same active policy again; the summary omits clear-text policy contents. Text and metadata never become rendered HTML; React escapes them. ZIP entry names are generated rather than derived from imported paths. Bundle generation re-sanitizes edited text and validates regenerated PNG chunks. Fixed omission descriptions prevent imported metadata from becoming a new secret channel in the summary.

There is no content-upload backend, service worker, analytics or remote asset. The included static server accepts GET/HEAD on 127.0.0.1, sends a restrictive CSP with `connect-src 'none'`, and prevents paths escaping its configured directory. Original previews can contain private content; reports deliberately preserve useful reviewed text and pixels. The architecture does not prove that all personal information can be found automatically.

The bundled files are trusted local inputs. Path checks and restrictive headers do not sandbox an attacker who can concurrently replace writable filesystem ancestors. Serve from a directory you control. The deterministic policy fingerprint can reveal guessed low-entropy policy values; review the summary before sharing.
