# Local text CLI

Node.js 24 is required. In an extracted package, run `node cli/bugpack.mjs --help`; in a source checkout, run `npm ci`, `npm run build`, then `node dist/cli/bugpack.mjs --help`. No account or network connection is required for processing.

```sh
node cli/bugpack.mjs --version
node cli/bugpack.mjs doctor --json
node cli/bugpack.mjs clean --kind har --input request.har --out request-clean.har --json
node cli/bugpack.mjs clean --kind log --input app.log --out app-clean.log
node cli/bugpack.mjs policy validate --file bugpack-policy.json --json
node cli/bugpack.mjs bundle --har request-clean.har --log app-clean.log --report report.json --out reviewed.zip --reviewed
```

`--version --json` reports the version embedded in the CLI at build time. `doctor --json` includes that same version and checks the required Node.js runtime.

Create the output parent directory first. Existing outputs are never overwritten. Input files remain unchanged. The CLI refuses links and non-regular inputs; diagnostic JSON uses stable error codes and does not print file contents. `--har` and `--log` may be repeated up to the shared 50-file and 64 MiB limits.

The CLI supports HAR and UTF-8 text. Process PNG/JPEG screenshots in the browser workbench, where you can inspect pixels and apply opaque masks. CLI image inputs fail explicitly.

Run in directories you control. Link checks and exclusive output creation protect normal local use; they do not isolate an attacker who can concurrently replace writable parent directories. The CLI is not a filesystem sandbox.

Review each cleaned file and the final ZIP before sharing. `--reviewed` is an explicit acknowledgement, not a guarantee that automatic cleanup found everything. Without `--report`, the generated report contains visibly incomplete placeholders; replace them before sharing. A report file contains string fields `title`, `steps`, `expected`, `actual` and `environment`.

## Reusing a policy

Use the browser's **Cleaning policy** panel to save a version 1 policy, then pass `--policy bugpack-policy.json` to `clean` or `bundle`. Saved policy files contain literal match values and may themselves contain secrets; keep them private. The ZIP summary includes a policy fingerprint and body mode, not the policy name, keys or literal values.

The fingerprint is a deterministic SHA-256 identifier of the complete canonical policy, not a secret or anonymization guarantee. Someone who can guess a low-entropy match value can test that guess against the fingerprint. Inspect the processing summary as part of your sharing review; a policy containing private values can make this identifier sensitive.

Policies add bounded field names and literal replacements. They cannot disable the built-in credential rules. Unknown versions, ambiguous JSON and unsupported fields are rejected. Regular-expression execution is not supported.

The default omits all HAR bodies. Opt-in supported-body mode cleans valid UTF-8 `application/json` and `application/x-www-form-urlencoded` text in request and response bodies. Binary/base64, other media types, malformed or ambiguous content and unsupported parameter representations are omitted with explicit summary reasons. Manually inspect retained content for private values beyond your rules.

Default exports preserve processing-summary version 1. An explicitly selected policy produces version 2 with the same file and limitations fields plus `policy: {schemaVersion, id, bodyMode}`. Policy files and processing summaries are different formats; a summary cannot be imported as a policy.
