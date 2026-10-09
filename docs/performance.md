# CLI performance measurement

This development runner requires a source checkout and `npm ci`; the runner is not included in portable packages. Run the following commands from that checkout, including when measuring a separately extracted package.

Run one repeatable synthetic workload against the built Node CLI:

```sh
npm run build
node scripts/benchmark.mjs
```

For an extracted package, point the runner at both the extracted root and the exact package archive:

```sh
node scripts/benchmark.mjs --app-root <extracted-package> --package <package-archive>
```

Each run creates a fresh ignored `artifacts/benchmark-*` directory and refuses to reuse an existing one. It writes a 4 MiB synthetic log, a 1,000-entry HAR, a report, and an opt-in policy that retains valid JSON and URL-encoded form bodies. The HAR contains 334 JSON, 333 form, and 333 base64 binary response bodies. Validation checks the expected body kind at every entry index, retained-body content and credential replacement, omitted binary bodies, and the exact policy fingerprint in both the ZIP summary and CLI JSON response. It also checks that synthetic markers occur in their inputs and are absent from the ZIP text, and that generated inputs remain byte-identical after the CLI run.

Before `fflate` reads the generated bundle, the benchmark validates the raw ZIP under a 32 MiB archive limit, 1,000-member limit, and 32 MiB aggregate expanded-content limit. It checks duplicate names, local and central framing, record overlap or gaps, sizes, CRCs, and complete DEFLATE consumption. It then requires `fflate` to return the same members and bytes. The product's larger output limit does not raise the benchmark's smaller measurement bound.

In packaged mode, the public static-package inspector verifies the archive against the extracted application root before and after the CLI run. The benchmark also checks that the root's `package.json` and `cli/bugpack.mjs` bytes and hashes match those exact archive members, and that the inspected package remains unchanged during the run.

`benchmark.json` records the exact child command, Node/package/CLI identities, Git commit and dirty-source snapshot, platform and CPU details, input/output SHA-256 hashes, raw CLI JSON and exit status, validation checks, parent wall time, and the child's profile. The profiler is loaded into the actual CLI child with Node's `--require` option. Bundle creation time includes process startup and exit but excludes fixture generation and post-run ZIP checks.

`process.resourceUsage().maxRSS` is recorded for the CLI child only. [Node.js v24 documents this field in kibibytes (1,024 bytes)](https://nodejs.org/download/release/v24.21.0/docs/api/process.html#processresourceusage); the JSON keeps the raw value and its byte conversion. If the runtime reports zero or no usable value, the run records the metric as unavailable instead of treating zero as measured memory. CPU time is the child process's user and system CPU time in microseconds. These figures do not measure the browser, worker processes, or whole-machine memory.

The workload exercises a bounded local bundle path, not a universal performance limit. A run that hits a product work cap is recorded as failed; the benchmark does not increase product limits to force completion. It reports one machine-specific sample without a throughput target or cross-machine comparison. Automatic redaction remains incomplete, and the synthetic checks are not a privacy guarantee for real evidence.

## Stable 1.0.0 CI samples

CI run [37921280761](https://github.com/Pastalikek65/bugpack/actions/runs/37921280761), at clean source `97805ce3d17384f91e0b6afced4587bfd3c55bf7`, recorded the same synthetic workload in source and freshly extracted package modes. All four records passed on Node 24.21.0 and are bound by the release's `verification.json`. Each is one machine-specific sample; parent time includes CLI process startup and exit, while child time and maximum RSS cover only the CLI child.

| CI platform | Mode | Parent wall time | CLI child wall time | CLI child maximum RSS |
| --- | --- | ---: | ---: | ---: |
| Windows x64 | Source | 450.6 ms | 397.4 ms | 121,430,016 bytes |
| Windows x64 | Extracted package | 446.8 ms | 393.0 ms | 119,795,712 bytes |
| Ubuntu 24.04 x64 | Source | 532.1 ms | 497.9 ms | 138,608,640 bytes |
| Ubuntu 24.04 x64 | Extracted package | 528.2 ms | 494.0 ms | 137,793,536 bytes |

The workload uses a 4 MiB synthetic log and a 1,000-entry HAR. These four samples do not establish a throughput target, cross-machine comparison or process-memory bound. They cover only the CLI child and synthetic local inputs; see [verification](verification.md#stable-100-release) for release scope and limitations.

## Historical 0.2.0 beta CI samples

CI run [37912575939](https://github.com/Pastalikek65/bugpack/actions/runs/37912575939), at source `20c6cc524dc0cd4153c0ae718a606507c6ee9aad`, ran the same workload in both source and freshly extracted package modes. Node was 24.21.0; each record was checked against its CI job/step time window, raw profile, seeded inputs, complete output ZIP and exact CLI/package identity. These four samples describe the **0.2.0 beta** only; use the stable 1.0.0 section above for the 1.0.0 CI samples.

| CI platform | Mode | Parent wall time | CLI child wall time | CLI child maximum RSS |
| --- | --- | ---: | ---: | ---: |
| Windows x64 | Source | 326.8 ms | 281.9 ms | 120,987,648 bytes |
| Windows x64 | Extracted package | 334.2 ms | 287.4 ms | 126,668,800 bytes |
| Ubuntu 24.04 x64 | Source | 553.7 ms | 522.4 ms | 134,258,688 bytes |
| Ubuntu 24.04 x64 | Extracted package | 511.7 ms | 480.0 ms | 135,475,200 bytes |

The parent timing includes process startup and exit; child timing and maximum RSS cover only the actual CLI process. They exclude the browser, workers and other machine processes. These measurements are not throughput promises or a valid cross-machine performance comparison. Each retained raw record includes CPU time, hashes, profiler units and availability. Release verification binds the exact records; a fresh candidate must rerun them. The review retains the distinction between measured values and unavailable metrics.

## Pre-freeze development baseline

The recorded sample below is a pre-freeze, dirty Windows 11 development baseline only. It is not a performance measurement of a frozen or public package, and it does not qualify a release. The run's Git commit pointer was `de47154576f9e260fa6de286d785bbca56c1f77d`, but the source snapshot contained 39 dirty or untracked paths. Its `sourceStateBefore.sha256` is `455f4373abb85eaa4bf66d00cb271f0df359e079563b39768431ca798a222412`; this is a raw machine-local snapshot, not a CI-verified source identity or public attestation. Linux performance and frozen-package performance remain unmeasured here.

The sample used Node.js 24.21.0 on Windows x64, OS build 10.0.26300, with an AMD Ryzen 9 8945HX and 32 logical CPUs. It processed a 4,194,304-byte log and a 1,581,205-byte HAR with 1,000 entries. The CLI child took 288.6 ms wall time and reached 121,475,072 bytes maximum RSS; its user and system CPU readings were 344,000 µs and 62,000 µs. The parent measured 347.7 ms around the child process. The resulting ZIP was 567,481 bytes.

The run passed raw ZIP framing and inflation checks, exact schema-2 policy identity checks, all per-index body checks including exact generated chunk contents, synthetic-marker checks, and input/source/CLI identity checks. The app was run from the local source-mode `dist/cli/bugpack.mjs` entry at version `0.2.0`; the CLI entry SHA-256 was `738aad01b7c8a8340ae22cb212e69103c288f76893f5be1338b0447d8e532767`. The output ZIP SHA-256 was `88705e17e4c1c18c411a110b264cec583d76c7f6d1882b4d39c60104e1198c4d`.

The raw record is at the ignored, machine-local path `artifacts/benchmark-2026-10-09T09-32-54-812Z-5d3e9d16-3fc1-42dc-bd06-d4e55cc5a2fc/benchmark.json` (SHA-256 `dbbd619566740933016ebbe1d88df2a883f4825092678b98be16ca43c618845a`). It is preserved locally for inspection and is not checked into the repository, uploaded as a release artifact, or evidence of CI or public-package qualification. A separate local packaged-mode run also passed the archive/root pairing checks against a pre-release package; it is likewise only a local development check.
