# BugPack

Inspect debugging evidence locally, remove sensitive values, and share a reviewed ZIP containing clean files and a bug report.

BugPack is for developers and support teams who need to share a HAR, log or screenshot without attaching its original credentials and metadata. The working MVP source is public; downloadable preview packages are being qualified on Windows and Linux. A stable release is not yet published. It runs as a static browser app without an account, upload backend, paid API or remote model.

![Actual synthetic evidence review and opaque mask](examples/outputs/review.png)

See the [actual processing summary](examples/outputs/processing-summary.json) and [generated Markdown report](examples/outputs/bug-report.md). These files come from the real browser acceptance, not a mockup.

[![CI](https://github.com/Pastalikek65/bugpack/actions/workflows/ci.yml/badge.svg)](https://github.com/Pastalikek65/bugpack/actions/workflows/ci.yml)

## First report

Requires Node.js 24 and a current Chromium browser on Windows or Linux x64.

```sh
npm ci
npm run build
node scripts/serve.mjs --root dist --port 4174
```

Open `http://127.0.0.1:4174`. Choose `examples/sample.har`, `sample.log` and `sample.png`. Review **Original text** beside the editable clean copy. Remove the example email manually: automatic patterns do not find every personal value. On the screenshot, cover the highlighted token with an opaque mask, then choose **Apply masks and regenerate PNG**. Complete the report fields, review every clean file, and choose **Build and download ZIP**.

The ZIP contains neutral `evidence-*` filenames, a Markdown report and `processing-summary.json`. Originals and original filenames are not included automatically. HAR bodies, cookies, unapproved headers and unknown extension fields are omitted in the MVP and counted in the summary. All input files remain unchanged.

[Türkçe hızlı başlangıç](docs/quickstart.tr.md) · [Supported inputs and limits](docs/support.md) · [Architecture](docs/architecture.md) · [Roadmap](docs/roadmap.md)

## Review before sharing

Known authorization, cookie, credential assignment and signed-URL patterns are removed automatically. The cleaned text is editable. Screenshot masks cover whole pixels with opaque black; outputs are newly encoded PNGs without ancillary metadata. Original previews remain local and can contain secrets. Inspect URLs, names, text, pixels and the report before sharing. BugPack does not guarantee detection of every secret or personal value.

A failed input blocks export until it is removed. Editing evidence, report fields or masks invalidates the review acknowledgement. File processing and ZIP creation run in dedicated workers with explicit cancellation and deadlines.

## Development

```sh
npm test
npm run typecheck
npm run build
node scripts/acceptance.mjs
```

The acceptance harness uses real Chromium, workers, downloads, ZIP inspection and decoded PNG pixel checks. Synthetic fixture bytes are bound by `examples/manifest.json`. See [verification](docs/verification.md) for current evidence and unqualified states. The app uses Apache-2.0; bundled third-party licenses and the dependency inventory are in [third_party](third_party/README.md).
