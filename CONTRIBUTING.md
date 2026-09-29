# Contributing a Zeus community feature

This is the canonical guide for feature authors, reviewers, and automation
agents. The JSON schemas under `schema/` are the machine-readable JSON-shape
contract; the scripts under `tools/` enforce catalog, archive, and cross-platform
path policy. If the guide, a schema, and a validator disagree, stop and open an
issue rather than guessing.

A feature is developed and released from the author's own source repository.
This repository hosts the public SDK snapshot, starter template, validation
tools, and `registry.json`; a normal feature-listing pull request changes only
`registry.json`. Approved ZIPs are stored separately as immutable Zeus-SDR
release assets; feature source and binaries are never committed to this Git
tree.

## 1. Public SDK and security boundary

Use only:

- the public types in `sdk/Zeussdr.Zeus.Plugins.Contracts/`;
- the manifest fields in `schema/plugin.schema.json`;
- `registerPanel` and `callBackend`, the complete ABI-1 browser API described
  below.

Do not request, copy, translate, reconstruct, or depend on private Zeus source,
host/loading implementations, frontend modules, DOM structure, internal state
stores, undocumented API routes, DSP or radio protocol logic, credentials,
native libraries, or compiled product artifacts. Do not use reflection or
implementation-specific behavior to reach around the public contracts. If the
SDK is missing a capability, open an issue describing the public use case.

PureSignal is forbidden. A community feature may not inspect or change
PureSignal logic, arm/disarm or startup state, persistence, calibration,
attenuation defaults, feedback selection, or an endpoint that indirectly
changes those behaviors. A feature must never auto-key a transmitter.

Community packages execute in-process. Capabilities, permissions, assembly load
contexts, catalog review, and `verified` metadata are disclosure and
compatibility mechanisms, not a security sandbox or warranty.

## 2. Build the feature in its own repository

1. Copy `templates/hello-world/`, `sdk/`, and `Directory.Build.props` into a new
   public feature repository. Preserve the template-to-SDK project-reference
   layout, or update that relative reference explicitly.
2. Replace every sample ID, assembly name, namespace, URL, and metadata value.
3. Choose a permanent, globally unique reverse-DNS ID such as
   `com.example.callsignlogger`. Use the same ID everywhere.
4. Reference the vendored contracts project, or a matching published contracts
   package when one becomes available. Never depend on a sibling or private
   Zeus checkout.
5. Add a feature-owned `LICENSE`, third-party notices, operator documentation,
   and tests for behavior whose regression could affect an operator or radio.
   Update the copied packaging script to include that feature-owned license,
   never the catalog repository's license by accident.
6. Keep the complete corresponding source, project files, dependency lockfiles,
   build/package scripts, license, and notices public. Tag the exact source used
   for every submitted release so reviewers can reproduce and audit it.
7. Build and package from a clean checkout on every declared platform.

The ZIP must contain exactly one top-level `plugin.json` and the entrypoint DLL
named by that manifest. Do not bundle `Zeus.Plugins.Contracts.dll`, framework
assemblies, secrets, credentials, build caches, or unrelated source files.

The copied packaging script automatically includes declared `ui.modules`, a
declared bundled `audio.vst3Path`, the entrypoint `.deps.json`, the feature
license, and notices. List each additional managed DLL by plain filename with
`-ManagedDependency`; list other feature-relative files or directories with
`-AdditionalAsset`. Both parameters may be repeated/array-valued. For example:

```powershell
& ./templates/hello-world/build-package.ps1 `
  -ManagedDependency @("Example.Protocol.dll") `
  -AdditionalAsset @("ui/chunk.js", "assets")
```

Every input is containment-checked, links are rejected, and collisions fail the
build. Do not modify the script to bypass these checks.

## 3. Manifest schema and naming rules

`schema/plugin.schema.json` is authoritative. Store submissions use schema
version 1, SDK ABI 1, and the lowest SDK version whose APIs they use. Keep these
values identical between the embedded manifest and the catalog version:

| Embedded `plugin.json` | `registry.json` version |
|---|---|
| `id` | parent entry `id` |
| `version` | `version` |
| `sdk.abi` | `sdkAbi` |
| `sdk.minVersion` | `sdkMinVersion` |

Use lowercase reverse-DNS IDs. Use SemVer `major.minor.patch`, optionally with a
valid pre-release or build suffix. Entrypoint and UI-module paths are relative
package paths: never absolute, never `..`, and never URLs.

When `audio` is present, specify `format`, `slot`, `channels`, and `sampleRate`
explicitly. The schema lists the supported formats, processing slots, channel
counts, sample rates, and format-specific identity fields; do not invent values.
Use `format: "managed"` for a direct `IAudioPlugin`, `format: "vst3"` with a
non-null bundled `vst3Path`, or `format: "au"` with a non-null
`auComponentId`.

Declare only capabilities and permissions the feature actually uses. ABI 1
automatically grants declared capabilities; there is no permission prompt.
Network, filesystem, native-code, child-process, audio-stream, and radio-control
behavior receives elevated review. Undeclared privileged behavior is grounds
for rejection or removal.

For a visual feature, every `ui.panels[].id` must be unique inside the feature
and must exactly match one `registerPanel({ id, component })` call. Supported UI
slots are:

| Slot | Purpose |
|---|---|
| `workspace.<feature>` | Operator-addable workspace panel; use a stable lowercase suffix. |
| `tx-audio-tools.chain` | TX audio-chain contribution. |
| `rx-audio-tools.chain` | RX audio-chain contribution. |

The browser module's default export receives this complete public surface:

```ts
interface ZeusPluginApi {
  registerPanel(spec: { id: string; component: React.ComponentType }): void;
  callBackend(method: string, path: string, body?: unknown): Promise<Response>;
}
```

`callBackend('GET', '/status')` is scoped to
`/api/plugins/<your-id>/status`. Do not call Zeus endpoints directly. Bundle UI
code as ESM, externalize `react` and `react/jsx-runtime`, and include every
declared module in the ZIP.

## 4. Uniform UI styling contract

Visual features must feel native in every Zeus theme without importing product
source. Scope all selectors beneath a feature-owned root class, such as
`.com-example-callsignlogger`, and prefix secondary class names. Never style
`html`, `body`, generic elements, Zeus classes, or host DOM descendants.

Use this public, stable CSS-token subset. Do not copy token values and do not
use raw hex, RGB, HSL, or named colors in feature UI CSS.

| Purpose | Tokens |
|---|---|
| Surfaces | `--bg-0`, `--bg-1`, `--bg-2`, `--bg-3`, `--bg-inset` |
| Text | `--fg-0`, `--fg-1`, `--fg-2`, `--fg-3` |
| Lines and panels | `--line`, `--line-strong`, `--panel-border`, `--panel-top`, `--panel-bot` |
| State | `--accent`, `--accent-bright`, `--ok`, `--amber`, `--tx` |
| Type | `--font-sans`, `--font-mono` |
| Radius | `--r-xs`, `--r-sm`, `--r-md`, `--r-lg` |
| Motion | `--dur-fast`, `--dur-med`, `--ease-out` |

Use state colors semantically: `--tx` only for transmit/danger, `--amber` for a
warning, `--ok` for confirmed healthy state, and `--accent` for selection or
focus. Do not use color as the only indication of state.

Required UI behavior:

- work in dark and light themes and at 200% display scaling;
- fit a resizable panel without fixed app-sized widths or heights;
- preserve visible keyboard focus, labels, and accessible names;
- honor reduced-motion preferences and avoid continuous decorative animation;
- keep touch targets practical and avoid hover-only actions;
- show loading, empty, error, disconnected, and unavailable states explicitly;
- use `callBackend` for backend work and clean up timers, subscriptions, and
  listeners when the component unmounts.

Every visual submission must attach screenshots directly to its pull request.
At minimum show the complete panel in dark and light themes, at normal and
narrow widths, and at 200% display scaling. Include visible keyboard focus and
each applicable loading, empty, error, disconnected, unavailable, selected,
warning, and transmit/danger state. Use additional close-ups where text or
controls would otherwise be unreadable. Screenshots are required review
evidence; a statement that the UI was tested is not a substitute.

Example:

```css
.com-example-callsignlogger {
  color: var(--fg-1);
  background: var(--bg-1);
  border: 1px solid var(--panel-border);
  border-radius: var(--r-md);
  font-family: var(--font-sans);
}

.com-example-callsignlogger__button:focus-visible {
  outline: 2px solid var(--accent-bright);
  outline-offset: 2px;
}
```

## 5. Publish the intake release

Build the package, validate it, and install it locally through
**Features → Community → Install local feature**. Then publish the exact tested
ZIP as a `.zip` asset on a versioned public GitHub Release. This
contributor-owned copy is the intake artifact that a maintainer will review and
mirror into Zeus-SDR custody. The intake URL must use the standard
`https://github.com/<owner>/<repository>/releases/download/<tag>/<asset>.zip`
form without a query string. Never replace bytes at an existing URL. Release a
new SemVer version for every change.

Compute the digest over the exact published ZIP:

```powershell
(Get-FileHash -Algorithm SHA256 feature.zip).Hash.ToLowerInvariant()
```

## 6. Add the catalog entry

Fork this repository and create a branch from the latest protected `main`:

```powershell
gh repo fork Zeus-SDR/zeus-community-features --clone
Set-Location zeus-community-features
git remote -v
git fetch upstream main
git switch -c community/com.example.callsignlogger-1.0.0 upstream/main
```

If `gh repo fork` names the source remote differently, use the source remote
shown by `git remote -v`; do not guess. A listing pull request must:

- add one new community feature or one new version of one community feature;
- edit only `registry.json`;
- leave every `channel: "official"` entry untouched;
- set a new entry's `channel` to `community` and `verified` to `false`;
- omit `subscription`, which is not a community-submission field;
- keep prior versions, URLs, and hashes unchanged;
- put the newest version first in `versions`;
- use lowercase category slugs, preferring `amplifiers`, `audio`, `logging`,
  `modes`, `monitors`, `switches`, `tools`, or `tuners` when applicable;
- update the top-level `generated` value to the current UTC RFC 3339 timestamp.

Community package downloads are kept under Zeus-SDR custody so removing or
renaming a contributor release cannot break installs for everyone else. Use
this exact deterministic catalog URL:

```text
https://github.com/Zeus-SDR/zeus-community-features/releases/download/community-<id>-v<version>/<id>-<version>.zip
```

For `com.example.callsignlogger` version `1.0.0`, that is
`https://github.com/Zeus-SDR/zeus-community-features/releases/download/community-com.example.callsignlogger-v1.0.0/com.example.callsignlogger-1.0.0.zip`.
Put the contributor-owned intake URL in the pull request template, not in the
final `registry.json`. The custody URL intentionally returns 404 until a
maintainer completes the custody gate.

New entries use this exact shape:

```json
{
  "id": "com.example.callsignlogger",
  "channel": "community",
  "name": "Callsign Logger",
  "description": "One-line operator-visible purpose.",
  "author": "Your name or callsign",
  "license": "GPL-2.0-or-later",
  "homepage": "https://github.com/example/callsignlogger",
  "categories": ["logging"],
  "verified": false,
  "versions": [{
    "version": "1.0.0",
    "sdkAbi": 1,
    "sdkMinVersion": "1.5.0",
    "platforms": ["any"],
    "downloadUrl": "https://github.com/Zeus-SDR/zeus-community-features/releases/download/community-com.example.callsignlogger-v1.0.0/com.example.callsignlogger-1.0.0.zip",
    "sha256": "64-lowercase-hex-characters"
  }]
}
```

Use `platforms: ["any"]` only for a fully managed, platform-neutral package.
List every actual runtime identifier when the ZIP contains native or
platform-specific files.

## 7. Required local checks

Install .NET 10, PowerShell 7, and Node.js, then run from the catalog repository
root. Replace the sample package arguments with the contributor package's exact
path and metadata for the first `validate-package.ps1` invocation:

```powershell
dotnet build Zeus.CommunityFeatures.slnx -c Release --nologo
npx --yes -p ajv-cli@5.0.0 -p ajv-formats@3.0.1 ajv validate --spec=draft2020 --strict=false -c ajv-formats -s schema/registry.schema.json -d registry.json
npx --yes -p ajv-cli@5.0.0 -p ajv-formats@3.0.1 ajv validate --spec=draft2020 --strict=false -c ajv-formats -s schema/plugin.schema.json -d templates/hello-world/plugin.json
pwsh tools/validate-sdk-boundary.ps1
pwsh tools/test-package-validator.ps1
pwsh tools/validate-registry.ps1
pwsh tools/validate-package.ps1 `
  -PackagePath C:/absolute/path/to/your-feature-1.0.0.zip `
  -ExpectedId com.example.callsignlogger `
  -ExpectedVersion 1.0.0 `
  -ExpectedSdkAbi 1 `
  -ExpectedSdkMinVersion 1.5.0 `
  -ManifestSchemaPath schema/plugin.schema.json
pwsh templates/hello-world/build-package.ps1
pwsh tools/validate-package.ps1 `
  -PackagePath artifacts/com.example.zeus.helloworld/com.example.zeus.helloworld-1.0.0.zip `
  -ExpectedId com.example.zeus.helloworld `
  -ExpectedVersion 1.0.0 `
  -ExpectedSdkAbi 1 `
  -ExpectedSdkMinVersion 1.5.0 `
  -ManifestSchemaPath schema/plugin.schema.json
```

CI also validates `registry.json` and the template manifest directly against
their JSON schemas. Before custody, validate the contributor ZIP directly with
the first `validate-package.ps1` command. After custody, CI and maintainers also
run `pwsh tools/validate-registry.ps1 -DownloadPackages`; it downloads the
Zeus-SDR copy, verifies its exact SHA-256, validates the embedded manifest, and
compares its identity, SDK, and catalog metadata. Contributors are not expected
to make that final command pass before a maintainer creates the custody asset.

## 8. Open the pull request

Push the branch to your fork and open a pull request against this repository's
`main` branch. Use:

- `feat(registry): add <id> <version>` for a first listing;
- `feat(registry): release <id> <version>` for a new version.

For example:

```powershell
git add registry.json
git commit -m "feat(registry): add com.example.callsignlogger 1.0.0"
git push -u origin community/com.example.callsignlogger-1.0.0
gh pr create --repo Zeus-SDR/zeus-community-features --base main --fill
gh pr checks --repo Zeus-SDR/zeus-community-features --watch
```

Push corrections to the same branch and answer each review conversation. Rebase
onto current `upstream/main` when a maintainer requests it. If package bytes
change after publication, create a new version, URL, and hash; never overwrite
the existing release.

Complete every applicable item in the pull request template and include the
feature source URL, contributor intake ZIP URL, SHA-256, declared platforms,
capability reasoning, local test results, and the complete screenshot set from
the uniform UI styling contract when the feature is visual. Attach the images
to the pull request description or a review comment so reviewers can inspect
them without building the feature first.
Copied, translated, vendored, generated, or clean-room-derived code must be
identified precisely. Resolve review conversations; never weaken or bypass a
failed check.

Public-fork CI uses disposable GitHub-hosted runners, a read-only token, and no
secrets. A separate trusted policy check reads only the candidate
`registry.json` bytes through the GitHub API and runs protected-main policy; it
never checks out or executes fork code. The checks validate catalog shape and
policy, custody URLs, hashes, embedded manifests, SDK metadata, package safety,
the SDK boundary, and builds on Linux, Windows, and macOS x64/arm64.

## 9. Review, merge, and store publication

Protected `main` requires passing checks, resolved conversations, and approval
from either Douglas J. Cerrato (KB2UKA / `@Kb2uka`) or Christian Suarez (N9WAR /
`@iamexemplar`). Either maintainer may validate and merge a contribution alone;
approval from both is not required.

After content review and before approval, either maintainer runs **Take custody
of community package** from the Actions page on protected `main`, entering the
pull request number, feature ID, version, contributor intake URL, and lowercase
SHA-256. The workflow:

1. checks the PR changes only `registry.json` and reads that file through the
   GitHub API without checking out the contributor branch;
2. downloads the intake ZIP as inert data with a compressed-size limit;
3. verifies SHA-256, archive safety, schema, manifest, SDK, and catalog metadata
   using tools checked out explicitly from protected `main`;
4. transfers only those validated bytes to a separate write-scoped job;
5. uploads, re-downloads, and re-verifies the exact ZIP before publishing its
   deterministic Zeus-SDR release, then verifies GitHub's immutable-release
   attestation; and
6. refuses to delete, overwrite, or replace any existing custody asset.

Published custody releases are immutable. Re-run the PR checks after custody is
created; the catalog package check must download the Zeus-SDR URL successfully
before approval. If any package byte must change, stop and publish a new SemVer
version instead of replacing the intake or custody asset.

Once a maintainer merges the listing into `main`, it becomes part of the public
catalog. Zeus shows it in **Features → Community** after the catalog cache
refreshes (normally within about five minutes). Users still choose whether to
install it. Merge does not auto-install the feature, set `verified` to `true`,
or turn execution into a sandbox.

Security reports do not belong in a public issue. Follow `SECURITY.md`.
