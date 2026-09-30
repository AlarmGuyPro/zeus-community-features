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
   Commit `package-lock.json` for every browser build, and enable
   `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` so NuGet
   writes a `packages.lock.json`; the dependency scan and the rebuild check
   require them.
7. Add a `zeus-build.json` rebuild contract and a `global.json` SDK pin at the
   repository root (below).
8. Build and package from a clean checkout of the exact commit you will submit,
   on every declared platform.

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

### Rebuild contract (`zeus-build.json`)

Every new community version must be reproducible from its public source. CI
clones `source.repository` at `source.commit`, rebuilds the feature, and
compares the rebuilt files with the submitted ZIP. Describe the build in
`zeus-build.json` at the source repository root. The shape is defined by
[`schema/zeus-build.schema.json`](schema/zeus-build.schema.json):

```json
{
  "schemaVersion": 1,
  "dotnet": {
    "project": "src/CallsignLogger/CallsignLogger.csproj",
    "configuration": "Release"
  },
  "node": [
    { "directory": "web", "script": "build" }
  ],
  "package": {
    "plugin.json": "src/CallsignLogger/plugin.json",
    "LICENSE": "LICENSE",
    "THIRD-PARTY-NOTICES.txt": "THIRD-PARTY-NOTICES.txt",
    "ui/callsign-logger.js": "web/dist/callsign-logger.js"
  }
}
```

- `dotnet.project` is the feature project. Every DLL in the ZIP and the
  entrypoint `.deps.json` are taken from its build output, so never list them
  under `package`.
- `node` is optional. Each entry names a directory containing `package.json`
  and `package-lock.json` and the npm script that builds the browser module.
  Browser builds run before the .NET build, in the listed order.
- `package` maps every other file in the ZIP (path inside the ZIP) to where that
  file exists in the source tree after the build. Every ZIP file must be
  accounted for, and every mapping must name a file the ZIP contains. Files the
  .NET build writes to its output directory can be mapped from
  `.zeus-build/out/<file>`, the output directory the check uses.
- Every path is relative to the repository root, uses forward slashes, and must
  not be absolute, contain `.` or `..` segments, point inside `.git`, or pass
  through a symbolic link.

Two more files are required at the source repository root:

- `global.json` pins one exact .NET SDK and forbids roll-forward. CI installs
  exactly that SDK. Nothing else (such as `msbuild-sdks`) is allowed:

  ```json
  { "sdk": { "version": "10.0.100", "rollForward": "disable" } }
  ```

- `packages.lock.json` beside every project that restores NuGet packages. Set
  `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` (for
  example in `Directory.Build.props`), restore once, and commit the lock files.
  A project with `PackageReference` items and no lock file fails.

The check runs in this order, on a disposable Linux runner without secrets:

1. It validates `zeus-build.json`, `global.json`, and the ZIP's archive safety.
2. It deletes every mapped file and `.zeus-build/` before building, so a
   committed prebuilt file cannot stand in for build output. A committed file
   is kept and packaged as committed only when its ZIP path and its source path
   both look like plain text or images (such as `LICENSE`, `plugin.json`,
   `*.md`, `*.txt`, `*.json`, `*.css`, and images) and its content does not
   start with an executable or archive header.
3. Trusted tooling, not your build, downloads every package listed in your
   `packages.lock.json` files from nuget.org and checks each one against the
   lock file's SHA-512 `contentHash`. They become a local package feed; no
   other package source is available to the build.
4. `npm ci --ignore-scripts` installs browser dependencies from
   `https://registry.npmjs.org/` only. Install scripts never run, and any
   `.npmrc` in your repository is ignored. Every `package-lock.json` entry must
   resolve from `https://registry.npmjs.org/` and have an `integrity` hash;
   git, tarball, or other-registry dependencies fail.
5. It proves the build sandbox is isolated, then runs every step that executes
   your code inside it: `dotnet restore --locked-mode` from the local feed,
   `npm run <script> --ignore-scripts`, and `dotnet build --no-restore`. The
   sandbox has no network, its own process space (nothing it starts survives
   it), no privileges, and can write only to your source tree and a private
   home directory; the rest of the machine is read-only.
6. A separate job that never runs contributor code compares the rebuilt files
   with the ZIP. Assemblies are compared by their metadata (types, members,
   referenced APIs, strings, resources, native imports) and method bodies, so
   differences such as build paths do not matter but any code difference fails.
   The `.deps.json` is compared as JSON without package hash fields. Other
   files must match byte for byte, and extra or missing files fail.

The rebuild check has no review tier: it passes or fails. It also fails when:

- the source repository tracks an executable or archive, detected by file
  header (Windows, Linux, and macOS executables, ZIP, gzip, WebAssembly) or by
  extension (`*.dll`, `*.exe`, `*.so`, `*.dylib`, `*.zip`, `*.nupkg`, and
  similar);
- a NuGet package other than `Microsoft.*` or `System.*` (prefixes only
  Microsoft can publish on nuget.org) ships
  analyzers, source generators, MSBuild targets, content files, or tools
  (`analyzers/`, `build/`, `buildTransitive/`, `buildMultiTargeting/`,
  `contentFiles/`, `tools/`), because they inject code or files that are not
  in your source. To use such a package, open an issue naming the exact
  package ID and version and why it is needed. If a maintainer approves it,
  they add it to [`tools/rebuild-package-allowlist.json`](tools/rebuild-package-allowlist.json)
  in a separate maintainer pull request; never edit that file in a listing
  pull request;
- restore uses any package that is not in a lock file, or the project moves
  `obj/` away from its default location;
- the repository's MSBuild is not plain declarative data. The rules are an
  allowlist kept in `tools/SourceRebuild.psm1`:
  - only `.csproj` and `.props` files are allowed; any `.targets`, `.tasks`,
    `.user`, `.rsp` (including `Directory.Build.rsp`), other project type, or
    committed `bin/` or `obj/` directory fails;
  - allowed elements are `Project` (with `Sdk` exactly `Microsoft.NET.Sdk`,
    `Microsoft.NET.Sdk.Web`, or `Microsoft.NET.Sdk.Razor`), `PropertyGroup`,
    `ItemGroup`, `Choose`/`When`/`Otherwise`, and `Import` of another linted
    `.props` file in the repository by literal path;
  - only allowlisted property names (for example `TargetFramework`,
    `AssemblyName`, `Version`, `Nullable`, `ImplicitUsings`, `NoWarn`,
    `CopyLocalLockFileAssemblies`, `EnableDynamicLoading`,
    `RestorePackagesWithLockFile` set to `true`), item types (`Compile`,
    `None`, `Content`, `EmbeddedResource`, `PackageReference`,
    `PackageVersion`, `ProjectReference`, `FrameworkReference`, `Using`,
    `InternalsVisibleTo`, `AssemblyAttribute`, `Folder`), and item metadata;
  - values may use plain `$(Property)` references and a few `[MSBuild]::`
    path and version helpers only; no other property functions, item or
    metadata references, or escapes, including in conditions;
  - item paths are literal, repository-relative, never under `node_modules/`,
    `obj/`, `bin/`, or `.git/`, and wildcards need a directory prefix that
    does not contain a project or browser build directory;
  - items that add files (`Compile`, `None`, `Content`, `EmbeddedResource`
    `Include`) belong in a `.csproj` and may name only committed files; a
    wildcard that matches any uncommitted file fails;
  - `CopyToOutputDirectory` is allowed only for one literal, committed text or
    image file.
  If your feature needs something outside the allowlist, open an issue and ask
  a maintainer to extend it;
- a browser build directory (`node[].directory`) is inside, equal to, or
  contains a .NET project directory; keep them in separate directories and
  package browser output through the `package` mapping;
- after the browser build, any untracked, ignored, or modified file exists
  inside a .NET project directory (other than that project's own `obj/` and
  `bin/`), because MSBuild's default item globs would compile or package it;
- an `npm-shrinkwrap.json` exists in a browser build directory or any parent
  up to the repository root, or a `package-lock.json` link points outside the
  repository;
- the rebuilt files contain a symbolic link.

Build the submitted ZIP from the same commit you record in `source`, with the
SDK pinned in `global.json`; the commit hash is stamped into the assembly
version metadata, so a ZIP built from any other commit will not match.

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
- include `source` (repository, commit, and intake package URL) on the new
  version;
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
Record the contributor-owned intake URL in the new version's `source.package`
field and in the pull request template; never use it as `downloadUrl`. The
custody URL intentionally returns 404 until a maintainer completes the custody
gate.

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
    "sha256": "64-lowercase-hex-characters",
    "source": {
      "repository": "https://github.com/example/callsignlogger",
      "commit": "40-lowercase-hex-character-commit-sha",
      "package": "https://github.com/example/callsignlogger/releases/download/v1.0.0/com.example.callsignlogger-1.0.0.zip"
    }
  }]
}
```

### Source provenance (`source`)

Every community version added from now on must include a `source` object.
Versions listed before this requirement are unchanged, and official entries
are exempt.

| Field | Value |
|---|---|
| `repository` | `https://github.com/<owner>/<repository>`, with no trailing `.git` or slash. |
| `commit` | The full 40-character lowercase commit SHA the ZIP was built from. It must contain `zeus-build.json`. |
| `package` | The contributor intake ZIP on a versioned GitHub Release. Its bytes must match `sha256`. |

The security scan downloads `source.package`, the rebuild check clones
`source.repository` at `source.commit`, and the maintainer custody workflow
refuses an intake URL that differs from `source.package`. Zeus ignores
catalog fields it does not recognize, so `source` does not affect existing
Zeus installs.

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

Also validate your rebuild contract, and on Linux reproduce the rebuild check
from a fresh clone of the exact commit you will submit (the output directory
must be empty and outside the clone):

```powershell
npx --yes -p ajv-cli@5.0.0 -p ajv-formats@3.0.1 ajv validate --spec=draft2020 --strict=false -c ajv-formats -s schema/zeus-build.schema.json -d /absolute/path/to/feature-clone/zeus-build.json
pwsh tools/verify-source-build.ps1 `
  -PackagePath /absolute/path/to/your-feature-1.0.0.zip `
  -SourceDirectory /absolute/path/to/feature-clone `
  -OutputDirectory /absolute/path/to/empty-output
```

`verify-source-build.ps1` deletes mapped build outputs in the clone, needs the
SDK pinned in `global.json`, bubblewrap (`bwrap`), and unprivileged user
namespaces; on Ubuntu 24.04 install `bubblewrap` and enable them with
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`. It fails
closed if it cannot prove the sandbox has no network and cannot write outside
the clone.

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

### Security scan

**Package security scan** runs protected-main tooling on every new or changed
community version. It never checks out or runs code from the fork or the
feature. For each version it:

1. downloads `source.package` over HTTPS with a 256 MiB limit and verifies the
   SHA-256 from `registry.json` before anything else reads the file;
2. applies the archive safety rules and scans the ZIP and its extracted files
   with ClamAV; any detection fails;
3. runs the static package scanner, which reads assemblies, browser modules,
   and other files as data and looks for malware and backdoor patterns such as
   undeclared network, file, process, or native-code use, dynamic code
   loading, obfuscation, and hidden endpoints (rules:
   [`tools/package-security-rules.md`](tools/package-security-rules.md));
4. clones the pinned source as data only and checks its `packages.lock.json`,
   `package-lock.json`, and project `PackageReference` versions against the
   OSV vulnerability database. A known-malicious package fails; a vulnerable or
   unpinned dependency needs review.

Each finding is **fail**, **review**, or **info**. Any fail turns the check red
and blocks the listing. Review items keep the check green but add the
`security-review-required` label, and a maintainer must look at them before
approving. A clear result removes the label. The scan posts one summary comment
on the pull request and updates it on every push; the full JSON report is kept
with the workflow run. If a finding is a false positive, explain it in the
pull request; do not change the scanner or its allowlist in a listing pull
request.

### Source rebuild check

**Source rebuild matches package** rebuilds the feature from
`source.repository` at `source.commit` using `zeus-build.json` and compares the
result with the ZIP, as described in
[Rebuild contract](#rebuild-contract-zeus-buildjson). A missing
`zeus-build.json` or `global.json`, a build failure, a tracked binary, an
unapproved build-time package, or any difference between the rebuilt files and
the ZIP fails the check. There is no review tier.

Both checks handle exactly one new or changed community version; a pull request
that touches more than one fails.

Both checks prove less than a human review. Static rules and signatures can be
evaded, and a rebuild only shows that the ZIP matches the source, not that the
source is safe. Maintainers still read the source before approving.

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
   using tools checked out explicitly from protected `main`, requires the intake
   URL to equal the version's `source.package`, and refuses custody when the
   package security scanner returns a fail result;
4. transfers only those validated bytes to a separate write-scoped job;
5. uploads, re-downloads, and re-verifies the exact ZIP before publishing its
   deterministic Zeus-SDR release, then verifies GitHub's immutable-release
   attestation; and
6. refuses to delete, overwrite, or replace any existing custody asset.

Published custody releases are immutable. Re-run the PR checks after custody is
created; the catalog package check must download the Zeus-SDR URL successfully
before approval. If any package byte must change, stop and publish a new SemVer
version instead of replacing the intake or custody asset.

Once a maintainer merges the listing into `main`, the validation workflow
automatically publishes the catalog to the download host after its schema,
six-platform build, and package checks pass. It verifies the public catalog
content against the validated commit, allowing the download host's release URL
mapping; a publication failure is visible in Actions.
See [catalog publishing setup](README.md#catalog-publishing-setup-maintainers)
for the required secrets and retry procedure. Zeus shows it in **Features → Community** after the catalog cache
refreshes (normally within about five minutes). Users still choose whether to
install it. Merge does not auto-install the feature, set `verified` to `true`,
or turn execution into a sandbox.

Security reports do not belong in a public issue. Follow `SECURITY.md`.
