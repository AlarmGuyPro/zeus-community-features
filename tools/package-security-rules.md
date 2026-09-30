<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Package security scan rules

`tools/PackageSecurityScan` is a static scanner for community feature packages.
Zeus loads plugins in-process with no sandbox: declared capabilities are
disclosure only, and UI modules share the Zeus SPA origin with no content
security policy. The catalog review is the only security control, and this
scanner exists to make that review see what the package really does.

The scanner never loads, runs, or evaluates anything from the package.
Assemblies are parsed as bytes with `System.Reflection.Metadata`; JavaScript is
scanned as text. The ZIP is read into memory and never extracted to disk.
`tools/test-package-security.ps1` proves this with a fixture whose module
initializer writes a marker file: the marker does not exist after the scan, and
a positive control shows the same fixture does write it when deliberately run.

## Commands

```bash
dotnet run --project tools/PackageSecurityScan -c Release -- \
  scan --package <zip> [--json <out.json>] [--allowlist tools/package-security-allowlist.json]

dotnet run --project tools/PackageSecurityScan -c Release -- \
  compare --package <zip> --rebuilt <dir> [--json <out.json>] [--il-strict]
```

| Exit code | Meaning |
|---|---|
| 0 | Disposition `clear` or `review` |
| 2 | Disposition `fail`: at least one unsuppressed `fail` finding |
| 1 | Tool error (bad arguments, unreadable ZIP, no `plugin.json`, invalid allowlist). No report is written. |

A human summary goes to stdout. `--json` writes:

```json
{
  "tool": "PackageSecurityScan", "version": "1", "mode": "scan",
  "package": "<file name>", "sha256": "<hex of the ZIP>",
  "manifest": { "id": "…", "version": "…", "capabilities": [],
                "permissions": { "network": false, "fileSystemRead": false, "fileSystemWrite": false } },
  "findings": [ { "ruleId": "…", "severity": "fail|review|info", "file": "…",
                  "detail": "…", "evidence": "item; item; (+N more)" } ],
  "disposition": "fail|review|clear"
}
```

`manifest` is present for `scan` only. There is one finding per rule per file;
repeated hits merge into its evidence (at most 40 items, each at most 200
characters). Evidence is escaped: control characters, bidi overrides, and
zero-width characters are printed as `\uXXXX`, so a package cannot hide text in
a CI log or review comment. Secrets are never printed in full.

Disposition is `fail` if any unsuppressed finding is `fail`, otherwise `review`
if any is `review`, otherwise `clear`.

## Package rules (every file)

| Rule | Severity | Trigger |
|---|---|---|
| `native-binary` | fail (review when `audio.format` is `vst3` or `au`) | ELF or Mach-O magic, a PE image without a CLI header, a mixed-mode assembly (not ILOnly), or a ReadyToRun image (its native code can differ from the reviewed IL). A `.dll`/`.exe`/`.so`/`.dylib`/… with unrecognised content is `review`. |
| `script-file` | review | `.sh .bash .zsh .ps1 .psm1 .psd1 .bat .cmd .vbs .vbe .wsf .py .rb .pl .command .applescript .scpt`, or content starting with `#!`. |
| `nested-archive` | review | Archive extensions (`.zip .nupkg .jar .tar .gz .tgz .7z .rar .xz .bz2 .zst .cab .msi`) or ZIP/gzip/7z/RAR magic. Nested archives are not scanned. |
| `manifest-capabilities` | info | Echoes declared capabilities and permissions. |
| `markup-script` | fail | In `.html .htm .xhtml .svg`: `<script`, inline event handlers (`onload=` and any `on…=` attribute), or `javascript:` in an attribute value or CSS `url(`. |
| `markup-embed` | review | In the same files: `<iframe`, `<object`, `<embed`, `<frame`, `<foreignObject`. |
| `markup-html-file` | review | Any `.html`/`.htm`/`.xhtml` file: framed or navigated to, it runs in the Zeus origin. |
| `wasm-file` | review | A `.wasm` file or WebAssembly magic (`\0asm`). Instantiating WebAssembly from JavaScript is a `js-remote-code` fail. |
| `scan-error` | fail | A PE file or its metadata/IL is malformed or exceeds scanner limits, so it could not be fully analysed. |

## Managed assembly rules (every PE with a CLI header)

| Rule | Severity | Trigger |
|---|---|---|
| `pinvoke` | fail | Methods with `PinvokeImpl`/ImplMap rows; `DllImportAttribute`/`LibraryImportAttribute`. Evidence: `Type::Method -> module!entry`. |
| `native-library-load` | fail | `System.Runtime.InteropServices.NativeLibrary`, `Marshal.GetDelegateForFunctionPointer`, or a `calli` whose signature uses an unmanaged calling convention (found by walking IL). |
| `module-initializer` | fail | `<Module>` has a `.cctor`, or any `[ModuleInitializer]`. |
| `dynamic-code` | fail | `System.Reflection.Emit.*`, `AssemblyLoadContext`, `Assembly.Load/LoadFrom/LoadFile/UnsafeLoadFrom/LoadWithPartialName/ReflectionOnlyLoad*`, `AppDomain.Load/ExecuteAssembly*`, `System.CodeDom.Compiler.*` (except `GeneratedCodeAttribute`, which every source generator emits), and references to `Microsoft.CodeAnalysis.*`. |
| `process` | fail | `System.Diagnostics.Process`, `ProcessStartInfo`. |
| `obfuscation` | fail | Known obfuscator marker types (ConfuserEx `ConfusedByAttribute`, Dotfuscator, SmartAssembly, Goliath, Babel, Crypto Obfuscator, Xenocode, .NET Reactor/Eziriz, Agile.NET, Yano, MaxtoCode, Spices.Net), or more than 30% of non-generated type/method names containing non-ASCII or unprintable characters (with at least 5 names). |
| `unexpected-assembly-ref` | fail | An assembly reference other than `System`, `System.*`, `Microsoft.AspNetCore.*`, `Microsoft.Extensions.*`, `Microsoft.Win32.Primitives`, `Microsoft.CSharp`, `Microsoft.VisualBasic(.Core)`, `Microsoft.Win32.Registry`, `WindowsBase`, `Microsoft.Net.Http.Headers`, `Microsoft.JSInterop`, `netstandard`, `mscorlib`, `Zeus.Plugins.Contracts`, or an assembly shipped in the same package. `Zeus.*` other than `Zeus.Plugins.Contracts` is called out as a host internal. |
| `unexpected-assembly-ref` | review | A bundled managed assembly other than the manifest entrypoint (listed so its origin and licence are checked). It is scanned with every rule. |
| `undeclared-network` | fail, or info when declared | `System.Net.Http/Sockets/WebSockets/Mail/Quic/NetworkInformation/Security.*`, `Dns`, `WebClient`, `WebRequest`, `HttpWebRequest`, `FtpWebRequest`, `HttpListener`, and URL-capable XML APIs (`XmlReader.Create(string)`, `XmlTextReader(string)`, `XmlDocument.Load(string)`, `XDocument/XElement.Load(string)`, `XslCompiledTransform.Load/Transform(string)`, `XmlUrlResolver`, `XmlSecureResolver`; evidence notes they accept URLs). Declared means capability `NetworkAccess` **and** `permissions.network: true`. |
| `undeclared-filesystem` | fail, or info when declared | `File`, `FileInfo`, `FileStream`, `Directory`, `DirectoryInfo`, `FileSystemInfo`, `FileSystemWatcher`, `DriveInfo`, `RandomAccess`, `SafeFileHandle`, `FileVersionInfo`, `System.IO.Enumeration.*`, `Microsoft.Extensions.FileProviders.Physical*`, `Path.GetTempPath/GetTempFileName/Exists`, `StreamReader/StreamWriter(string path, …)`, `XmlWriter.Create(string)`, `XmlTextWriter(string)`, `XmlDocument/XDocument/XElement.Save(string)` (write) and `.Load(string)` (read), `XmlReader.Create(string)`, `XmlTextReader(string)`, `ZipFile.*` (`OpenRead` read, the rest write), `ZipFileExtensions.ExtractToFile/ExtractToDirectory` (write) and `CreateEntryFromFile` (read), `MemoryMappedFile.CreateFromFile` (write) and `OpenExisting` (read). Overloads taking a `Stream` or `TextReader` are not file access. Writes (`Write*`, `Create*`, `Append*`, `Delete`, `Move*`, `Copy*`, `Replace`, `Set*`, `Open`/`OpenWrite`/`OpenHandle`, `FileStream`, `StreamWriter(path)`, `GetTempFileName`) need `permissions.fileSystemWrite: true`; everything else needs `permissions.fileSystemRead: true`. |
| `ipc` | review | `System.IO.Pipes.*` and named shared memory (`MemoryMappedFile.CreateNew/CreateOrOpen/OpenExisting`): talking to other processes on the machine. |
| `unclassified-io-api` | review | Deny by default: any member of a `System.IO.*`, `System.Xml.*`, or `System.Net.*` type that no other rule classifies and that is not on the known-safe list (streams and readers/writers over streams, `Path` string helpers, compression streams and `ZipArchive`, XML DOM/`XmlReader`/`XmlWriter` over streams, `System.Xml.Linq/Serialization/XPath`, `System.IO.Pipelines`, `IPAddress`, `IPEndPoint`, `DnsEndPoint`, `IPNetwork`, `WebUtility`, `HttpStatusCode`, `HttpVersion`, `DecompressionMethods`, `System.Net.Mime`). Examples it lists: `SerialPort`, `NetworkCredential`. |
| `registry` | review | `Microsoft.Win32.Registry*`. |
| `environment` | review | `Environment.GetEnvironmentVariable(s)/ExpandEnvironmentVariables/SetEnvironmentVariable`. The Zeus station access token lives in the host environment. |
| `reflection` | review | `Type.GetType/InvokeMember/GetMethod(s)/GetField(s)/GetProperty(ies)/GetMember(s)/GetConstructor(s)/GetNestedType(s)/GetEvent(s)`, `Activator.*`, `MethodBase/MethodInfo/ConstructorInfo.Invoke/CreateDelegate`, `FieldInfo/PropertyInfo.GetValue/SetValue`, `Delegate.CreateDelegate`, `UnsafeAccessorAttribute`, `Unsafe.As/AsRef/AsPointer` (unless every call site is the compiler's `<PrivateImplementationDetails>` helpers), and every `Marshal.*` member except the one reported by `native-library-load`. |
| `host-services` | review | `IServiceProvider.GetService`, `ServiceProviderServiceExtensions.Get*Service*`, `ActivatorUtilities`, `IEndpointRouteBuilder.ServiceProvider`, `HttpContext.RequestServices`, `IApplicationBuilder.ApplicationServices`, `[FromServices]`/`[FromKeyedServices]`. Resolving host services directly bypasses the plugin context. |
| `host-data` | review | `IPluginContext.HostDataDirectory`, or strings containing (case-insensitive) `zeus-prefs`, `zeus-logbook`, `.litedb`, `litedb`, `zeus_station`, `ZEUS_STATION_ACCESS_TOKEN`. |
| `host-api-string` | fail | Strings matching `/api/(tx\|radio\|station\|dsp\|ps\|auth\|plugins/(install\|uninstall\|registry))\b`, the SignalR hub as a path (`/hub`, `/hub/…`, `http://host:port/hub`), or `ZEUS_STATION_ACCESS_TOKEN`. |
| `public-endpoint` | review (info for the manifest homepage host and standards/documentation hosts) | `http(s)://` URLs and bare IPv4 literals whose host is public. Non-public: 10/8, 172.16/12, 192.168/16, 127/8, 0/8, 169.254/16, 100.64/10, 224/4 and above, the documentation ranges 192.0.2/24, 198.51.100/24, 203.0.113/24, IPv6 loopback/link-local/ULA/multicast/2001:db8::/32, `localhost`, `*.local`, `example.com/.org/.net`, `.example`, `.test`, `.invalid`. Standards hosts listed as info: `w3.org`, `react.dev`, `reactjs.org`, `developer.mozilla.org`, `json-schema.org`, `schemas.microsoft.com`, `schemas.xmlsoap.org`, `schemas.openxmlformats.org`. `github.com` is never exempt. Bare IPv4 detection is skipped for attribute arguments, where four-part version numbers live. |
| `secret-like` | review | `ghp_…`, `github_pat_…`, `sk-…`, `xox[abprs]-…`, `AKIA…`, `-----BEGIN … PRIVATE KEY-----`, JWTs, and runs of 40+ base64/hex characters with Shannon entropy above 4.5 bits/char (runs with more than two `/` — paths — and sequential alphabet tables are skipped). Evidence shows the first 12 characters and the length only. |
| `embedded-resource` | review (fail when the resource starts with MZ/ELF/Mach-O/ZIP/gzip/7z/RAR magic) | Every manifest resource; linked (external) resources are listed. |
| `large-data-blob` | review | FieldRVA static data larger than 4096 bytes. |
| `time-bomb` | review | An IL walk finds an `ldc.i4` year constant (2000–2100) within 8 instructions before a call/newobj on `System.DateTime`, `DateTimeOffset`, or `DateOnly`, or a method that both reads `Now`/`UtcNow`/`Today` and loads such a constant. |

Strings for the string rules come from the `#US` heap (every `ldstr` literal,
referenced or not), string constants, and printable runs of custom-attribute
arguments.

## JavaScript rules (`.js`, `.mjs`, `.cjs`)

Evidence is `line:column: ~120-character excerpt`. Comments are scanned too.
Call patterns tolerate whitespace and comments between the callee and `(`
(`fetch/**/(`, `new/**/WebSocket(`).

**Reconstruction.** Strings split to dodge a text scan are reassembled: string
literals joined with `+`, arrays of string literals followed by `.join(sep)`,
single literals written with escapes (`'\x65val'`, `\u…`), and a literal followed by `.split(sep).reverse().join(sep)`, which is reversed. The rules
marked "reconstructed" below are re-run on that text. A match counts only when
it does not already appear inside one raw literal, and its evidence says
"reconstructed from split/escaped string literals". So
`Function(["fe","tch('/ap","i/tx')"].join(""))()` reports `js-eval`,
`js-host-api`, `js-network`, and `js-split-name`.

| Rule | Severity | Trigger |
|---|---|---|
| `js-eval` | fail (reconstructed too) | Any reference to `eval` (`eval(x)`, `(0,eval)(x)`, `window.eval`, `window['eval']`), except an object-literal key (`{ eval: … }`) or a hyphenated word (`'unsafe-eval'`); bare or `new` `Function(` (not `obj.Function(`); the global `Function` through `window/globalThis/self/top/parent/frames.Function` or `['Function']`; `Reflect.construct/apply(Function|eval`; `.constructor.constructor`, `.constructor(`, `['constructor']`; `}).constructor`, which covers `(async () => {}).constructor`, `(async function () {}).constructor`, `(function* () {}).constructor` and `Object.getPrototypeOf(function () {}).constructor`; `setTimeout`/`setInterval` with a string first argument. |
| `js-split-name` | fail (reconstructed only) | Reassembled or reversed text reveals a host API path (as in `js-host-api`) or a dangerous name that no single literal contains: `eval`, `Function`, `constructor`, `fetch`, `import`, `importScripts`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, `postMessage`, `localStorage`, `sessionStorage`, `indexedDB`, `cookie`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `srcdoc`, `WebAssembly`, `Worker`, `__zeus`, `external`, `ZEUS_STATION`, `atob`, `setTimeout`, `setInterval`, `window`, `globalThis`, `opener`. |
| `js-constructor-access` | review | `.constructor` read as a value, except `this.constructor`, `X.prototype.constructor`, `.constructor.name/.prototype`, identity comparisons (`=== !== == !=`), and the `.constructor(`/`.constructor.constructor` forms that `js-eval` already fails. From a function literal, `.constructor` is the Function constructor. |
| `js-string-transform` | review | `String.fromCharCode(`, `.map(…fromCharCode…)`, or a string literal immediately followed by `.replace(`/`.replaceAll(`. |
| `js-computed-access` | review | `window/globalThis/self/document/top/parent/this[…]` where the property name is built with `+`, `.join(`, or `${`. |
| `js-srcdoc` | fail (reconstructed too) | `srcdoc`: a frame whose HTML and script run in the Zeus origin. |
| `js-embed` | review | `createElement('iframe'\|'object'\|'embed'\|'frame')`, or `.src =` a relative `.html`/`.htm`/`.xhtml`/`.svg` literal. |
| `js-remote-code` | fail (reconstructed too) | `import('https:…`, static `import`/`export … from 'https:…'`, `importScripts(`, `createElement('script'`, `new Worker(`/`new SharedWorker(`, `.src = 'https:…`, `WebAssembly.instantiate/compile(Streaming)(`. |
| `js-dynamic-import` | review | Any other `import(`. |
| `js-host-api` | fail (reconstructed too) | `/api/(tx\|radio\|station\|dsp\|ps\|auth\|plugins/(install\|uninstall\|registry))\b`, `/hub` paths, `window.__zeus`, `window.external` (desktop native bridge), `ZEUS_STATION`. |
| `js-network` | review (reconstructed too) | Any reference to `fetch` (so an alias `const f = fetch` is seen), `XMLHttpRequest`, `new WebSocket(`, `new EventSource(`, `sendBeacon(`. Plugin UIs should use the host's `callBackend`. |
| `js-storage` | review | `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie`, `caches.open(`. |
| `js-global-keys` | review | `window/document/globalThis.addEventListener('keydown'\|'keyup'\|'keypress'` or `.onkey…=`. A global key listener can intercept Zeus hotkeys such as Space (transmit). |
| `js-cross-window` | review | `postMessage(`, `window.parent/top/opener`, `window.open(`, `location.href/assign/replace`. |
| `js-html-injection` | review | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `document.write(`. |
| `js-obfuscation` | fail | More than 20 distinct `_0x…` identifiers, more than 200 `\xNN` escapes, or `String.fromCharCode` with more than 20 arguments. |
| `js-obfuscation` | review | `atob(`, `unescape(`, or a string literal containing an unbroken base64 run of 200+ characters with entropy above 5.0 bits/char. |
| `js-public-endpoint` | review (info in the leading licence comment for github.com or the homepage host, and for the standards hosts above) | `http(s)://` URLs to public hosts, classified as for `public-endpoint`. |

## `compare`

Every file in the ZIP must exist at the same relative path under `--rebuilt`,
and every rebuilt file must exist in the ZIP.

| Rule | Severity | Trigger |
|---|---|---|
| `compare-missing-in-rebuilt` | fail | A packaged file the rebuild did not produce. |
| `compare-missing-in-package` | fail | A rebuilt file the package lacks. |
| `compare-bytes-differ` | fail | A non-assembly file is not byte-identical (evidence: both SHA-256 values and the first differing offset). `*.deps.json` is compared as parsed JSON, ignoring whitespace, property order, and `sha512`/`signature` string values. |
| `compare-metadata-differ` | fail | The normalized metadata fingerprints differ. Evidence lists each item only in the package or only in the rebuild. |
| `compare-il-differ` | review, or fail with `--il-strict` | Fingerprints match but method IL bodies differ (a different compiler version can do this); evidence lists the methods. Pass `--il-strict` when the contributor pins the SDK (`global.json`), so the same compiler must reproduce identical IL. |

The fingerprint contains: assembly name, version and public-key hash; assembly
references; type definitions with base types; method definitions with decoded
signatures; field definitions with types and string constants; P/Invoke
targets; every member reference with its decoded signature; every type
reference with its resolution scope; the set of `#US` strings; manifest
resources with SHA-256; FieldRVA static data hashes; and custom attributes
(constructor type, target, value hash). Compiler-generated type, method, field,
and attribute-target names (containing `<`) are left out because they vary
between compiler versions; anything generated code does still appears as member
references, type references, strings, or static data, which are always
compared in full, and generated method bodies are included in the IL check.

## Allowlist

`tools/package-security-allowlist.json` is maintainer-owned and lives on
protected `main`.

```json
{
  "schemaVersion": 1,
  "entries": [
    {
      "id": "com.example.feature",
      "version": "1.2.3",
      "sha256": "<64 lowercase hex characters of the package ZIP>",
      "ruleId": "pinvoke",
      "file": "Example.dll",
      "reason": "Calls libc getpid for diagnostics; reviewed.",
      "approvedBy": "KB2UKA"
    }
  ]
}
```

An entry suppresses a finding only when `id`, `version`, `sha256`, `ruleId`,
and `file` all match exactly, so an approval never carries over to a different
version or different bytes. A suppressed finding stays in the report as
`info`, with the approver and reason prepended to its detail. Unknown
properties, missing or empty fields, or a malformed `sha256` are a tool error.

## Known limits

- The scan is static. Code that assembles API names or URLs at runtime from
  fragments, or decrypts them, is only caught indirectly (through `reflection`,
  `dynamic-code`, `obfuscation`, and entropy findings). A `clear` disposition
  is not proof of safety; it means none of these patterns were found.
- Nested archives are flagged but not opened.
- `undeclared-filesystem` also fires for access under the plugin's own
  install directory, which the SDK permits without a permission; the plugin
  declares the permission or a maintainer allowlists the exact package.
- JavaScript is scanned as text, not parsed: a pattern inside a comment is
  reported, and string-literal extraction (for reconstruction and the entropy
  check) is approximate. Reconstruction covers `+` chains, `[…].join(…)`, and
  escapes; strings assembled through variables, `String.fromCharCode`, or
  arithmetic are caught only indirectly (`js-computed-access`, `js-obfuscation`).
- Bare IPv4 detection can match four-part version strings in user strings.
