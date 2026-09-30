# Security policy

Zeus controls real transmitters. A feature vulnerability can cause data loss,
unintended RF emission, or equipment damage.

Do not open a public issue for a vulnerability. Email
`support@zeussdr.com` with a subject beginning `SECURITY:` and include the
feature ID/version, platform, reproduction, impact, and required attacker
access. Put unintended transmit, auto-keying, or PureSignal impact first.

Catalog removal prevents new installs but does not remove already-installed
code. Security response may therefore yank a version and recommend uninstall
or safe-mode startup.

Community packages execute in-process. SDK capability declarations and
collectible assembly load contexts are not a security boundary. Never put
credentials in source, manifests, packages, logs, or CI output.


## What the catalog security checks cover

Every new or changed community version goes through two automated checks
before a maintainer can approve it (details in
[CONTRIBUTING.md](CONTRIBUTING.md#security-scan)):

- **Package security scan.** The exact ZIP bytes are verified against the
  catalog SHA-256, scanned with ClamAV, and read by a static scanner that looks
  for malware and backdoor patterns: undeclared network, filesystem, process,
  registry, or native-code use, dynamic code loading, obfuscated or encoded
  payloads, hidden endpoints, and time-triggered logic. Dependency lockfiles
  in the pinned source are checked against the OSV database; a known-malicious
  dependency fails. Package code is never executed. Any failure blocks the
  listing and review findings add the `security-review-required` label.
- **Source rebuild.** The feature is rebuilt from the public source commit
  recorded in the catalog, with the exact SDK it pins and only hash-verified
  NuGet packages from its lock files, and compared with the ZIP, so the
  reviewed source is what actually ships. Contributor build code runs only in
  a sandbox with no network, no privileges, and a read-only view of the
  machine. Packages that inject build-time code (analyzers, source
  generators, MSBuild targets) and committed binaries fail the check.

The same scanner runs again on the exact bytes during maintainer custody, and
custody is refused on a failure.

What these checks cannot prove:

- Static rules and antivirus signatures can be evaded by code written to avoid
  them. A clear result means nothing known was found, not that a package is
  safe.
- A matching rebuild shows the ZIP came from the recorded source; it says
  nothing about whether that source is safe. Build-time behavior written into
  the source itself (for example in project files) is only caught by reading
  it.
- OSV only knows published advisories, and only dependencies with exact
  versions in a lockfile or project file can be checked.

Human source review stays mandatory for every listing. If a package slips past
these checks, report it as described above.
