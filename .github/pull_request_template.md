## Community feature release

- Feature ID:
- Version:
- Source repository (public, matches `source.repository`):
- Source commit (matches `source.commit`, contains `zeus-build.json`):
- Contributor intake GitHub Releases HTTPS ZIP (matches `source.package`):
- SHA-256 (lowercase):
- Expected Zeus-SDR custody URL:
- Platforms:

## Submission checklist

- [ ] This pull request adds one feature or one new version of one feature.
- [ ] This listing pull request changes only `registry.json`.
- [ ] The entry uses `channel: "community"`, `verified: false`, and no
      `subscription` field.
- [ ] The new version includes `source` with the public repository, the full
      commit SHA the ZIP was built from, and the intake ZIP URL.
- [ ] That commit contains a `zeus-build.json` rebuild contract, a
      `global.json` pinning one exact SDK with `rollForward: "disable"`, and a
      `packages.lock.json` beside every project with NuGet packages, and the
      ZIP was built from that exact commit with that SDK.
- [ ] The embedded `plugin.json` and catalog agree on ID, version, SDK ABI, and
      minimum SDK version.
- [ ] The intake ZIP is the exact locally tested artifact, is available over
      HTTPS, and will not be replaced at this versioned URL.
- [ ] The public source repository contains the complete corresponding source,
      build files, license, notices, and a tag or commit for this exact version.
- [ ] The feature uses only the public SDK/browser API and does not contain,
      reconstruct, or depend on private Zeus logic or undocumented endpoints.
- [ ] PureSignal is untouched and the feature never auto-keys a transmitter.
- [ ] Capabilities and permissions are complete and no broader than necessary.
- [ ] Package license, third-party notices, manifest, and catalog metadata agree.
- [ ] UI CSS follows the token, selector-scoping, theme, scaling, keyboard, and
      state guidance in `CONTRIBUTING.md`, or this feature has no UI.
- [ ] For a visual feature, I attached the required dark/light, normal/narrow,
      200%-scaling, keyboard-focus, and applicable state screenshots below.
- [ ] I installed the ZIP locally and tested the declared platforms and operator
      states. Results are described below.
- [ ] All contributor-side commands in “Required local checks” pass. I
      understand the custody-download check becomes green only after maintainer
      intake.
- [ ] I will explain any Package security scan or Source rebuild finding in
      this pull request rather than changing tools, workflows, or the scanner
      allowlist.

## Capability and safety review

Explain every requested capability and permission, any network hosts or file
paths used, all radio-control behavior, and how transmit is kept operator-led.

## Validation evidence

List tested OS/architecture combinations, local-install results, and
failure-state tests.

### UI screenshots (required for visual features)

Attach the complete-panel screenshots here. Label dark/light theme,
normal/narrow width, 200% scaling, keyboard focus, and each applicable loading,
empty, error, disconnected, unavailable, selected, warning, and
transmit/danger state. A text-only assertion is not sufficient.

## Review and publication

Maintainer custody gate (completed by either maintainer after content review):

- [ ] Source, provenance, permissions, UI, licensing, and operator-safety
      evidence have been reviewed.
- [ ] Package security scan and Source rebuild matches package are green, and
      every review finding (and the `security-review-required` label, if set)
      has been resolved by reading the source.
- [ ] The protected-main custody workflow mirrored and re-downloaded the exact
      SHA-256-verified bytes without executing feature code.
- [ ] `registry.json` uses the resulting immutable Zeus-SDR custody URL and all
      required checks are green.

I understand that either Douglas J. Cerrato (KB2UKA / `@Kb2uka`) or Christian
Suarez (N9WAR / `@iamexemplar`) may validate and merge this contribution. After
merge to protected `main`, Zeus will include the listing in
**Features → Community** after its catalog cache refreshes; users must still
choose to install it.
