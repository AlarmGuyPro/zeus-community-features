# Agent workflow — KB2UKA software factory

This file is rendered from the software factory (`Kb2uka/software-factory`,
installed at the path in `~/.config/software-factory/root`). Do not edit it in
place: change `repos/zeus-community-features.md` or `AGENTS.md.template` in the factory and
re-run `scripts/install.sh`. It applies to every agent and every harness working
in this repository. `CLAUDE.md`, where present, is the deeper project brief and
this file never overrides it.

## The four beats

Every feature, fix, refactor or task runs these in order. Each is a skill; when
a harness cannot load skills, the skill text lives in the factory under
`skills/<name>/SKILL.md` and is read from there.

1. **Isolate — `/isolate`.** Fresh git worktree branched from `origin/main`,
   sibling to the checkout, after a scope check against every open PR. Never
   build in the shared checkout, never on `main` or `main`.
2. **Shape — `/shape`.** Grep the seams first and model the change on the
   nearest existing pattern in this repo. DRY, tests mandatory, engineered
   enough, explicit over clever. Self-review through the four lenses
   (architecture, code, tests, performance) before and after writing.
3. **Prove — `/evidence`.** Bug fixes ship a test recorded failing before the
   fix and passing after. Visible changes ship before/after captures. Backend
   changes ship the wire log or measured numbers. Everything lands in
   `.artifacts/<task>/` with an `assertions.md`. Automation never keys a
   transmitter.
4. **Ship — `/proof`, `/review-loop`, then `/ship` reports.** Draft PR against
   `main` with the Proof section filled, gates listed as actually run, then
   the review loop until every judge seat scores 5/5 with nothing open (max 5
   rounds). End by presenting the PR URL and the "Needs a human" list.

The PR body has these headings in this order: Summary, Root cause (fixes),
Proof, Gates, Review rounds, Needs a human, then the `factory:` footer line.

## Multi-agent rules

- One worktree and one branch per task per agent. Never reuse or touch another
  agent's worktree, branch, or uncommitted work.
- Never `checkout`, `reset`, `stash` or `clean` in the shared primary checkout.
  Other sessions are sitting in it.
- Scope check before starting: `gh pr list`, then `gh pr diff <n> --name-only`
  for each. On overlap with your files, stop and report.
- `--force-with-lease` only, only on your own task branch. Never force-push a
  shared branch.
- Lockfile conflicts are regenerated, never hand-merged.
- Worktrees do not isolate ports or databases: confirm a port answers your
  process before trusting it, and use a throwaway data path where the repo
  offers one.
- If a conflict cannot be resolved with confidence, stop and report.

## Inside an orchestrated pipeline

When another agent or a pipeline is driving you (the autofix fleet, a `/trio`
run, a `/ship --swarm` coder brief), the orchestrator owns beats 1 and 4: it
created your worktree, it owns git, it opens the PR, and it runs the review.
You do beats 2 and 3 only: shape, implement, test, and leave the evidence in
`.artifacts/<task>/`. Never commit, push, open a PR, or trigger a review from
inside a brief unless the brief says so explicitly. The brief overrides the
"Completing a task" list below.

## Hard rules that never vary

- Never mention any AI assistant, model or vendor in commits, PR bodies, code
  comments, or any repo-visible artifact. Credit is KB2UKA.
- Never merge, publish, release, or send anything outward without a human
  maintainer's explicit go. End at a draft PR.
- Never change the power state of any machine on the 10.70.x.x network.
- Never claim a gate passed that did not run. Never cite a source not opened.
- Red-light surfaces (visual design, UX behaviour, architecture and new
  dependencies, operator-felt defaults) are implemented minimally and listed
  under "Needs a human", never decided silently.

## Completing a task

1. Keep the change to the assigned task.
2. Run every command under "Gates" below and record the result.
3. Assemble the evidence into the Proof section.
4. Rebase onto the latest `origin/main`, rerun the gates.
5. Push (`git push -u origin <branch>`; `--force-with-lease` after a rebase).
6. Open the draft PR against `main` with the required headings.
7. Run the review loop to 5/5.
8. Present the PR URL. Keep the worktree until the PR is merged or closed.

---

## Zeus Community Features (public catalog) — repo section

Public repository: the catalog (`registry.json`), the schemas, the SDK
snapshot and the hello-world template. Protected `main`. The contributor
instructions below were the repo's own `AGENTS.md` before the factory and
remain binding word for word.

### Gates

```bash
dotnet build Zeus.CommunityFeatures.slnx
dotnet build templates/hello-world
```

Run every validator under `tools/` that `CONTRIBUTING.md` names for the change
you made; passing schema validation alone is not sufficient.

### Contributor instructions (preserved)



This repository is designed to be followed by people and automation agents.
Before changing anything, read `README.md`, `CONTRIBUTING.md`, and the two
schemas under `schema/`. `CONTRIBUTING.md` is the canonical submission and UI
style guide. The schemas are the machine-readable truth for JSON shape; tools
under `tools/` additionally enforce archive, catalog, submission, and custody
policy. Passing schema validation alone is not sufficient.

## Public boundary

- Treat `sdk/Zeussdr.Zeus.Plugins.Contracts/` as the complete integration
  boundary. Use only its public types and the browser API documented in
  `CONTRIBUTING.md`.
- Never request, copy, translate, reconstruct, or depend on private Zeus source,
  host internals, DSP/radio protocol implementations, credentials, binaries, or
  undocumented endpoints. If the public SDK cannot support a feature, stop and
  open an issue describing the missing capability without proposing private
  implementation details.
- Never add Zeus product source to this repository. Changes under `sdk/` must be
  made by a maintainer in a dedicated SDK-update pull request and must pass the
  SDK allowlist audit.
- PureSignal is not an SDK surface. Do not inspect, call, proxy, persist, or
  change any PureSignal behavior.

## Catalog-listing task

For a new feature or release:

1. Build the feature in its own source repository from the public SDK and
   `templates/hello-world/`. Do not add feature source or release binaries to
   this repository's Git tree; approved binaries enter Zeus-SDR release custody
   only through the maintainer workflow.
2. Validate and locally install the ZIP before publishing it.
3. Publish the exact ZIP as a `.zip` asset on a versioned public GitHub Release.
   Record its bare lowercase SHA-256 and never replace its bytes.
4. Fork this repository and edit only `registry.json`. A listing pull request
   must not change schemas, SDK files, templates, tools, workflows, or existing
   official entries.
5. For a new listing, set `channel` to `community` and `verified` to `false`.
   Do not add `subscription`. Make the catalog metadata and embedded
   `plugin.json` metadata agree.
6. Add one feature, or one new version of one feature, per pull request. Keep
   existing versions and URLs unchanged; published `(id, version)` pairs are
   immutable.
7. Update the top-level `generated` timestamp to the current UTC RFC 3339 time.
8. Use the deterministic Zeus-SDR custody `downloadUrl` from
   `CONTRIBUTING.md`; keep the contributor-owned intake URL in the pull request
   evidence, not in the final catalog entry.
9. Run every contributor command in the “Required local checks” section of
   `CONTRIBUTING.md`, then open a pull request to `main` and complete the pull
   request template with real evidence.
10. If the feature has UI, attach the required dark/light, normal/narrow,
    200%-scaling, keyboard-focus, and applicable state screenshots. Do not
    replace screenshots with a text-only claim that the UI was tested.

Use the pull request title `feat(registry): add <id> <version>` for a first
listing or `feat(registry): release <id> <version>` for an update. Do not edit
or bypass failed checks.

## Acceptance lifecycle

Protected `main` requires passing checks, resolved review conversations, and
approval from either Douglas J. Cerrato (KB2UKA / `@Kb2uka`) or Christian
Suarez (N9WAR / `@iamexemplar`). Either maintainer has full authority to
validate and merge a contribution; approval from both is not required.

Before approval, that maintainer uses the protected-main custody workflow to
mirror the exact reviewed ZIP into an immutable release owned by Zeus-SDR. The
workflow never checks out or executes contributor code, refuses a hash or
manifest mismatch, and never replaces an existing asset. The final catalog URL
must be the deterministic Zeus-SDR custody URL, so deleting the contributor's
release cannot remove the package from other users.

After a maintainer merges the listing into `main`, Zeus picks it up from the
public catalog and shows it in **Features → Community** after the catalog cache
refreshes. A listing does not auto-install the feature, mark it verified, or
make it sandboxed.
