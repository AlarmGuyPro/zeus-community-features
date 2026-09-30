# Required repository settings

`main` is the protected review and publication boundary. Configure a GitHub
ruleset for `refs/heads/main` with pull requests, one code-owner approval for
outside contributions, stale-review dismissal, resolved conversations, strict
required Actions checks, and blocked force-push/deletion.

Require the exact `Trusted community submission policy` check after that
workflow exists on `main`, in addition to the schema, package, and platform
build checks. This protected-main check is the merge boundary that prevents an
outside listing pull request from changing tools or policy. Do not add it as a
required context before its workflow has landed, because the workflow cannot
run on the pull request that first introduces it.

The **Source rebuild matches package** check runs on `pull_request` because it
executes contributor build code, which means it runs the workflow file from
the pull request itself. It is only trustworthy while `Trusted community
submission policy` is a required check, because that check rejects any outside
listing pull request that changes workflows or tools. Once both workflows have landed on `main`, also require
`Package security scan`, `Publish security scan result`, and `Source rebuild
matches package`. `Publish security scan result` must be required because it
fails whenever the scan failed, was cancelled, or produced no valid report, so
a scan that never finished cannot look green. Review findings keep both jobs
green but add the `security-review-required` label, which the report job owns. It removes
the label only when the bot applied it most recently, never a label a
maintainer added. The security scan creates the `security-review-required`
label (color `d93f0b`) on first use.

Set default workflow-token permissions to read-only. Keep `@Kb2uka` and
`@iamexemplar` as explicit bypass actors so either maintainer retains
independent authority for their own work.

Never attach self-hosted runners to this public repository and never use
`pull_request_target` to check out or execute contributor content. Future CDN
credentials belong in a protected post-merge environment whose job does not
execute feature code.

Enable **immutable releases** for the repository before taking custody of any
package. The custody workflow checks this setting before upload and requires
the published release itself to report as immutable before it succeeds. Do not
disable the setting while any community package is published. The publishing
job also verifies GitHub's release attestation and asset digest before it
reports success.
