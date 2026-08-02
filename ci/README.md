# CI architecture

GitHub Actions selects events, runners, permissions, caches, artifacts, and the
credential boundary. The non-publishable memcordon-ci Rust package performs all
sequencing with typed argument vectors and monotonic subprocess deadlines.

Local credential-free entry points include:

    cargo run --locked --package memcordon-ci -- suite policy
    cargo run --locked --package memcordon-ci -- suite quality
    cargo run --locked --package memcordon-ci -- suite native

Public CI uses fixed Linux x64/arm64, macOS arm64/x64, and Windows x64 runners.
Hard cgroup and Job Object certification uses dedicated one-job ephemeral
runners. A cache miss affects speed only. Toolchains are installed rather than
cached; Cargo sources, suite targets, and pinned CI tools use separate keys.

Release phases derive source identity and the typed credential path from Git and
GitHub event metadata, never from a custom project environment variable. The
first-release transition accepts exactly two step-local variables in
`release.yml`: `GITHUB_TOKEN` for GitHub staging/finalization and
`CARGO_REGISTRY_TOKEN` for each selected crates.io publication slot. A protected
tag push selects the temporary repository Actions secret; a same-tag manual
dispatch may deliberately select that path or OIDC fallback. The fallback is
rejected until every configured crate name exists. No job names a GitHub
Environment, so execution requires no environment approval or environment OIDC
claim. Repository policy rejects any named GitHub Environment.

After the first-tag OIDC reconciliation, the required cleanup changes the closed
credential policy to `oidc-only`, removes the stored secret and transition input,
and promotes the three OIDC pairs to the sole unconditional publication path.
The crates.io trusted-publisher identity is owner, repository, and workflow.
Repository policy enforces exact transition and steady-state shapes and prevents
the stored-token path from surviving into a later version.
