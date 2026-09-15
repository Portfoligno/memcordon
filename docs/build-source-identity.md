# Build source identity

The published CLI build script delegates identity parsing and selection to
`crates/memcordon-cli/build_support/`. The files ship with the Cargo package;
there is no non-publishable build dependency.

Selection uses validated `.cargo_vcs_info.json` first, then the exact checkout
commit, then `.memcordon-source.json`, and finally `unknown`. Malformed present
package metadata is an error, including invalid UTF-8, abbreviated commits and
duplicate fields. Environment commit strings cannot override file identity.

The optional release-generated file has this strict shape:

```json
{"schema":1,"source_commit":"0123456789abcdef0123456789abcdef01234567"}
```

Release tooling must generate it from the reviewed source commit when preparing
an archive without Git or Cargo provenance. Merely adding this file does not
attest an archive or authorize release. Native asset, Cargo archive and
certification admission all require an exact source object id and their existing
provenance comparisons. Policy and release preflight reject unknown identities.

Direct checkouts, detached HEADs and linked worktrees resolve loose and packed
refs. Linked worktrees use `commondir` for shared refs. Every consulted metadata
path is a Cargo rerun input. A dirty tree still has its exact HEAD identity;
release preflight independently rejects dirty worktrees and indexes.
Malformed HEADs, present malformed loose refs, and invalid or duplicate matching
packed refs are errors. A well-formed symbolic HEAD whose ref is absent is an
unborn branch with no checkout commit; only that absent-ref case can use explicit
release metadata or `unknown`.

Static MSVC selection is a separate pure target-OS/environment decision. Default
binary identities and feature-gated fixture exclusions remain covered by the
fixture inventory and native archive tests.
