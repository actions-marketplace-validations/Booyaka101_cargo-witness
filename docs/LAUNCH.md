# cargo-witness — Launch Material

Copy for launching cargo-witness across Hacker News, r/rust, and social. The tone
throughout is factual and technical: this audience is (rightly) skeptical of
security hype, so every claim is one the tool actually backs up, and the honest
limitations are stated up front rather than buried.

---

## One-paragraph pitch

**cargo-witness** is a zero-cost Node.js CLI, nightly daemon, and GitHub Action
that detects Rust supply-chain attacks by diffing the published `.crate` artifact —
the exact bytes Cargo installs from `static.crates.io` — against the crate's real
git source. Its headline detection is the *onering* attack pattern (a real, named
attack from June 10, 2026): a `build.rs` build script that is present in the
published artifact but absent from the crate's git history — malicious code
injected at publish time that never appears in the repository people actually
review on GitHub. cargo-witness verifies against the **exact commit** the artifact
was published from (read from the `.cargo_vcs_info.json` embedded in the crate — no
tag-guessing) and, when available, against crates.io's **Trusted Publishing (OIDC)
attested commit**, which the publisher cannot forge. It runs with
`npx cargo-witness --scan` — no API keys, no accounts, no paid services.

---

## Show HN post

**Title:**

> Show HN: cargo-witness – detect Rust supply-chain attacks by diffing the published crate against its git source

**Body:**

The *onering* attack (June 10, 2026) worked like this: an attacker with a publish
token uploaded a `.crate` to crates.io that contained a malicious `build.rs` build
script. That `build.rs` was never committed to the crate's public GitHub repo. So
anyone auditing the source on GitHub saw nothing wrong — but `cargo build` runs the
artifact from crates.io, which is a *separate upload*, and it executed the injected
build script.

cargo-witness is a cheap, automated tripwire for exactly that pattern. It downloads
the same `.crate` artifact Cargo installs from `static.crates.io`, extracts it, and
diffs it against the crate's actual git source. The headline detection,
`BUILD_RS_INJECTED`, fires when a `build.rs` exists in the published artifact but
not in git.

The part I think matters most is *what* it diffs against. Every modern `.crate`
embeds a `.cargo_vcs_info.json` recording the exact `git.sha1` the artifact was
built from. cargo-witness reads that and compares against the precise commit the
artifact claims to come from — no tag-guessing, no heuristics about which release
matches which version. When a crate was published via crates.io **Trusted
Publishing**, there's also an OIDC-attested commit (`trustpub_data.sha`) that the
publisher can't forge, and cargo-witness prefers that. Older crates fall back to
git-tag resolution.

Example run:

```
$ npx cargo-witness --scan --lock Cargo.lock

  serde@1.0.197        (git root: serde) @5fa711d   [clean]
  serde_derive@1.0.197 (git root: serde_derive) @5fa711d   [clean]
  tokio@1.36.0         @a1b2c3d   [clean]
  anyhow@1.0.80        @9f0e1d2   [clean]

  4 checked, 0 suspicious
```

Other detections (with severity): `BUILD_RS_MODIFIED` (high), `SOURCE_MODIFIED`
(medium), `FILE_NOT_IN_GIT` (medium), `BINARY_NOT_IN_GIT` (high),
`CHECKSUM_MISMATCH` (high), `VCS_MISMATCH` (info), `TRUSTED_PUBLISH` (info — a
positive assurance signal), `YANKED` (info).

It's workspace-aware, so it doesn't false-positive on crates like `serde` whose
`build.rs` lives in a subdirectory of a monorepo. It works against GitHub, GitLab,
and Codeberg. Modes: one-time `--scan`, nightly `--daemon`, `--report`, and `--ci`
(fails a PR when a newly-added dependency is suspicious). It also ships as a GitHub
Action with a job summary, a `fail-on` severity gate, and SARIF output for code
scanning.

No API keys, no accounts, no paid services — a `GITHUB_TOKEN` just raises the
git-trees API rate limit. Runs on any machine with Node 22+.

Honest about what it is: a detection aid, not a guarantee. An attacker who *also*
tampers with the git tag/commit, or a crate whose repo has no matching commit, can
evade it (reported as `NO_GIT_TAG` — not a clean verdict). Positioning vs.
neighbors: `cargo-audit` flags known CVEs from the RustSec DB; `cargo-vet` and
`cargo-crev` are human-attestation systems. Nothing mainstream does
artifact-vs-source diffing with a `build.rs` focus. The long-term trajectory is to
compose with crates.io provenance/attestation as it matures — Trusted Publishing
support is the first step.

Repo, install instructions, and the full detection list are in the README.
Feedback from people who run large lockfiles or maintain popular crates is
especially welcome.

---

## r/rust post

**Title:**

> cargo-witness: diff the published .crate against its git source to catch injected build.rs (the onering pattern)

**Body:**

After the *onering* supply-chain attack (June 10, 2026) — a malicious `build.rs`
injected into a published `.crate` that was never present in the crate's public
repo — I wanted a cheap, automated check for that specific class of attack, since
source review on GitHub can't catch it by construction. The artifact on
crates.io is a separate upload from what's in git.

**What it does:** downloads the exact `.crate` from `static.crates.io` (the bytes
Cargo actually installs), extracts it, and diffs it against the crate's real git
source. The headline detection, `BUILD_RS_INJECTED`, fires when a build script is
in the artifact but not in git.

**What it diffs against — the part I care about being correct:** it reads
`.cargo_vcs_info.json` from inside the `.crate`, which records the exact `git.sha1`
the artifact was published from, and compares against *that* commit — no
tag-guessing. When the crate was published with crates.io **Trusted Publishing**,
it uses the OIDC-attested commit (`trustpub_data.sha`), which the publisher can't
forge. Older crates fall back to resolving common tag formats.

```
$ npx cargo-witness --scan --lock Cargo.lock

  serde@1.0.197  (git root: serde) @5fa711d   [clean]

  1 checked, 0 suspicious
```

It's workspace-aware — `serde`'s `build.rs` lives at `serde/build.rs` in the
monorepo, so a naive root-vs-root diff would flag one of the most-used crates in
existence. cargo-witness resolves the crate's true root inside the git tree first,
which kills that false positive without hiding a real injection. Multi-host:
GitHub, GitLab, Codeberg.

Detections and severity: `BUILD_RS_INJECTED` (high), `BUILD_RS_MODIFIED` (high),
`SOURCE_MODIFIED` (medium), `FILE_NOT_IN_GIT` (medium), `BINARY_NOT_IN_GIT` (high),
`CHECKSUM_MISMATCH` (high), `VCS_MISMATCH` (info), `TRUSTED_PUBLISH` (info, a
positive signal), `YANKED` (info).

Modes: `--scan` (one-time), `--daemon` (nightly, desktop-notifies on findings),
`--report`, and `--ci` (scans only newly-added deps, exits non-zero on suspicious).
It also ships as a GitHub Action with a job summary, `fail-on` severity gate, and
SARIF output. Suppress accepted findings with a `.cargo-witness.json` allowlist. No
keys or paid services — a `GITHUB_TOKEN` only raises rate limits.

**Where it sits relative to existing tools:** it doesn't replace `cargo-audit`
(known CVEs from RustSec) or `cargo-vet`/`cargo-crev` (human attestation). It's a
different axis: automated artifact-vs-source diffing focused on `build.rs`, which
nothing mainstream does today.

**Honest limitations** (stated because this sub deserves it): it's a detection aid,
not a guarantee. An attacker who also rewrites the git tag/commit the artifact
points at, or a crate whose repo simply has no matching commit, can evade it — that
case is reported as `NO_GIT_TAG`, which is explicitly *not* a clean verdict. A
clean result is one signal among many, not proof a dependency is safe. The plan is
to lean harder on crates.io provenance/attestation as it matures; Trusted
Publishing support is step one.

Happy to answer questions about the diffing approach or false-positive handling.

---

## Social (≤280 chars)

> cargo-witness: catch Rust supply-chain attacks like *onering* — a malicious
> build.rs shipped in the published crate but never in its git repo. Diffs the exact
> .crate Cargo installs vs the exact published commit. No keys, no cost.
> `npx cargo-witness --scan`

(258 characters.)

---

## Why now

Two things converged in mid-2026.

First, the **onering attack (June 10, 2026)** made the artifact-vs-source gap
concrete and public. It demonstrated that reviewing a crate's source on GitHub is
not sufficient, because the published `.crate` is a distinct upload — an attacker
with a publish token can inject a `build.rs` into the artifact that never touches
the repository. This is precisely the gap cargo-witness watches.

Second, **crates.io Trusted Publishing** (OIDC-based publishing that attests the
exact commit an artifact was built from) has started to roll out. This is the first
piece of first-party provenance that a publisher *cannot* forge, and it gives a
tool like cargo-witness a trustworthy baseline to diff against. cargo-witness reads
the attested commit (`trustpub_data.sha`) when present and reports it as a positive
assurance signal (`TRUSTED_PUBLISH`).

The window matters: the attack primed the Rust security community to care about
this exact pattern, and the ecosystem primitive needed to verify it well (Trusted
Publishing) is arriving at the same time. cargo-witness is a pragmatic bridge — a
cheap tripwire today that composes with provenance/attestation as coverage grows.

---

## Responsible disclosure

cargo-witness is a detection tool, and it will occasionally find a *real*
divergence in a popular crate. If that happens, **do not open a public issue or
post the finding publicly first.** Follow coordinated disclosure:

1. **Report privately to the crate owner** — via a private channel (the crate's
   security policy, a private GitHub security advisory on the crate's repo, or
   direct contact with the maintainer). Give them the crate name/version, the
   commit compared against, the specific flag, and how to reproduce with
   cargo-witness.
2. **Report to the RustSec advisory database** —
   [github.com/rustsec/advisory-db](https://github.com/rustsec/advisory-db) — so
   the wider ecosystem can be protected through the established Rust security
   channel.
3. **Allow time for a fix** before any public disclosure, and coordinate timing
   with the maintainer and RustSec.

A finding from cargo-witness is a starting point for investigation, not a public
accusation. Divergences can have benign explanations (see the FAQ on false
positives and `NO_GIT_TAG`); confirm before you escalate, and escalate privately.
