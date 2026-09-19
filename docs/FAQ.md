# cargo-witness — FAQ

Straight answers, including the limitations. cargo-witness is a detection aid, not
a guarantee — the questions below are meant to make that boundary clear.

---

### 1. What does cargo-witness actually do?

It downloads the exact `.crate` artifact that Cargo installs from
`static.crates.io`, extracts it, and diffs it against the crate's real git source.
Its headline detection is the *onering* pattern: a `build.rs` build script present
in the published artifact but absent from the crate's git history — code injected
at publish time that never appears in the repository people review on GitHub.

---

### 2. How is this different from `cargo-audit`?

`cargo-audit` checks your dependencies against the RustSec advisory database — it
tells you when you're using a version with a *known, already-reported*
vulnerability or a yanked crate. cargo-witness doesn't rely on a database of known
issues at all. It looks for a structural discrepancy — the published artifact not
matching its source — which is how you catch a *novel* supply-chain injection
before anyone has filed an advisory. They're complementary: run both.

---

### 3. How is this different from `cargo-vet` / `cargo-crev`?

`cargo-vet` and `cargo-crev` are human-attestation systems: people (or trusted
organizations) review crates and record that they've been audited, and you gate on
those attestations. That's valuable but relies on human review effort and
coverage. cargo-witness is automated and mechanical — it doesn't ask whether a
crate's *behavior* is trustworthy, only whether the bytes you install match the
source that was reviewed. It catches a specific thing human review structurally
misses: code that's in the artifact but not in the repo the humans read.

---

### 4. So nothing else does this?

Not in a mainstream, automated way. `cargo-audit` is known-CVE matching;
`cargo-vet`/`cargo-crev` are human attestation. Artifact-vs-source diffing with a
`build.rs` focus is the gap cargo-witness fills — a cheap automated tripwire for
"the published crate doesn't match its source."

---

### 5. What's the false-positive story?

The main historical false positive is workspace layout. Most popular crates live in
a subdirectory of a cargo workspace/monorepo — `serde@1.0.197`, for example, ships
`build.rs` at the crate root of the artifact, but in git it lives at
`serde/build.rs`. A naive root-vs-root comparison would flag serde, one of the
most-used crates in existence. cargo-witness is **workspace-aware**: it locates the
crate's true root inside the git tree first (anchored on the crate's own
`Cargo.toml` and corroborated by matching source files) before comparing, so it
doesn't flag serde — while still catching a real injection, which is absent even at
the correctly-resolved subdirectory.

Content comparison is done with git blob SHAs and newline-normalized, so CRLF vs LF
differences don't produce spurious `SOURCE_MODIFIED`/`BUILD_RS_MODIFIED` flags. For
crates that *legitimately* ship, say, a prebuilt binary, you can suppress the
finding with a `.cargo-witness.json` allowlist entry.

---

### 6. What does `NO_GIT_TAG` mean? Is that "clean"?

No. `NO_GIT_TAG` means cargo-witness could not establish a trusted baseline to diff
against — there was no embedded VCS info, no attested commit, and no resolvable git
tag/commit for that published version. It is explicitly **not** a clean verdict; it
means "could not verify," and you should treat it as unverified rather than safe.
This is also the honest evasion window: a crate whose repo has no matching commit
falls into this bucket.

---

### 7. What exactly does it verify the artifact against?

In priority order:

1. **crates.io Trusted Publishing attested commit** (`trustpub_data.sha`), when the
   crate was published via OIDC Trusted Publishing. The publisher cannot forge
   this, so it's the strongest baseline. It's also surfaced as a positive
   `TRUSTED_PUBLISH` signal.
2. **The exact commit from `.cargo_vcs_info.json`** embedded in the `.crate`, which
   records the `git.sha1` and `path_in_vcs` the artifact was built from — no
   tag-guessing.
3. **Git-tag resolution** as a fallback for older crates that predate the embedded
   VCS info (trying formats like `v{ver}`, `{ver}`, `{name}-{ver}`,
   `{name}-v{ver}`).

If none of these yields a baseline, the result is `NO_GIT_TAG` (see above).

---

### 8. Do I need an API key, an account, or a paid service?

No. There are no API keys, no accounts, and no paid services. It runs with
`npx cargo-witness --scan`. A `GITHUB_TOKEN` is optional and only raises the
git-trees API rate limit (from 60/hr to 5000/hr), which helps when scanning large
lockfiles — but it's not required.

---

### 9. Is my source code sent anywhere?

No. cargo-witness only fetches **public** data: the published `.crate` artifact from
`static.crates.io`, crate metadata from the crates.io API, and public git trees/blobs
from the crate's public host. Your own source is never uploaded. The tool reads your
`Cargo.lock` locally to learn which crate names and versions to check; that's it.

---

### 10. What about crates that aren't on GitHub?

Supported. cargo-witness is multi-host and works against **GitHub, GitLab, and
Codeberg**. The repository URL is taken from crates.io metadata, and the tool talks
to the corresponding host's tree/blob APIs. A crate hosted somewhere none of these
cover, or with no usable public repo, will fall back and may end up `NO_GIT_TAG`
(unverified).

---

### 11. Can attackers evade it?

Yes — and it's important to be clear about how. cargo-witness detects a *divergence*
between artifact and source. An attacker who compromises the git source itself, so
that the malicious artifact matches its (also malicious) source, produces no
finding. An attacker who also tampers with the tag/commit the artifact points at
can defeat tag-based baselines. And a crate whose repo has no matching commit can't
be verified at all — reported as `NO_GIT_TAG`, not as clean. The strongest defense
in the tool is the Trusted Publishing attested commit, which the publisher cannot
forge; where that's present, evasion is much harder. Treat a clean result as one
signal among many, not proof of safety.

---

### 12. Does it slow down CI?

Not meaningfully. In `--ci` mode it scans only the packages **newly added** in the
last commit, not your whole dependency graph, so most PRs check a handful of crates
or none. Work is parallelized (`--concurrency`, default 5), file content is compared
via git blob SHAs with no extra network calls (only a SHA mismatch triggers a raw
fetch), and trees/blobs are cached per repo so workspace siblings like `serde` and
`serde_derive` share a single fetch. Network calls back off politely on rate limits.
The CLI/daemon additionally keep a local SQLite cache so already-checked
`name@version` pairs are skipped on later runs.

---

### 13. How do I run it — CLI, daemon, or Action?

All three:

- **`--scan`** — one-time scan of a `Cargo.lock`. Exits non-zero if a finding meets
  `--fail-on`, so it doubles as a pipeline gate.
- **`--daemon`** — nightly scan (03:00), desktop-notifies on any suspicious finding.
- **`--report`** — print recorded suspicious packages (add `--json` for machine
  output).
- **`--ci`** — scan only newly-added dependencies and exit non-zero if any are
  suspicious.
- **GitHub Action** — ships with a job summary, a `fail-on` severity gate, and SARIF
  output for GitHub code scanning.

---

### 14. What are all the detections and their severities?

| Flag | Severity | Meaning |
|------|----------|---------|
| `BUILD_RS_INJECTED` | high | `build.rs` in the artifact, absent from git (the *onering* pattern). |
| `BUILD_RS_MODIFIED` | high | `build.rs` in both, but the published content differs from source. |
| `DEP_INJECTED` | high | A dependency declared in the artifact's `Cargo.toml` but absent from the git manifest (the *arrayref* pattern). |
| `VERSION_REMOVED` | high | crates.io deleted this version while the crate still exists (its response to a malicious publish). |
| `CRATE_REMOVED` | high | crates.io no longer serves the crate at all. |
| `SOURCE_MODIFIED` | medium | A shared source file's published content differs from git. |
| `FILE_NOT_IN_GIT` | medium | A file shipped in the artifact isn't present in source. |
| `BINARY_NOT_IN_GIT` | high | A precompiled binary (`.so`/`.dll`/`.exe`/`.dylib`/`.wasm`) in the artifact but not in source. |
| `CHECKSUM_MISMATCH` | high | Downloaded artifact's sha256 doesn't match crates.io's recorded checksum. |
| `PUBLISH_AGE` | medium | The lockfile pins a version younger than `--min-publish-age`. Opt-in: off unless you pass the flag. |
| `VCS_MISMATCH` | info | Discrepancy in the embedded VCS metadata. |
| `TRUSTED_PUBLISH` | info | Positive: the crate was published with Trusted Publishing (attested commit). |
| `YANKED` | info | The version has been yanked from crates.io. |

Any high/medium flag marks the package `SUSPICIOUS`. Use `--fail-on high|medium|info`
to set the gate.

---

### 15. Doesn't cargo already have a minimum publish age?

Yes, from Rust 1.100. [RFC 3923](https://rust-lang.github.io/rfcs/3923-cargo-min-publish-age.html)
was stabilized by [rust-lang/cargo#17335](https://github.com/rust-lang/cargo/pull/17335)
on 2026-08-28. What it gates is **resolution**. Its own rule is that with
`resolver.incompatible-publish-age = "deny"` the resolver "will ignore these
versions unless they already exist in the `Cargo.lock` file", and "once the
versions are recorded in `Cargo.lock`, subsequent resolves will keep them".

So the versions cargo's gate never sees are exactly the ones already pinned:
a version resolved before you set the policy, or one forced through with
`CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow cargo update -p foo`, which
#17335 says is "preserved within the lockfile". `cargo-witness --scan
--min-publish-age "7 days"` reads that committed lockfile and tells you which
pins are still inside the window. The two compose; they do not overlap.

`cargo-witness --write-cargo-config --min-publish-age "7 days"` writes cargo's
half into `.cargo/config.toml` for you, and reads your installed cargo to tell
you whether it will actually be enforced yet.

---

### 16. Why is `PUBLISH_AGE` medium and not high?

Because it is not a detection. A young version is not a compromised version;
the overwhelming majority of them are fine. What the flag says is that nobody
has had time to look yet, and that the three arrayref-wave compromises were
each deleted inside 107 minutes of publication. Medium is enough to fail the
default `--fail-on medium` gate, which is the behaviour a cooldown policy
wants, without claiming something the check cannot know.

It is raised to `error` in SARIF in one case: when the same crate also trips a
high flag from another lane. Young *and* diverging from its source is the
combination worth waking someone for, and it is reported as one finding rather
than two.

---

### 17. How do I suppress a finding I've reviewed and accepted?

Add an entry to `.cargo-witness.json` (or point at one with `--config`):

```json
{
  "allow": [
    { "name": "ring", "flag": "BINARY_NOT_IN_GIT" },
    { "name": "foo", "version": "1.2.3", "flag": "SOURCE_MODIFIED", "file": "src/gen.rs" }
  ]
}
```

Omitted `version`/`flag`/`file` (or `"*"`) match anything. Suppressed findings are
still counted and reported, but they don't mark the package suspicious.

---

### 18. What's the roadmap regarding provenance/attestation?

The long-term direction is to **compose with crates.io provenance and attestation**
as that ecosystem matures. Trusted Publishing support — using the OIDC-attested
commit as an unforgeable baseline — is the first step. As more crates publish with
attested provenance, cargo-witness leans on that stronger signal and needs the
weaker tag-based fallbacks less. The goal isn't to be the whole answer; it's to be a
cheap, automated tripwire today that gets more precise as first-party provenance
becomes the norm.

---

### 19. Should I treat a clean result as proof my dependencies are safe?

No. A clean cargo-witness result means the published artifact matched the source it
claims to come from — that's a genuinely useful signal, but it's one signal among
many. It doesn't vouch for the *behavior* of that source, it can't verify crates
that land in `NO_GIT_TAG`, and it can be evaded by an attacker who also compromises
the git source. Use it alongside pinning, review, `cargo-audit`, and provenance
verification — not instead of them.

---

### 20. I found a real divergence in a popular crate. What now?

Disclose responsibly, privately, first. Report to the crate owner through a private
channel and to the RustSec advisory database
([github.com/rustsec/advisory-db](https://github.com/rustsec/advisory-db)) before
any public disclosure, and give the maintainer time to fix. A finding is a starting
point for investigation, not a public accusation — divergences can have benign
explanations, so confirm before you escalate, and escalate privately. See
`docs/LAUNCH.md` for the full responsible-disclosure note.
