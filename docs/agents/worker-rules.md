# Rules every worker follows (Zombo's Razor, Rust rewrite)

You are one of several workers building independent slices in parallel, each in your own git worktree. Do not launch other agents. Own your diff end to end: write it, test it, commit it.

## First, in your worktree
1. Run `git reset --hard rewrite` on your own branch. Your worktree starts on a Go-era commit with no Cargo workspace, and every earlier worker had to do this. `rewrite` is the Rust line of work.
2. Read `docs/progress.md` (state), `docs/plan.md` (why), and `CONTEXT.md` (vocabulary: Check, Lookup, Vantage, Finding, Target, Evidence).
3. Read the Go oracle files named in your task in full (the Go code was deleted from `rewrite` on 2026-11-09; read it with `git show main:<path>`). The Go code is the behaviour spec: keep finding codes, severities, titles and message wording verbatim where one exists. Do not edit Go code.

## The Rust you build on (already merged, read the ones you need)
- `crates/zombo-core/src/dns.rs`: `exchange` and `exchange_with` (UDP then TCP, EDNS), `interception_finding`. Every DNS query goes through these. Do not write another DNS client.
- `crates/zombo-core/src/lookup.rs` (`dns_lookup`), `propagation.rs` (`Vantage`, `default_resolvers`, `ask_any`), `delegation.rs`, `dnssec.rs`, `registration.rs` (the bounded `ureq` + rustls HTTP client pattern: `spawn_blocking`, 1 MiB cap, https only, redirect limit, one overall deadline, injectable `Endpoints` for tests), `email_auth/` (a good example of a larger module split into files).
- `crates/zombo-core/src/finding.rs`: `Finding { code: &'static str, severity, title: Cow<'static, str>, message: String, recommendation: Option<Cow<'static, str>> }`. Titles and recommendations may carry runtime values via `format!(..).into()`.
- `crates/zombo/src/main.rs`: subcommands, `print_findings`, `addr`, the `USAGE` const.
- Tests: `crates/zombo-core/tests/common/mod.rs` has `FakeDns`; `tests/common/registry.rs` has fake HTTP and WHOIS servers loaded with `#[path]`. Add your own helpers in a NEW file under `tests/common/` and load it with `#[path]`, or append new functions at the end of `common/mod.rs`. Do not change existing helpers.

## Boundaries
- Put your code in NEW files and a new `pub mod` line in `crates/zombo-core/src/lib.rs`. Touch existing modules only for a tiny additive change you can name in your report.
- Do NOT edit `docs/`, `CONTEXT.md`, `deny.toml`, `.github/`, or the Go code. The lead updates docs. If a new dependency needs a `deny.toml` license entry, say so in your report; do not edit it.
- `crates/zombo/src/main.rs`: add one import line, one match arm, and your own function(s) plus a local usage const. Do not edit the top-level `USAGE` const; list the exact line to add in your report. Other workers edit this file at the same time, so keep your hunk contained.
- `Cargo.toml` of zombo-core: add only the dependencies you need. Several workers do this at once, so expect the lead to merge them.

## How to build
- Name the data shape first (typed structs, enums for states and kinds, tables or registries instead of branching). Per `principle-model-the-domain`.
- Findings come from pure functions over your result type, so every finding is unit-testable without a network.
- Make the network injectable (ports, endpoints, resolver addresses, clocks) so tests run offline.
- Test first: write each failing test, watch it fail for the right reason, then implement. Port the Go test scenarios. Share fixtures with the Go tests by copying the inline text into new files under `testdata/<your-area>/` at the repo root (read them with `env!("CARGO_MANIFEST_DIR")`, as `tests/common/mod.rs` does for zones).
- Mutation-check at least three behaviours that matter (break the code on purpose, run the tests, confirm one fails, restore). A test that still passes after the break is not testing the behaviour: fix the test and report it.
- Everything from the network is untrusted: no panics (no `unwrap`/`expect`/indexing on external data in production code), bounded sizes, bounded work, bounded time. Use `split_first_chunk`/`get`/`checked_*` style parsing. Control characters in text that reaches a Finding message are replaced.
- No `unsafe`. No OpenSSL, native-tls or any C library dependency; rustls is acceptable. Check `cargo deny check` (in `~/.cargo/bin`; `export PATH=$HOME/.cargo/bin:$PATH`).
- Comments only for a non-obvious why. No long-dash punctuation (em or en dash) in code, comments or prose.

## Quality gate (all must be clean before you report)
`cargo test --workspace`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo deny check`, `cargo audit`.

## Live check
This machine's network intercepts DNS on port 53 (a home router), so DNS-based live results may not be real. HTTPS and plain TCP are real. Run your CLI subcommand against a few real targets and paste the output; say honestly which parts looked meaningful. The lead reruns it from a clean network.

## Commits
Small ordered commits on your worktree branch (types and parsing; core logic; findings; CLI). No `Co-Authored-By` line and no session trailer in any message. Do not merge, push, or open a PR.

## Report (your final message, factual and short)
Branch name and `git log --oneline`; `cargo test` totals; clippy, deny and audit results; mutation checks and their outcome; live output; every deviation from the Go behaviour and why; the exact line to add to the top-level `USAGE`; any new dependency and its license; anything you could not verify.
