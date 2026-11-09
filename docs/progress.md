# Progress

The single list of what is done, what is running, and what is left. Update it in the same commit as the work. `docs/plan.md` explains the why; this file tracks the state.

Last updated: 2026-11-09. Branch: `rewrite`.

## Active now

| Work | Owner | Notes |
|---|---|---|
| Evidence analysis: email headers and mail logs (`evidence/`, `zombo evidence headers|maillog`) | worker D | Pure text. Go: `headers.go`, `maillog.go`, `evidence.go` |
| TLS certificate and chain level 1, TCP port test (`tls.rs`, `ports.rs`, `zombo tls`, `zombo ports`) | worker E | Go: `ssl.go`, `hosting.go`. Builds a reusable `inspect over a stream` seam for SMTP STARTTLS |
| Blacklist, reverse DNS and FCrDNS (`blacklist.rs`, `rdns.rs`, `zombo blacklist`, `zombo rdns`) | worker F | Go: `blacklist.go`. Uses the system resolver, not public ones, for blocklists |
| Web inspection: redirect chain, headers, origin vs CDN, CDN and ASN (`web.rs`, `zombo web`) | worker G | Go: `website.go`, `origin.go`. Reuses the `ureq` client pattern |

Each worker follows `docs/agents/worker-rules.md`. Waiting on worker E: SMTP banner and STARTTLS.

**Merge order when workers finish:** review each diff, merge one at a time (A, B, C), resolve the mechanical conflicts in `Cargo.toml`, `lib.rs`, `main.rs`, `tests/common/mod.rs`, run the whole suite plus clippy, `cargo deny check`, then update this file. Live-check each Check from the VPS (clean network).

## Done

- [x] Workers A (registration), B (email) and C (DNSSEC) reviewed and merged into `rewrite`. 236 tests pass; clippy, `cargo deny` and `cargo audit` clean. Email auth (`email_auth/`, `zombo email`): SPF walker with the 10-lookup count, DKIM, DMARC, TLS-RPT, BIMI, MTA-STS record. MX comes from the lookup inside `email_auth`

- [x] Planning session, ADR-0006 and ADR-0007, `CONTEXT.md` rewritten
- [x] GPUI spike passed (Ubuntu 24.04.5 laptop with Orca, 24.04 and 26.04 containers, AMD, Intel)
- [x] Rust workspace (`zombo-core`, `zombo`), release profile tuned
- [x] Target parser (`target.rs`)
- [x] DNS client: UDP then TCP, EDNS 1232 (`dns.rs`)
- [x] DNS lookup, 8 record types, TTLs, Go-exact record text (`lookup.rs`)
- [x] DNS propagation across 10 public resolvers, streaming, scopes (`propagation.rs`)
- [x] Authoritative Vantage: nameserver discovery, AA-flag trust, stale-cache finding
- [x] SOA serial comparison (behind vs serial not bumped)
- [x] Agreement verdict
- [x] Delegation and glue checks (`delegation.rs`, `zombo delegation`)
- [x] HTTP client chosen: `ureq` 3 with rustls (ring, bundled webpki-roots). Add `CDLA-Permissive-2.0` to `deny.toml`. Reused for the later web and MTA-STS checks
- [x] DNS-interception Finding (`dns_network_intercepts`) and `Agreement::Intercepted`, for propagation and delegation. Passive: at least two nameservers at different addresses all answering without AA but with RA
- [x] Shared zone fixtures in `testdata/zones` for Go and Rust tests
- [x] Verified live from a clean network (VPS) for propagation, stale cache, delegation

## To do: DNS and domain registration

- [ ] Interception canary probe for resolver-only runs (`--no-authoritative`): needs a short extra probe to an address that must never answer, so it is opt-in to keep clean runs fast
- [x] WHOIS/RDAP (`registration.rs`, `zombo registration`): RDAP first with WHOIS fallback, DENIC form, bounded `ureq`+rustls client (merged from worker A). 98 tests pass
- [x] DNSSEC (`dnssec.rs`, `zombo dnssec`, merged from worker C): resolver verdict (CD=0 vs CD=1) plus local DS/DNSKEY/RRSIG analysis. Key tag and DS digest proven on real cloudflare.com and iana.org data. 133 tests pass. Resolver verdicts NOT yet seen live from a clean network (do it from the VPS). Full chain-to-root validation is deliberately out of scope: validating resolvers do that, and the CD trick plus DS/DNSKEY/RRSIG analysis explains failures
- [ ] More record types in lookup (SRV, PTR, DNSKEY, DS) if needed by the UI

## To do: email

Go sources to port: `email_auth.go`, `blacklist.go`, `headers.go`, `maillog.go`.

- [x] MX
- [x] SPF with the 10-lookup count
- [x] DKIM by selector
- [x] DMARC
- [x] MTA-STS, TLS-RPT, BIMI: DNS records only. The MTA-STS policy file over HTTPS is not fetched yet (the HTTP client from `registration` can do it)
- [ ] SMTP banner and STARTTLS test
- [ ] Blacklist lookup
- [ ] Reverse DNS and forward-confirmed reverse DNS
- [ ] SMTP banner and STARTTLS test (no Go source; new)
- [ ] Header analysis (Evidence)
- [ ] Mail-log analysis (Evidence)

## To do: hosting and web

Go sources to port: `website.go`, `origin.go`, `ssl.go`, `hosting.go`.

- [ ] HTTP redirect chain, headers, status
- [ ] Origin versus CDN comparison
- [ ] Certificate and chain, level 1 (trust, expiry, SAN match, OCSP stapling, HSTS, CAA)
- [ ] CDN and ASN detection
- [ ] TCP port connect test

## To do: the app

- [ ] `zombo-ui` crate on `gpui-kit` (pinned snapshot, ADR-0007)
- [ ] One box (Diagnosis): all relevant Checks in parallel, results streaming
- [ ] Command palette for single Checks
- [ ] Watch (re-run until the answer changes)
- [x] `DESIGN.md` written (layout, Checks per target kind, states, Evidence, copy, history, Watch, keyboard, settings, accessibility, motion, type scale, spacing, initial dark palette with contrast checked)
- [ ] Design foundation in code: tokens, LCH theme derivation, fonts, 6/12 px radii
- [ ] Table cell labels for screen readers on every result view
- [ ] Tabs, rail with five Check states, status bar with Watches, empty state with recent targets
- [ ] Copy at three levels (value, section, Diagnosis) in Markdown, plus JSON per section
- [ ] Evidence paste tabs; settings pane (resolvers, DKIM selectors, timeout, proxy, notifications)
- [x] Main screen sketch: `docs/sketches/main-screen.html` (+ PNG). Built as HTML, not Pencil: the Pencil tool needs the Cursor IDE running with its extension. Shows the stale-cache case on the test domain
- [ ] Window title and app ID set; clear error when the compositor has no `wl_seat`
- [ ] Recent-lookups list (no Cases)

## To do: security, quality, release

- [x] CI workflow `.github/workflows/rust.yml` (test, clippy `-D warnings`, `cargo deny`, `cargo audit`) and `deny.toml`; `cargo deny check` and `cargo audit` pass locally. Not yet run on GitHub (no remote yet)
- [ ] After the workers merge: `#![forbid(unsafe_code)]` via `[workspace.lints]`, then `cargo fmt` and a rustfmt CI check
- [ ] Fuzz tests for every parser of untrusted input (DNS messages, RDAP/WHOIS, headers, mail logs, certificates)
- [ ] Performance gates in CI: parser speed, AppImage size under 40 MB, llvmpipe render in a headless compositor
- [ ] Measure cold start, scroll frame rate, idle memory on a real laptop and record them
- [ ] AppImage build for `zombo` and the CLI from an Ubuntu 24.04 container; launch test on clean Ubuntu and Arch
- [ ] Signed releases (minisign) and updater (keep today's flow, verify signature first)
- [ ] Replace `packaging/smoke.sh` with a headless-compositor launch test

## To do: transition

- [ ] Parity: every Go Check passes its Go fixtures in Rust
- [ ] Last Go release with export-to-Markdown for old Cases
- [ ] Delete the Go code and the web UI
- [ ] Name-clash check for "Zombo's Razor", then rename the repo and app strings
- [ ] Open the PR for `spike/gpui` and `rewrite`

## Later, not scheduled

- [ ] Opt-in outside check for "down for everyone" (verify RIPE Atlas and probe-API limits first)
- [ ] Full TLS configuration scan (level 2, needs a custom TLS probe)
- [ ] Unprivileged traceroute
- [ ] Light theme, aarch64

## Decisions waiting

- [ ] Refactor: DNSSEC has its own zone discovery (`find_zone`, asks with DO and CD set) because `find_apex` asks with CD=0 and a validating bootstrap resolver SERVFAILs on exactly the broken zones. Give `find_apex` the CD flag and delete the duplicate
- [ ] DNSSEC expiry warning is `min(3 days, lifetime / 4)`, not a flat 3 days (Cloudflare signs for about 2 days). Accepted as a deliberate deviation; unsigned-yet (not-before) signatures have no finding
- [ ] Email: the SPF walk is breadth-first with a 30-lookup cap, so which subtree is cut when the cap bites can differ from Go
- [x] `Finding.title` and `Finding.recommendation` are `Cow<'static, str>`: Go's " (Registrar)" suffix is back in three registration recommendations, and "DMARC applies to N% of mail" has its Go title again
- [ ] ureq honours `HTTP_PROXY`/`HTTPS_PROXY`; keep (corporate networks) or turn off

## Live-verified from a clean network (VPS, 2026-11-09)

- [x] `dnssec`: cloudflare.com SECURE on all 4 validating resolvers, DS matches; dnssec-failed.org BOGUS on all 4 with `dnssec_ds_mismatch` (DS tag 42069 vs served key 50719)
- [x] `registration`: registered and not-registered domains over RDAP
- [x] `email`: google.com, github.com, etsy.com (11 lookups), the test domain
- [x] Earlier: propagation, stale cache, delegation
- [ ] UI note: the `dnssec` nameserver list repeats identical lines per address; collapse identical rows in the UI

## Still unverified

- [ ] NVIDIA GPUs
- [ ] The AppImage without `libfuse2` on real hardware (the work laptop has `libfuse2t64` installed)
- [ ] Broken-delegation paths against a real broken domain (fakes only so far)
- [ ] Registration: a real https redirect chain and the proxy path are untested; `.ru`/`.it` referral seen live only via IANA
- [ ] Scroll frame rate
