# Zombo's Razor: plan

Agreed in a grilling session. Terms are in `CONTEXT.md`. Decisions that are hard to reverse are in ADR-0006 and ADR-0007, both proposed until the spike passes.

## Goal

Replace MXToolbox, DNSChecker, WhatsMyDNS, WHOIS sites and SSL Labs with one fast, secure, good-looking native Linux app. Replace Geopeeker's daily use ("is it down or just caching?") with the Agreement verdict. SecurityTrails, screenshots and casework are out of scope.

## Identity

- Name: Zombo's Razor. Binary: `zombo`. App ID: `io.github.scribek2.zombos-razor` (no team-owned domain assumed).
- Targets: Linux, x86_64. Tested on Ubuntu 24.04, 26.04, 26.10 and Arch.
- Before the rename ships: check for clashes (existing products, crate names, domains). Rename last; it only touches strings.

## Phases

1. **Spike** (ADR-0006): passed.
2. **`zombo-core`**, in this order, each Check done only when its Go fixtures pass in Rust:
   1. DNS records from authoritative servers and many public resolvers, with TTL and Agreement. Parallel, streaming.
   2. Delegation, glue, lame nameservers, DNSSEC.
   3. WHOIS/RDAP.
   4. Email: MX, SPF (10-lookup count), DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, SMTP banner and STARTTLS, blacklists, rDNS and FCrDNS, header and mail-log analysis.
   5. Web: HTTP redirects, headers and origin-vs-CDN, certificate and chain (level 1), CDN and ASN, TCP port test.
3. **`zombo-ui`**: one box (Diagnosis), a command palette for single Checks, Watch.
4. **Later**: opt-in outside check for "down for everyone" (verify RIPE Atlas and probe-API limits first); full TLS configuration scan (level 2, needs a custom TLS probe); unprivileged traceroute; light theme; aarch64.
5. **Retire Go**: ship one last Go release with an export-to-Markdown button for old Cases, then delete the Go code and the web UI.

## Security

- No telemetry. The app contacts only Targets and a short documented list of services.
- Untrusted input (DNS, headers, certificates, mail logs) is parsed in safe Rust and fuzzed.
- No `unsafe` outside the GPUI boundary. `cargo-deny` and `cargo-audit` in CI.
- Releases are signed with minisign. The updater keeps today's flow (daily check, `SHA256SUMS`, swap, restart), verifies the signature first, and never applies an update without a prompt.
- No API keys in v1. Add the OS keyring only when a feature needs one.

## Performance budgets

| Budget | Target | Gate |
|---|---|---|
| Cold start to interactive window | under 300 ms | measured on a team laptop and recorded |
| First DNS result | under 150 ms | measured on a team laptop and recorded |
| Propagation | all resolvers parallel, results stream; never wait for the slowest | CI |
| Scroll rendering | 120 fps | measured on a team laptop and recorded |
| Idle memory | under 150 MB | measured on a team laptop and recorded |
| AppImage size | under 40 MB | CI |
| Parser speed | no regression | CI |

CI runners have no GPU, so CI renders through llvmpipe in a headless compositor (for example `cage` or `weston --backend=headless`). The old HTTP-based `packaging/smoke.sh` does not apply to a GPUI app and is replaced by a headless-compositor launch test.

## Verification

1. Go `testdata` fixtures run through the Rust parsers; outputs must match.
2. Fuzzing on every parser of untrusted input.
3. Recorded DNS and HTTP fixtures, so tests run offline.
4. GPUI view tests for layout and keyboard flow.
5. AppImage launch test on clean Ubuntu and Arch (headless compositor).
6. CI gates from the table above.

## Design

Dark-first, dense, keyboard-first, with a command palette and the existing tuned motion carried over. Foundation, from Geist and Linear:

1. Geist-style 10-step semantic color scales (100 to 300 backgrounds, 400 to 600 borders, 700 and 800 high-contrast fills, 900 and 1000 text).
2. Dark theme derived in LCH from three inputs: base, accent, contrast. A light theme can come later from the same inputs.
3. Geist Sans and Geist Mono, bundled under the SIL OFL 1.1. Each copy carries the license text; the font is not modified.
4. Radii 6 px and 12 px.
5. Status colors for Findings (red, amber, green), always with a text label.
6. Soft borders and few separators ("structure should be felt, not seen").
7. Monospace for every DNS record, IP and header.

Type sizes, spacing, motion and keyboard rules are not published by either source. We define them and record them in `DESIGN.md`.

## Open facts to verify

- Component library: `gpui-component` vs `gpui-kit` status (reports conflict). Decided in the spike.
- RIPE Atlas and free probe-API limits (later phase).
- Orca/AT-SPI behaviour with GPUI (spike).
- Name clash check.
