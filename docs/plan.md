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
      - **Done:** the public-resolver half (`zombo-core::{dns,lookup,propagation,target}`, `zombo propagation`), ported from `internal/app/{dns,propagation,target}.go`. Tests share zone files in `testdata/zones` with the Go tests.
      - **Done:** the authoritative Vantage (`discover_nameservers`; nameservers asked directly with recursion off). It answers "down, or just caching?": nameservers that disagree are a zone problem (`dns_authoritative_mismatch`); resolvers that differ from agreeing nameservers are serving cache (`dns_propagation_stale_cache`, with the longest remaining TTL). An answer without the AA flag is not trusted (`dns_authoritative_not_authoritative`).
      - **SOA serial:** nameservers are also asked for the SOA. If they disagree and the serials differ, one is behind (`dns_authoritative_behind`, warning, with the zone's refresh interval). If the serials are the same but the data differs, the host did not bump the serial (`dns_authoritative_mismatch`, critical). Found live on a hosting provider whose two nameservers served different TXT data under one serial, then converged minutes later.
      - **Limits:** one address per family per nameserver is asked (anycast operators list several); IPv6 is skipped when the machine has no route. The positive path (a real nameserver answering with AA) is tested only against fakes: this network's router intercepts all port-53 traffic, UDP and TCP, so live runs here show only the detection. Re-check from a network that does not intercept DNS.
      - **Agreement verdict:** `PropagationResult.agreement` is one of `Agree`, `Cached`, `NameserversDiffer`, `ResolversDiffer`, `Inconclusive`, computed from the nameserver and resolver comparisons (priority in that order: zone problems first). Fixed on the way: resolvers that all serve old records no longer get a "Propagated" finding.
      - **Known gap:** on a network that intercepts DNS, every resolver is one box, so the verdict can read `Agree` next to a "not authoritative" warning. A dedicated Finding (and probably a downgraded verdict) for interception is the follow-up.
      - **Delegation and glue** (`zombo-core::delegation`, `zombo delegation <domain>`): asks the parent zone's server for the referral (recursion off), then each delegated nameserver for the SOA and its own NS set. Findings: `dns_delegation_mismatch` (parent vs zone NS sets), `dns_delegation_lame`, `dns_delegation_unreachable`, `dns_delegation_single_ns`, `dns_glue_missing`, `dns_glue_mismatch`, `dns_ns_unresolvable`, `dns_ns_is_cname`, and `dns_delegation_ok`. Checked live from a clean network on two domains. On an intercepting network every server reads as lame (the finding text says so).
      - **Next:** DNSSEC, WHOIS/RDAP.
      - **Divergences from Go, on purpose:** records keep their TTL; `zombo` queries only the scope's record types, where Go always queried all eight; results are reported as each resolver answers; `dnsSuggestions` is dropped (Suggested target was removed).
      - **Found live:** a home router answered a query sent to `192.0.2.1` (a documentation address that never answers), and a real Cloudflare nameserver address answered with AA=0 and RA=1 even over TCP. Public resolvers behind such a network agree because they are one box. A Finding for "this network intercepts DNS" is the follow-up.
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
