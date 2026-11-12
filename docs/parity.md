# Parity audit: Stackwell (Go) against Zombo's Razor (Rust)

Question: does the Rust app keep everything the team relied on in the Go app, apart from what was dropped on purpose? Casework (cases, tickets, write-ups) and SecurityTrails were dropped on purpose (plan.md "Goal", DESIGN.md "Not in the app", ADR-0002 "Status").

The Go source is no longer in the working tree. It lives in git history: the last Go commit is `b8fc3d5` (also the tag `v1.0.0` for the release), which stays reachable after the rewrite merged into `main`. To read it: `git show b8fc3d5:internal/app/dns.go`, or `git archive b8fc3d5 | tar -x -C <empty dir>`. Every script below reads Go from that commit with `git show`, so they keep working after the Go code is deleted from `rewrite`.

## How to check this document

```
scripts/parity.sh          # regenerates the generated block below, then verifies everything
scripts/parity.sh --check  # same checks, changes nothing, fails on a stale block
```

The script runs three checks:

1. `scripts/parity_findings.py` extracts every Finding from the Go source (`Code:` literals) and from the Rust source (`code: "x"` literals and calls such as `finding("x", Severity, ...)`). It rewrites the generated block in this file and fails when the block is stale.
2. `scripts/parity_findings.py --check` fails when a test cited in this file as `crate/path.rs::test_name` does not exist. A test counts when it has `#[test]` or `#[tokio::test]`.
3. `scripts/parity_lists.py` checks that each Go reference table (10 public resolvers, 10 DNSBLs, 9 ZEN return codes, 8 quick and 30 full ports, 3 propagation scopes, 2 mail providers) is in the Rust source with the same values.

Last run: 97 shared Finding codes, 1 Go code ported with deviation and 1 replaced (see "Finding codes"), every cited test found, every reference-table entry present.

## Status words

| Status | Meaning |
|---|---|
| ported | Same behaviour. The row names the Rust module and a test that covers it. |
| ported with deviation | Works, but something changed. The row says what and where the decision is recorded, or says that no record exists. |
| replaced | A different feature now answers the same need. |
| dropped on purpose | Removed by a decision. The row cites it. |
| MISSING | Nothing in Rust and no decision. |

Test names are written `crate/path.rs::name` relative to `crates/`.

## Summary

Counts of the inventory rows below (regenerate with `scripts/parity.sh`):

<!-- COUNTS -->
| Status | Rows |
|---|---|
| ported | 21 |
| ported with deviation | 17 |
| replaced | 14 |
| dropped on purpose | 18 |
| MISSING | 4 |
<!-- /COUNTS -->

Finding codes: 98 in Go. 96 ported (wording and severity checked mechanically, 10 codes whose wording differs only in spelling, read by hand), 1 ported with deviation, 1 replaced. The Go codes that were lost (the nine `dns_*` rules of the DNS Lookup) were ported test-first in this audit. Rust has 94 more codes that Go never had.

Found and fixed in this audit:

1. The nine `dns_*` DNS Lookup Findings did not exist in Rust. Now `zombo-core/src/lookup_findings.rs`, 9 tests, Go wording verbatim. Not yet called by the CLI or the UI (N1).
2. The Rust build never learned its release version. The Go build stamped it with `-ldflags -X main.version`. The Rust crates say `0.0.0`, and the updater compares that with the latest release, so a released build would offer the same release as an update for ever. Now `zombo_core::VERSION` reads `ZOMBO_VERSION`, `packaging/build-appimage.sh` sets it from `VERSION`, the updater uses it, and `zombo --version` and `zombo-razor --version` print it (the Go `-version` flag, which Rust lacked).

## Inventory

### Checks and tools

| ID | Go capability | Status | Rust and evidence | Decision or note |
|---|---|---|---|---|
| C01 | DNS Lookup: eight record types, NXDOMAIN as an answer, per-type errors | ported with deviation | `zombo-core/src/lookup.rs`; `zombo-core/tests/lookup.rs::records_read_the_same_as_in_the_go_engine`, `zombo-core/tests/lookup.rs::nxdomain_is_an_answer_not_a_failure` | plan.md phase 2.1 "Divergences from Go, on purpose": TTLs kept, only the scope's types asked, many Vantages instead of one resolver |
| C02 | DNS Lookup Findings (`dns_nxdomain`, `dns_cname_at_apex`, `dns_resolves`, `dns_no_address`, `dns_null_mx`, `dns_mx`, `dns_no_mx`, `dns_no_ns`, `dns_query_errors`) | ported with deviation | `zombo-core/src/lookup_findings.rs`; `zombo-core/tests/lookup_findings.rs::nxdomain_is_critical_and_the_only_finding`, `zombo-core/tests/lookup_findings.rs::a_failed_query_is_not_reported_as_a_missing_record`, `zombo-core/tests/lookup_findings.rs::a_hostname_is_not_held_to_the_apex_rules` | Lost until this audit. Rules ported, nothing calls them yet: N1 |
| C03 | DNS Propagation: 10 public resolvers, scopes all, mail, web, six findings | ported | `zombo-core/src/propagation.rs`; `zombo-core/tests/propagation.rs::flags_resolvers_that_disagree`, `zombo-core/tests/propagation.rs::scope_limits_the_compared_types`, `zombo-core/tests/propagation.rs::every_built_in_resolver_address_parses` | `parity_lists.py` confirms the 10 resolvers and 3 scopes. Rust adds the authoritative Vantage, TTLs, stale cache and the Agreement verdict |
| C04 | Registration: RDAP with the embedded IANA bootstrap, WHOIS fallback, IANA referral, DENIC, private suffixes | ported | `zombo-core/src/registration.rs`; `zombo-core/tests/registration.rs::rdap_reads_the_registry`, `zombo-core/tests/registration.rs::whois_answers_when_rdap_fails`, `zombo-core/tests/registration.rs::an_iana_referral_is_followed_once`, `zombo-core/tests/registration.rs::a_registered_de_domain_is_registered`, `zombo-core/tests/registration.rs::the_registered_name_of_a_private_suffix_site_is_what_is_asked` | The bootstrap is `crates/zombo-core/data/rdap_bootstrap.json`, same as Go |
| C05 | Registration runs for domains only, not hostnames | ported with deviation | `zombo-ui/src/checks.rs::a_domain_runs_every_check_and_a_host_name_the_short_list` | DESIGN.md "Checks per target kind": a hostname uses its registrable domain. Go refused hostnames (`TestRegistrationDoesNotApplyToHostnames`) |
| C06 | Email authentication: SPF walk, 10-lookup count, voids, permerrors, `all` qualifiers | ported | `zombo-core/src/email_auth/`; `zombo-core/tests/email_auth.rs::lookups_are_counted_through_includes`, `zombo-core/tests/email_findings.rs::thirteen_lookups_are_too_many`, `zombo-core/tests/email_findings.rs::each_all_qualifier_has_its_finding` | progress.md: the walk is breadth-first with a cap of 30, so which subtree is cut can differ from Go |
| C07 | DKIM: 37 common selectors, up to 20 custom, key strength, revoked | ported | `zombo-core/tests/email_auth.rs::at_most_twenty_custom_selectors_are_queried`, `zombo-core/src/email_auth/dkim.rs::rsa_key_sizes_are_read_from_the_modulus`, `zombo-core/tests/email_findings.rs::dkim_key_strength_findings_are_one_per_code` | |
| C08 | DMARC record and policy findings | ported | `zombo-core/tests/email_findings.rs::dmarc_policies_and_their_titles`, `zombo-core/tests/email_findings.rs::dmarc_monitoring_only_is_a_warning_with_two_notes` | |
| C09 | Connected rule `spf_missing_provider` (Microsoft 365, Google Workspace) | ported | `zombo-core/tests/email_findings.rs::spf_missing_the_mail_provider_is_flagged`, `zombo-core/tests/email_findings.rs::the_provider_finding_stays_silent_when_it_does_not_apply` | The only connected rule in Go |
| C10 | Website Inspection: redirect chain (max 10), loop, HTTP fallback, https not enforced, security headers, WordPress failure pages, slow response | ported with deviation | `zombo-core/src/web/`; `zombo-core/tests/web.rs::stops_after_ten_redirects`, `zombo-core/tests/web.rs::detects_wordpress_and_its_failure_pages`, `zombo-core/tests/web.rs::missing_headers_with_frame_ancestors_standing_in_for_x_frame_options` | progress.md "Decisions waiting": User-Agent is `zombo/<version>` (Go sent a Mozilla string), no cookie jar (open), https to http redirects are followed and flagged (`web_redirect_downgrade`) |
| C11 | SSL Inspection: chain, trust states, expiry thresholds, hostname, self-signed, weak key, SHA-1 | ported | `zombo-core/src/tls.rs`; `zombo-core/tests/tls.rs::expiry_warnings_follow_the_go_thresholds`, `zombo-core/tests/tls.rs::a_missing_intermediate_is_an_incomplete_chain`, `zombo-core/tests/tls.rs::a_wrong_host_is_critical_and_not_valid` | |
| C12 | SSL Inspection reports a server that negotiated TLS 1.0 or 1.1 (`ssl_inspection_old_protocol`) | ported with deviation | `zombo-core/src/tls.rs` (`handshake_error`) | rustls speaks TLS 1.2 and 1.3 only, so the Finding can never fire. A TLS 1.0/1.1-only server now gives a handshake error with a hint. progress.md "To do: hosting and web" records the limit. No test names the finding or the hint: N2 |
| C13 | SSL Inspection port option 443, 465, 587, 993, 995, 8443, with the SMTP STARTTLS upgrade on 587 | ported with deviation | `zombo-core/tests/tls.rs::the_inspection_runs_over_any_connected_stream`, `zombo-core/tests/smtp.rs::certificate_problems_use_the_tls_findings` | CLI: `zombo tls host:port` for any implicit-TLS port, `zombo smtp` for 587. UI: the TLS section is 443 only. DESIGN.md says "TLS on a port later" for IP targets only: N3 |
| C14 | Hosting Reachability: quick and full sweep, banners, open, closed, filtered, no route | ported | `zombo-core/src/ports.rs`; `zombo-core/tests/ports.rs::the_quick_sweep_classifies_each_port`, `zombo-core/tests/ports.rs::the_full_table_has_the_hosting_ports`, `zombo-core/tests/ports.rs::web_mail_and_database_findings` | Rust adds `hosting_reachability_mail_filtered` (progress.md). On demand in the UI |
| C15 | Blacklist: 10 DNSBLs, ZEN codes, refusals, PBL, IPv6 skip, cap of 5 addresses | ported | `zombo-core/src/blacklist.rs`; `zombo-core/tests/blacklist.rs::reports_a_listing_with_its_reason_and_delist_link`, `zombo-core/tests/blacklist.rs::a_refused_query_is_neither_listed_nor_clean`, `zombo-core/tests/blacklist.rs::caps_the_addresses_it_checks` | `parity_lists.py` confirms the 10 lists and 9 ZEN codes |
| C16 | Evidence: paste email headers, analysed | ported | `zombo-core/src/evidence/headers.rs`; `zombo-core/tests/evidence_headers.rs::spoofed_headers_are_called_out`, `zombo-core/tests/evidence_headers.rs::the_delivering_server_is_known_apart_from_the_claimed_origin` | Pasted text stays in memory (DESIGN.md "Evidence"); Go kept it in the Case |
| C17 | Evidence: paste a mail log, analysed by queue ID | ported | `zombo-core/src/evidence/maillog.rs`; `zombo-core/tests/evidence_maillog.rs::a_delivered_message_is_reconstructed_by_queue_id`, `zombo-core/tests/evidence_maillog.rs::a_large_log_does_not_flood_the_findings` | |
| C18 | Playbooks: Email Delivery, Hosting and Website, Orientation | dropped on purpose | | ADR-0002 "Status": playbooks dropped, the Diagnosis replaces them |
| C19 | Team playbooks from a folder of YAML files (Settings, `playbook_dir`) | dropped on purpose | | ADR-0002 "Status" |
| C20 | Playbook boundary notes, shown as "Not visible from here" in the Write-up | dropped on purpose | | Part of the dropped Playbook data. The notes themselves were useful: N4 |
| C21 | Run a Check on all Targets of a Case; several Targets in one Case | replaced | `zombo-ui/src/checks.rs::a_domain_runs_every_check_and_a_host_name_the_short_list` | One tab per target, one Diagnosis per tab (DESIGN.md "Structure") |
| C22 | Suggested Targets from results and Evidence | dropped on purpose | | plan.md phase 2.1: "dnsSuggestions is dropped (Suggested target was removed)" |
| C23 | Cancel a running Step (`x`, `POST .../cancel`) | MISSING | | No cancel action in `crates/zombo-ui/src/keys.rs`. A Check ends by its timeout and offers Retry. N9 |
| C24 | Re-run a Check (`r`) | ported | `zombo-ui/src/keys.rs::the_documented_shortcuts_map_to_their_actions`, `zombo-ui/src/diagnosis.rs::a_propagation_rerun_reports_records_added_and_removed` | `Ctrl+R` |
| C25 | Changes between two runs of a Check (`diff.go`) | ported with deviation | `zombo-ui/src/outcome.rs::diff_lists_what_was_added_and_what_was_removed`, `zombo-ui/src/outcome.rs::a_rerun_compares_with_the_previous_finished_run` | DESIGN.md "History and change": in-session only. Go compared with Steps stored in the database |
| C26 | Findings sorted by severity, one list per Case | ported with deviation | `zombo-ui/src/diagnosis.rs::findings_sort_worst_first_and_keep_input_order_within_a_severity`, `zombo-ui/src/diagnosis.rs::the_summary_lists_a_finding_that_several_checks_share_once` | Findings are per section, with a Summary across sections |
| C27 | `check_failed` Finding and a failed Step with its error | replaced | `zombo-ui/src/status.rs::only_failed_and_timed_out_offer_retry`, `zombo-ui/src/diagnosis.rs::a_failure_keeps_its_reason` | Five Check states with Retry (DESIGN.md "Check states") |
| C28 | History pane: find past Cases by text, purge old Cases | dropped on purpose | | Casework is out of scope (plan.md "Goal"); DESIGN.md "Nothing stored" |
| C29 | Recent Cases list | replaced | `zombo-ui/src/workspace.rs::recent_targets_are_newest_first_deduplicated_and_capped_at_eight`, `zombo-ui/src/config.rs::recent_targets_hold_only_a_name_and_a_time_and_round_trip` | Eight recent targets, name and time only |
| C30 | Case title, ticket reference, status (resolve, reopen), Rep notes, active Case | dropped on purpose | | CONTEXT.md "casework was dropped"; DESIGN.md "Not in the app" |
| C31 | Write-up: Markdown and plain text, preview | dropped on purpose | | DESIGN.md "Not in the app" lists a Write-up. Diagnosis copy replaces it: see "Export to Markdown" |
| C32 | Per-Step "Copy" as plain text | replaced | `zombo-ui/src/copy.rs::a_section_is_markdown_with_values_in_code_spans` | Copy a section, a value or the whole Diagnosis |
| C33 | Secrets store (system keyring or a 0600 file) and the Settings secrets list | dropped on purpose | | plan.md "Security": "No API keys in v1"; SecurityTrails is out of scope. No Go Check read a secret |
| C34 | Updater: daily check, `SHA256SUMS`, atomic swap, restart | ported with deviation | `zombo-core/tests/update.rs::a_signed_newer_release_replaces_the_file_atomically_and_keeps_its_mode`, `zombo-ui/src/update_model.rs::a_check_is_due_once_a_day` | plan.md "Security": adds a minisign signature, a prompt, "skip this version". The key is still the test key (docs/release.md) |
| C35 | Single instance: a lock file and a socket hand the URL to a second launch | dropped on purpose | | ADR-0006 supersedes ADR-0001 and ADR-0005: no localhost server. Two Rust launches open two windows: N8 |
| C36 | Loopback host check and Origin check on the API (`origin.go`) | dropped on purpose | | ADR-0006 "Consequences": the attack surface that ADR-0005 defended disappears |
| C37 | Server-sent events stream results to the page | replaced | `zombo-ui/src/diagnosis.rs::answers_stream_into_rows_before_the_result_exists` | In-process streaming |
| C38 | Remote or headless use: `--no-browser` and an SSH tunnel | replaced | `zombo/src/main.rs` (the `zombo` CLI) | The CLI runs the Checks on a server. The window needs a display |
| C39 | Checks ignore proxies, the updater honours them | ported with deviation | `zombo-core/tests/registration_proxy.rs` | progress.md "Decisions waiting": proxy policy decided, registration honours `HTTP_PROXY`, web does not |
| C40 | DNS Lookup, email, rDNS, MX asked through the machine's resolver (first `/etc/resolv.conf` entry) | ported with deviation | `zombo-core/src/resolver.rs`; `zombo-ui/src/checks.rs::the_rep_s_resolvers_join_the_ten_public_ones_without_repeating_any` | Rust asks public resolvers and authoritative servers for DNS and email. The machine's resolver is used for the blacklist, rDNS and MX only. No record of this decision: N5 |
| C41 | Check timeout 15 s | ported with deviation | `zombo-ui/src/settings_model.rs::the_timeout_is_one_to_one_hundred_twenty_seconds`, `zombo-ui/src/settings_model.rs::the_setting_replaces_an_automatic_limit_and_scales_the_question_limit` | Setting `timeout_seconds` |
| C42 | Playwright end-to-end tests of the page | replaced | `zombo-ui/src/keys.rs::the_documented_shortcuts_map_to_their_actions` | GPUI view-model tests and the AppImage smoke test (plan.md "Verification") |

### Inputs and options

| ID | Go capability | Status | Rust and evidence | Decision or note |
|---|---|---|---|---|
| I01 | Target parsing: URL reduced to host, port and path dropped, IDN to punycode, email, IPv4 and IPv6, private suffixes count as domains | ported | `zombo-core/src/target.rs::classifies_and_normalises`, `zombo-core/src/target.rs::rejects_garbage` | |
| I02 | Underscore labels (`_dmarc`, `selector._domainkey`) | ported | `zombo-core/src/target.rs::allows_underscore_labels` | |
| I03 | Propagation option `scope` (all, mail, web) | ported with deviation | `zombo-core/tests/propagation.rs::scope_limits_the_compared_types` | CLI `--scope`. The UI always uses `all`. No record: N3 |
| I04 | Email option `scope` (all, spf, dkim, dmarc) | ported with deviation | `zombo-core/tests/email_auth.rs::a_healthy_domains_spf_resolves_its_include` | Rust always runs every part. No record: N3 |
| I05 | Email option `selectors` (free text, up to 20) | ported | `zombo-core/src/email_auth/dkim.rs::selectors_are_split_lowercased_and_made_distinct`, `zombo-ui/src/settings_model.rs::selectors_follow_the_dkim_rules_and_the_cap_of_twenty` | CLI `--selector`, setting `dkim_selectors` |
| I06 | Hosting option `depth` (quick, full) | ported | `zombo-core/tests/ports.rs::the_full_table_has_the_hosting_ports` | CLI `--full` |
| I07 | SSL option `port` | ported with deviation | see C13 | |
| I08 | Evidence kinds: email headers, mail log | ported | `zombo-ui/src/evidence_model.rs::the_sniffer_tells_the_four_fixtures_apart` | The app also sniffs which kind a paste is |

### Export and copy

| ID | Go capability | Status | Rust and evidence | Decision or note |
|---|---|---|---|---|
| E01 | Copy Write-up as Markdown (`c`), API `?format=markdown` | replaced | `zombo-ui/src/copy.rs::the_whole_diagnosis_lists_sections_that_ran_in_rail_order_and_names_the_rest` | Diagnosis copy, `Ctrl+Alt+C`. The differences are listed below |
| E02 | Copy Write-up as plain text (`C`), API `?format=text` | dropped on purpose | | DESIGN.md "Copy": Markdown "stays readable as plain text" |
| E03 | Toast after a copy ("Copied ...") | ported | `zombo-ui/src/copy.rs::each_format_names_what_it_copied` | |
| E04 | Write-up Changes section: what changed between runs, "Resolved:" lines | MISSING | | `copy.rs` has no builder for it. The UI shows "Changed since the previous run" only on screen. N6 |

### Settings, keyboard and persisted data

| ID | Go capability | Status | Rust and evidence | Decision or note |
|---|---|---|---|---|
| S01 | Settings pane: secrets, team playbook folder | dropped on purpose | | See C19 and C33 |
| S02 | Settings pane in Rust: resolvers, selectors, timeout, proxy, notifications, update check | replaced | `zombo-ui/src/settings_model.rs::a_full_file_round_trips`, `zombo-ui/src/config.rs::saving_writes_a_private_file_in_a_private_new_directory_and_loading_reads_it_back` | `$XDG_CONFIG_HOME/zombo-razor/config.toml` |
| S03 | Launch flags `-port`, `-no-browser`, `-no-keyring`, `-update-url` | dropped on purpose | | ADR-0006: no server, no secrets. The update address is not a flag in release builds (docs/release.md) |
| S04 | Launch flag `-version` | ported | `zombo/tests/version.rs::version_flag_prints_the_name_and_the_stamped_version` | Fixed in this audit (see Summary) |
| S05 | Browser launch: `$BROWSER`, Chromium app mode, `xdg-open` | dropped on purpose | | ADR-0006: a native window |
| K01 | `Ctrl+K` and `:` open the palette | ported with deviation | `zombo-ui/src/keys.rs::the_palette_and_sheet_capture_the_keyboard` | `:` is not bound. Plain keys are word keys in the new design |
| K02 | `?` shortcut sheet | ported | `zombo-ui/src/keys.rs::question_mark_opens_the_sheet_unless_typing` | |
| K03 | `,` opens Settings | ported with deviation | `zombo-ui/src/keys.rs::settings_opens_with_ctrl_comma_and_from_the_palette_and_escape_closes_it` | `Ctrl+,` (DESIGN.md "Keyboard") |
| K04 | `/` add a Target | replaced | `zombo-ui/src/keys.rs::the_documented_shortcuts_map_to_their_actions` | `Ctrl+L` focuses the omnibox |
| K05 | `n` new Case, `h` find a Case, `s` go to suggestions, `e` edit notes, `w` preview Write-up, resolve and reopen | dropped on purpose | | Casework, Suggestions and Write-up are gone: C22, C28, C30, C31 |
| K06 | `r` re-run | ported | see C24 | `Ctrl+R` |
| K07 | `x` cancel a Step | MISSING | | See C23 |
| K08 | `c`, `C` copy the Write-up | replaced | `zombo-ui/src/keys.rs::copy_as_json_has_a_key_and_a_palette_entry` | `Ctrl+Shift+C`, `Ctrl+Alt+C`, `Ctrl+Shift+J` |
| K09 | `v` paste Evidence | replaced | `zombo-ui/src/keys.rs::the_evidence_shortcuts_are_bound_shown_and_do_not_clash` | `Ctrl+Shift+H`, `Ctrl+Shift+M` |
| K10 | `j` and `k` move through a list | MISSING | | DESIGN.md "Keyboard" promises `J`, `K` or arrows for findings and rows. Only the palette and the recent list take arrows (`zombo-ui/src/app.rs`, `Action::MoveUp`). N9 |
| D01 | `$XDG_DATA_HOME/stackwell/stackwell.db`: Cases, Targets, Steps with results, Evidence text, notes, dismissed suggestions, playbook runs, settings, secret names | dropped on purpose | | DESIGN.md "Nothing stored" and ADR-0004. Rust never reads it: see "Migration" |
| D02 | `$XDG_CONFIG_HOME/stackwell/secrets.json` or the keyring service `stackwell` | dropped on purpose | | See C33 |
| D03 | `update_check` row in the database: the last release answer, kept across restarts | replaced | `zombo-ui/src/update_model.rs::the_state_is_a_private_file_that_round_trips_and_a_broken_one_is_empty` | `$XDG_STATE_HOME/zombo-razor/update.toml` |
| D04 | `$XDG_RUNTIME_DIR/stackwell.lock` and `.sock` | dropped on purpose | | See C35 |
| D05 | Recent targets | replaced | see C29 | `$XDG_STATE_HOME/zombo-razor/recent.toml` |

## Finding codes

`scripts/parity_findings.py` finds the codes. The block below is generated. Do not edit it by hand.

Reading the table:

- 96 shared codes are ported. Severity words and the literal wording of the title, message and recommendation match, or the code is one of the 10 `DIFF` entries (12 fields), all read by hand and found harmless: `blacklist_unknown` (the Go severity is a variable, Rust has the same two values), `dmarc_enforced` (Go has one site, Rust has two, same words), `dns_cname_at_apex` (a map key in the Go expression counted as a word), `mail_log_bounced`, `mail_log_deferred` and `mail_log_rejected` (Go calls `orUnknown` and `orDefault`, Rust spells the same default text), `registration_expiring_soon` and `ssl_inspection_valid` (day plural and a date layout), `spf_missing_provider` and `website_inspection_missing_headers` (the title and recommendation come from a table or a count in Rust).
- `ssl_inspection_old_protocol` is ported with deviation (C12) and is the only Go code with no test that names it.
- `check_failed` is replaced by the Failed state (C27).
- The six Rust codes that no test body names are listed at the end of the block. Five are new in Rust.

<!-- BEGIN GENERATED findings -->
Go: 102 Finding sites, 98 codes. Rust: 200 sites, 191 codes. In both: 97. Go only: 1. Rust only: 94.

#### Go codes absent from Rust

- `check_failed` (findings.go:37)

#### Every Go code against Rust

Sev is the severity word at the Go site and at the Rust site. The three wording columns say `same` when a Go site and a Rust site have the same literal words (order, values, punctuation and case ignored) and `DIFF` otherwise. Tests are the first two test functions whose body names the code.

| Go code | Sev Go | Sev Rust | Title | Message | Rec | Tests naming the code |
|---|---|---|---|---|---|---|
| `blacklist_clean` | ok | ok | same | same | same | `zombo-core/tests/blacklist.rs::reports_a_listing_with_its_reason_and_delist_link`, `zombo-core/tests/blacklist.rs::a_refused_query_is_neither_listed_nor_clean` (+5) |
| `blacklist_ipv6` | info | info | same | same | same | `zombo-core/tests/blacklist.rs::skips_ipv6_without_calling_it_clean` |
| `blacklist_listed` | dynamic | dynamic | same | same | same | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/blacklist.rs::reports_a_listing_with_its_reason_and_delist_link` (+11) |
| `blacklist_no_addresses` | warning | warning | same | same | same | `zombo-core/tests/blacklist.rs::warns_when_a_domain_has_no_addresses`, `zombo-core/tests/blacklist.rs::does_not_check_the_website_of_a_domain_that_takes_no_mail` |
| `blacklist_refused` | info | info | same | same | same | `zombo-core/tests/blacklist.rs::a_refused_query_is_neither_listed_nor_clean` |
| `blacklist_unknown` | dynamic | info/warning | same | same | same | `zombo-core/tests/blacklist.rs::timeouts_are_unknown_not_clean`, `zombo-core/tests/blacklist.rs::one_silent_blocklist_does_not_delay_the_others` (+1) |
| `check_failed` | warning | absent | - | - | - | - |
| `dkim_found` | ok | ok | same | same | same | `zombo-core/tests/email_findings.rs::a_healthy_domain_has_only_ok_findings`, `zombo-core/tests/email_findings.rs::dkim_key_strength_findings_are_one_per_code` (+1) |
| `dkim_invalid_key` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::dkim_key_strength_findings_are_one_per_code` |
| `dkim_missing` | warning | warning | same | same | same | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-ui/src/finding_owner.rs::a_finding_has_no_button_in_the_section_that_owns_it` (+4) |
| `dkim_revoked` | info | info | same | same | same | `zombo-core/tests/email_findings.rs::dkim_key_strength_findings_are_one_per_code`, `zombo-core/tests/email_findings.rs::a_revoked_key_alone_is_a_missing_key` |
| `dkim_short_key` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::dkim_key_strength_findings_are_one_per_code` |
| `dkim_weak_key` | critical | critical | same | same | same | `zombo-core/tests/email_findings.rs::dkim_key_strength_findings_are_one_per_code` |
| `dmarc_enforced` | ok | ok | DIFF | DIFF | same | `zombo-core/tests/email_findings.rs::a_healthy_domain_has_only_ok_findings`, `zombo-core/tests/email_findings.rs::dmarc_policies_and_their_titles` |
| `dmarc_invalid_policy` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::dmarc_policies_and_their_titles` |
| `dmarc_lookup_failed` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::a_dead_resolver_gives_lookup_failed_findings_not_missing_ones` |
| `dmarc_missing` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::a_domain_with_no_mail_records_is_told_so`, `zombo-core/tests/email_findings.rs::a_dead_resolver_gives_lookup_failed_findings_not_missing_ones` |
| `dmarc_multiple` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::two_dmarc_records_are_ignored_by_receivers` |
| `dmarc_no_rua` | info | info | same | same | same | `zombo-core/tests/email_findings.rs::dmarc_monitoring_only_is_a_warning_with_two_notes`, `zombo-core/tests/email_findings.rs::dmarc_policies_and_their_titles` |
| `dmarc_partial` | info | info | same | same | same | `zombo-core/tests/email_findings.rs::dmarc_monitoring_only_is_a_warning_with_two_notes`, `zombo-core/tests/email_findings.rs::dmarc_policies_and_their_titles` |
| `dmarc_policy_none` | warning | warning | same | same | same | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/email_findings.rs::dmarc_monitoring_only_is_a_warning_with_two_notes` (+1) |
| `dns_cname_at_apex` | critical | critical | same | DIFF | same | `zombo-core/tests/lookup_findings.rs::a_cname_at_the_apex_is_critical`, `zombo-core/tests/lookup_findings.rs::a_hostname_is_not_held_to_the_apex_rules` |
| `dns_mx` | ok | ok | same | same | same | `zombo-ui/src/record_findings.rs::the_authoritative_answer_is_read_even_when_resolvers_say_otherwise`, `zombo-core/tests/lookup_findings.rs::a_healthy_domain_resolves_and_has_mail_exchangers` (+1) |
| `dns_no_address` | warning | warning | same | same | same | `zombo-ui/src/record_findings.rs::a_type_that_failed_is_reported_as_a_failed_lookup_not_as_missing`, `zombo-core/tests/lookup_findings.rs::a_domain_with_no_address_records` (+2) |
| `dns_no_mx` | warning | warning | same | same | same | `zombo-ui/src/record_findings.rs::a_hostname_gets_no_apex_rules_and_a_domain_does`, `zombo-core/tests/lookup_findings.rs::a_domain_with_no_mx` (+2) |
| `dns_no_ns` | critical | critical | same | same | same | `zombo-ui/src/record_findings.rs::a_hostname_gets_no_apex_rules_and_a_domain_does`, `zombo-core/tests/lookup_findings.rs::a_domain_with_no_ns` (+2) |
| `dns_null_mx` | info | info | same | same | same | `zombo-core/tests/lookup_findings.rs::a_null_mx_declares_no_mail`, `zombo-core/tests/lookup_findings.rs::a_hostname_is_not_held_to_the_apex_rules` |
| `dns_nxdomain` | critical | critical | same | same | same | `zombo-ui/src/record_findings.rs::nxdomain_is_said_once`, `zombo-core/tests/lookup_findings.rs::nxdomain_is_critical_and_the_only_finding` |
| `dns_propagation_addresses_vary` | info | info | same | same | same | `zombo-core/tests/propagation.rs::differing_addresses_are_info_not_a_warning` |
| `dns_propagation_consistent` | ok | ok | same | same | same | `zombo-core/tests/authoritative.rs::resolvers_that_all_serve_old_records_are_cached_not_propagated`, `zombo-core/tests/authoritative.rs::nameservers_that_all_answer_like_a_forwarder_mean_the_network_intercepts_dns` (+3) |
| `dns_propagation_insufficient` | warning | warning | same | same | same | `zombo-core/tests/propagation.rs::too_few_answers_cannot_be_called_propagated` |
| `dns_propagation_mismatch` | warning | warning | same | same | same | `zombo-core/tests/propagation.rs::flags_resolvers_that_disagree`, `zombo-core/tests/propagation.rs::differing_addresses_are_info_not_a_warning` (+2) |
| `dns_propagation_nxdomain` | warning | warning | same | same | same | `zombo-ui/src/record_findings.rs::nxdomain_is_said_once`, `zombo-core/tests/propagation.rs::a_name_that_exists_nowhere_is_not_propagated` |
| `dns_propagation_unreachable` | info | info | same | same | same | `zombo-core/tests/propagation.rs::flags_resolvers_that_disagree` |
| `dns_query_errors` | info | info | same | same | same | `zombo-ui/src/record_findings.rs::a_type_that_failed_is_reported_as_a_failed_lookup_not_as_missing`, `zombo-core/tests/lookup_findings.rs::a_failed_query_is_not_reported_as_a_missing_record` |
| `dns_resolves` | ok | ok | same | same | same | `zombo-ui/src/record_findings.rs::a_hostname_gets_no_apex_rules_and_a_domain_does`, `zombo-core/tests/lookup_findings.rs::a_healthy_domain_resolves_and_has_mail_exchangers` |
| `email_headers_authenticated` | ok | ok | same | same | same | `zombo-core/tests/evidence_headers.rs::pasted_headers_are_analysed` |
| `email_headers_delayed` | warning | warning | same | same | same | `zombo-core/tests/evidence_headers.rs::a_long_delay_between_hops_is_flagged` |
| `email_headers_dkim_fail` | warning | warning | same | same | same | `zombo-core/tests/evidence_headers.rs::spoofed_headers_are_called_out` |
| `email_headers_dmarc_fail` | critical | critical | same | same | same | `zombo-core/tests/evidence_headers.rs::spoofed_headers_are_called_out` |
| `email_headers_dmarc_none` | info | info | same | same | same | `zombo-core/tests/evidence_headers.rs::unknown_verdict_words_are_kept` |
| `email_headers_misaligned` | warning | warning | same | same | same | `zombo-core/tests/evidence_headers.rs::spoofed_headers_are_called_out`, `zombo-core/tests/evidence_headers.rs::a_failed_dkim_signature_does_not_count_as_aligned` (+1) |
| `email_headers_no_auth_results` | info | info | same | same | same | `zombo-core/tests/evidence_headers.rs::minimal_headers_have_no_authentication_verdict` |
| `email_headers_spam` | warning | warning | same | same | same | `zombo-core/tests/evidence_headers.rs::relaxed_alignment_and_a_spam_score` |
| `email_headers_spf_fail` | critical | critical/warning | same | same | same | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/evidence_headers.rs::spoofed_headers_are_called_out` (+1) |
| `hosting_reachability_database_exposed` | warning | warning | same | same | same | `zombo-core/tests/ports.rs::the_full_table_has_the_hosting_ports`, `zombo-core/tests/ports.rs::web_mail_and_database_findings` |
| `hosting_reachability_no_address` | critical | critical | same | same | same | `zombo-core/tests/ports.rs::no_address_is_critical` |
| `hosting_reachability_no_https` | warning | warning | same | same | same | `zombo-core/tests/ports.rs::web_mail_and_database_findings` |
| `hosting_reachability_reachable` | ok | ok | same | same | same | `zombo-core/tests/ports.rs::the_quick_sweep_classifies_each_port`, `zombo-core/tests/ports.rs::web_mail_and_database_findings` (+1) |
| `hosting_reachability_smtp_closed` | info | info | same | same | same | `zombo-core/tests/ports.rs::web_mail_and_database_findings` |
| `hosting_reachability_unreachable` | critical | critical | same | same | same | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/ports.rs::an_unroutable_address_is_no_route_not_filtered` (+3) |
| `hosting_reachability_web_closed` | warning | warning | same | same | same | `zombo-core/tests/ports.rs::web_mail_and_database_findings`, `zombo-core/tests/ports.rs::each_address_is_judged_on_its_own` |
| `mail_log_bounced` | dynamic | dynamic | same | DIFF | same | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/evidence_maillog.rs::findings_for_every_kind_of_outcome` (+1) |
| `mail_log_deferred` | info | info | same | DIFF | same | `zombo-core/tests/evidence_maillog.rs::findings_for_every_kind_of_outcome` |
| `mail_log_delivered` | ok | ok | same | same | same | `zombo-core/tests/evidence_maillog.rs::findings_for_every_kind_of_outcome` |
| `mail_log_incomplete` | info | info | same | same | same | `zombo-core/tests/evidence_maillog.rs::an_incomplete_message_has_its_own_finding` |
| `mail_log_more` | info | info | same | same | same | `zombo-core/tests/evidence_maillog.rs::a_large_log_does_not_flood_the_findings` |
| `mail_log_rejected` | warning | warning | same | DIFF | same | `zombo-core/tests/evidence_maillog.rs::findings_for_every_kind_of_outcome` |
| `registration_expired` | critical | critical | same | same | same | `zombo-core/tests/registration.rs::findings_by_expiry_and_status`, `zombo-core/tests/registration.rs::an_rdap_server_error_or_garbage_is_an_error_not_a_panic` (+2) |
| `registration_expiring` | info | info | same | same | same | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/registration.rs::findings_by_expiry_and_status` (+1) |
| `registration_expiring_soon` | warning | warning | same | DIFF | same | `zombo-core/tests/registration.rs::findings_by_expiry_and_status`, `zombo-core/tests/registration.rs::the_finding_wording_is_the_go_wording` (+2) |
| `registration_not_registered` | critical | critical | same | same | same | `zombo-core/tests/registration.rs::not_registered_says_where_it_found_out`, `zombo-core/tests/registration.rs::an_rdap_404_means_not_registered` (+4) |
| `registration_ok` | ok | ok | same | same | same | `zombo-core/tests/registration.rs::findings_by_expiry_and_status`, `zombo-core/tests/registration.rs::a_healthy_domain_gets_one_ok_finding_naming_registrar_and_expiry` (+4) |
| `registration_on_hold` | critical | critical | same | same | same | `zombo-core/tests/registration.rs::findings_by_expiry_and_status`, `zombo-core/tests/registration.rs::the_finding_wording_is_the_go_wording` (+3) |
| `registration_pending_delete` | critical | critical | same | same | same | `zombo-core/tests/registration.rs::findings_by_expiry_and_status`, `zombo-core/tests/registration.rs::an_rdap_server_error_or_garbage_is_an_error_not_a_panic` (+1) |
| `spf_fail_all` | ok | ok | same | same | same | `zombo-core/tests/email_findings.rs::a_healthy_domain_has_only_ok_findings`, `zombo-core/tests/email_findings.rs::thirteen_lookups_are_too_many` (+1) |
| `spf_lookup_failed` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::failed_lookups_inside_the_tree_are_listed`, `zombo-core/tests/email_findings.rs::a_dead_resolver_gives_lookup_failed_findings_not_missing_ones` |
| `spf_missing` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::a_domain_with_no_mail_records_is_told_so`, `zombo-core/tests/email_findings.rs::a_dead_resolver_gives_lookup_failed_findings_not_missing_ones` |
| `spf_missing_provider` | warning | warning | DIFF | same | DIFF | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/email_findings.rs::spf_missing_the_mail_provider_is_flagged` (+3) |
| `spf_multiple` | critical | critical | same | same | same | `zombo-core/tests/email_findings.rs::two_spf_records_are_critical_and_nothing_else_is_said_about_spf` |
| `spf_neutral_all` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::each_all_qualifier_has_its_finding` |
| `spf_no_all` | warning | warning | same | same | same | `zombo-core/tests/email_findings.rs::each_all_qualifier_has_its_finding`, `zombo-core/tests/email_findings.rs::an_unresolved_redirect_is_not_a_missing_all` |
| `spf_pass_all` | critical | critical | same | same | same | `zombo-core/tests/email_findings.rs::each_all_qualifier_has_its_finding` |
| `spf_permerror` | critical | critical | same | same | same | `zombo-core/tests/email_findings.rs::thirteen_lookups_are_too_many`, `zombo-core/tests/email_findings.rs::syntax_and_include_errors_are_a_permerror` (+2) |
| `spf_softfail_all` | info | info | same | same | same | `zombo-core/tests/email_findings.rs::syntax_and_include_errors_are_a_permerror`, `zombo-core/tests/email_findings.rs::each_all_qualifier_has_its_finding` |
| `spf_too_many_lookups` | critical | critical | same | same | same | `zombo-core/tests/email_findings.rs::thirteen_lookups_are_too_many`, `zombo-core/tests/email_findings.rs::ten_lookups_are_still_fine` (+1) |
| `ssl_inspection_expired` | critical | critical | same | same | same | `zombo-ui/src/finding_owner.rs::the_tls_prefixes_belong_to_the_automatic_section_not_the_on_demand_one`, `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section` (+3) |
| `ssl_inspection_expiring` | warning | warning | same | same | same | `zombo-core/tests/tls.rs::expiry_warnings_follow_the_go_thresholds`, `zombo-core/tests/tls.rs::the_soonest_expiry_in_the_chain_is_reported_by_name` |
| `ssl_inspection_expiring_soon` | info | info | same | same | same | `zombo-core/tests/tls.rs::expiry_warnings_follow_the_go_thresholds` |
| `ssl_inspection_hostname_mismatch` | critical | critical | same | same | same | `zombo-core/tests/smtp.rs::certificate_problems_use_the_tls_findings`, `zombo-core/tests/tls.rs::a_wrong_host_is_critical_and_not_valid` |
| `ssl_inspection_incomplete_chain` | critical | critical | same | same | same | `zombo-core/tests/check_tls.rs::the_automatic_check_gives_handshake_rows_then_caa_rows_and_findings_worst_first`, `zombo-core/tests/tls.rs::a_missing_intermediate_is_an_incomplete_chain` |
| `ssl_inspection_old_protocol` | warning | warning | same | same | same | NONE |
| `ssl_inspection_self_signed` | critical | critical | same | same | same | `zombo-core/tests/tls.rs::a_self_signed_certificate_is_not_also_untrusted` |
| `ssl_inspection_untrusted` | critical | critical | same | same | same | `zombo-core/tests/tls.rs::a_complete_chain_under_an_unknown_root_is_untrusted`, `zombo-core/tests/tls.rs::a_chain_that_fails_verification_otherwise_is_invalid` |
| `ssl_inspection_valid` | ok | ok | same | DIFF | same | `zombo-core/tests/smtp.rs::the_whole_dialogue_is_read_and_never_sends_mail`, `zombo-core/tests/smtp.rs::implicit_tls_reads_the_greeting_inside_the_tunnel` (+2) |
| `website_inspection_client_error` | warning | warning | same | same | same | `zombo-core/tests/web.rs::server_and_client_errors` |
| `website_inspection_healthy` | ok | ok | same | same | same | `zombo-core/tests/web.rs::healthy_site_with_every_header`, `zombo-core/tests/web.rs::records_the_redirect_chain_with_relative_locations` (+5) |
| `website_inspection_https_failed` | warning | warning | same | same | same | `zombo-core/tests/web.rs::healthy_site_with_every_header`, `zombo-core/tests/web.rs::falls_back_to_http_when_https_fails` |
| `website_inspection_https_not_enforced` | warning | warning | same | same | same | `zombo-core/tests/web.rs::plain_http_that_never_reaches_https_is_flagged` |
| `website_inspection_missing_headers` | info | info | DIFF | same | same | `zombo-core/tests/web.rs::stops_after_ten_redirects`, `zombo-core/tests/web.rs::missing_headers_with_frame_ancestors_standing_in_for_x_frame_options` |
| `website_inspection_missing_hsts` | warning | warning | same | same | same | `zombo-core/tests/web.rs::falls_back_to_http_when_https_fails`, `zombo-core/tests/web.rs::https_site_without_hsts_is_warned_and_one_with_every_header_is_only_healthy` |
| `website_inspection_redirect_loop` | critical | critical | same | same | same | `zombo-core/tests/web.rs::detects_a_redirect_loop` |
| `website_inspection_server_error` | critical | critical | same | same | same | `zombo-core/tests/web.rs::server_and_client_errors`, `zombo-core/tests/web.rs::detects_wordpress_and_its_failure_pages` |
| `website_inspection_slow` | info | info | same | same | same | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/web.rs::slow_response_is_flagged` |
| `website_inspection_too_many_redirects` | warning | warning | same | same | same | `zombo-core/tests/web.rs::stops_after_ten_redirects` |
| `website_inspection_unreachable` | critical | critical | same | same | same | `zombo-core/tests/web.rs::scheme_relative_location_keeps_the_scheme`, `zombo-core/tests/web.rs::never_follows_a_redirect_to_another_scheme` (+3) |
| `website_inspection_wp_critical_error` | critical | critical | same | same | same | `zombo-core/tests/web.rs::detects_wordpress_and_its_failure_pages` |
| `website_inspection_wp_maintenance` | warning | warning | same | same | same | `zombo-core/tests/web.rs::detects_wordpress_and_its_failure_pages` |

10 shared codes have at least one DIFF: `blacklist_unknown`, `dmarc_enforced`, `dns_cname_at_apex`, `mail_log_bounced`, `mail_log_deferred`, `mail_log_rejected`, `registration_expiring_soon`, `spf_missing_provider`, `ssl_inspection_valid`, `website_inspection_missing_headers`.

#### Rust-only codes

| Code | Source | Severity | Tests naming the code |
|---|---|---|---|
| `caa_forbids_all` | crates/zombo-core/src/tls_extras.rs:213 | warning | `zombo-core/tests/tls_extras.rs::issuewild_is_noted_and_judges_wildcard_certificates`, `zombo-core/tests/tls_extras.rs::records_that_do_not_restrict_issuance_say_so` |
| `caa_forbids_issuer` | crates/zombo-core/src/tls_extras.rs:225 | critical | `zombo-core/tests/check_tls.rs::the_automatic_check_gives_handshake_rows_then_caa_rows_and_findings_worst_first`, `zombo-core/tests/tls_extras.rs::a_ca_the_records_forbid_is_critical` (+1) |
| `caa_issuer_unknown` | crates/zombo-core/src/tls_extras.rs:235 | info | `zombo-core/tests/tls_extras.rs::an_allowed_or_unmapped_issuer_is_not_critical` |
| `caa_issuewild` | crates/zombo-core/src/tls_extras.rs:252 | info | `zombo-core/tests/tls_extras.rs::issuewild_is_noted_and_judges_wildcard_certificates` |
| `caa_lookup_failed` | crates/zombo-core/src/tls_extras.rs:174 | warning | `zombo-core/src/tls.rs::a_caa_lookup_that_failed_says_so_and_is_a_warning`, `zombo-core/tests/tls_extras.rs::a_failed_question_is_not_read_as_no_caa` |
| `caa_no_issue` | crates/zombo-core/src/tls_extras.rs:206 | info | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-ui/src/finding_owner.rs::a_certificate_finding_in_the_tls_port_pane_does_not_send_the_rep_to_the_other_tls_section` (+1) |
| `caa_none` | crates/zombo-core/src/tls_extras.rs:183 | info | `zombo-core/src/tls.rs::no_caa_record_is_stated_and_flagged_not_left_blank`, `zombo-ui/src/finding_owner.rs::the_tls_prefixes_belong_to_the_automatic_section_not_the_on_demand_one` (+1) |
| `caa_ok` | crates/zombo-core/src/tls_extras.rs:241 | ok | `zombo-core/src/tls.rs::caa_records_join_the_tls_rows_and_its_findings_join_the_tls_findings`, `zombo-core/tests/tls_extras.rs::an_allowed_or_unmapped_issuer_is_not_critical` (+1) |
| `dns_authoritative_behind` | crates/zombo-core/src/propagation.rs:514 | warning | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/authoritative.rs::a_nameserver_on_an_older_serial_is_behind_not_broken` (+2) |
| `dns_authoritative_consistent` | crates/zombo-core/src/propagation.rs:695 | ok | `zombo-core/tests/authoritative.rs::everything_matching_the_nameservers_says_so` |
| `dns_authoritative_mismatch` | crates/zombo-core/src/propagation.rs:532 | critical | `zombo-core/tests/authoritative.rs::resolvers_serving_old_records_are_called_cached_not_broken`, `zombo-core/tests/authoritative.rs::a_nameserver_on_an_older_serial_is_behind_not_broken` (+2) |
| `dns_authoritative_not_authoritative` | crates/zombo-core/src/propagation.rs:677 | warning | `zombo-core/tests/authoritative.rs::an_answer_without_the_authoritative_flag_is_not_trusted`, `zombo-core/tests/authoritative.rs::nameservers_that_all_answer_like_a_forwarder_mean_the_network_intercepts_dns` (+1) |
| `dns_authoritative_unreachable` | crates/zombo-core/src/propagation.rs:660 | warning | `zombo-core/tests/authoritative.rs::a_nameserver_that_does_not_answer_is_reported` |
| `dns_delegation_lame` | crates/zombo-core/src/delegation.rs:302 | critical | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/delegation.rs::a_server_that_answers_but_does_not_serve_the_zone_is_lame` (+3) |
| `dns_delegation_mismatch` | crates/zombo-core/src/delegation.rs:330 | warning | `zombo-core/tests/delegation.rs::parent_and_zone_disagreeing_about_nameservers_is_reported_both_ways`, `zombo-core/tests/delegation.rs::finds_a_zone_that_lists_a_nameserver_the_parent_does_not` |
| `dns_delegation_ok` | crates/zombo-core/src/delegation.rs:411 | ok | `zombo-core/tests/delegation.rs::a_healthy_delegation_says_so`, `zombo-core/tests/delegation.rs::a_single_nameserver_is_a_warning` (+3) |
| `dns_delegation_single_ns` | crates/zombo-core/src/delegation.rs:259 | warning | `zombo-core/tests/delegation.rs::a_single_nameserver_is_a_warning` |
| `dns_delegation_unreachable` | crates/zombo-core/src/delegation.rs:275 | warning | `zombo-core/tests/delegation.rs::a_server_that_does_not_answer_is_unreachable`, `zombo-core/tests/delegation.rs::a_silent_server_is_unreachable` |
| `dns_glue_mismatch` | crates/zombo-core/src/delegation.rs:382 | critical | `zombo-core/tests/delegation.rs::glue_that_differs_from_the_zone_is_critical`, `zombo-core/tests/delegation.rs::finds_glue_that_differs_from_what_the_zone_serves` |
| `dns_glue_missing` | crates/zombo-core/src/delegation.rs:365 | critical | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/delegation.rs::an_in_zone_nameserver_without_glue_is_critical` (+1) |
| `dns_network_intercepts` | crates/zombo-core/src/dns.rs:123 | warning | `zombo-ui/src/diagnosis.rs::the_summary_lists_a_finding_that_several_checks_share_once`, `zombo-ui/src/diagnosis.rs::a_network_wide_finding_with_different_wording_is_listed_once_and_counted_once` (+5) |
| `dns_ns_is_cname` | crates/zombo-core/src/delegation.rs:402 | critical | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/delegation.rs::a_nameserver_that_is_a_cname_is_critical` |
| `dns_ns_unresolvable` | crates/zombo-core/src/delegation.rs:392 | critical | `zombo-core/tests/delegation.rs::an_unresolvable_nameserver_name_is_critical` |
| `dns_propagation_stale_cache` | crates/zombo-core/src/propagation.rs:717 | info | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/authoritative.rs::resolvers_serving_old_records_are_called_cached_not_broken` (+1) |
| `dnssec_algorithm_deprecated` | crates/zombo-core/src/dnssec.rs:663 | warning | `zombo-core/tests/dnssec.rs::a_deprecated_algorithm_is_a_warning_naming_it` |
| `dnssec_bogus` | crates/zombo-core/src/dnssec.rs:593 | critical | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/dnssec.rs::a_resolver_that_rejects_the_domain_is_named_and_the_domain_is_called_unreachable` (+2) |
| `dnssec_ds_mismatch` | crates/zombo-core/src/dnssec.rs:625 | critical | `zombo-core/tests/check_dnssec.rs::a_ds_that_matches_no_key_is_reported_as_unmatched`, `zombo-core/tests/dnssec.rs::a_ds_that_matches_no_key_is_a_mismatch_and_the_likely_cause_of_the_bogus_verdict` (+1) |
| `dnssec_ds_missing` | crates/zombo-core/src/dnssec.rs:693 | info | `zombo-core/tests/dnssec.rs::keys_with_no_ds_are_signed_but_not_linked` |
| `dnssec_ds_without_dnskey` | crates/zombo-core/src/dnssec.rs:606 | critical | `zombo-core/tests/dnssec.rs::a_ds_that_matches_no_key_is_a_mismatch_and_the_likely_cause_of_the_bogus_verdict`, `zombo-core/tests/dnssec.rs::a_ds_at_the_parent_with_no_dnskey_in_the_zone_is_called_out` |
| `dnssec_nameservers_disagree` | crates/zombo-core/src/dnssec.rs:680 | warning | `zombo-core/tests/dnssec.rs::nameservers_serving_different_keys_are_a_warning_listing_each` |
| `dnssec_not_signed` | crates/zombo-core/src/dnssec.rs:701 | info | `zombo-core/tests/dnssec.rs::no_ds_and_no_dnskey_is_just_unsigned` |
| `dnssec_secure` | crates/zombo-core/src/dnssec.rs:715 | ok | `zombo-core/tests/check_dnssec.rs::a_healthy_signed_zone_gives_zone_resolver_ds_and_key_rows`, `zombo-core/tests/dnssec.rs::healthy_dnssec_says_so_and_nothing_else` (+6) |
| `dnssec_signature_expired` | crates/zombo-core/src/dnssec.rs:638 | critical | `zombo-core/tests/dnssec.rs::a_signature_past_its_expiration_is_critical`, `zombo-core/tests/dnssec.rs::a_signature_about_to_expire_is_a_warning` |
| `dnssec_signature_expiring` | crates/zombo-core/src/dnssec.rs:647 | warning | `zombo-core/tests/dnssec.rs::a_signature_about_to_expire_is_a_warning`, `zombo-core/tests/dnssec.rs::under_three_days_left_on_a_long_signature_is_a_warning` |
| `email_bimi_invalid` | crates/zombo-core/src/email_auth/findings.rs:440 | warning | `zombo-core/tests/email_records.rs::bimi_needs_an_https_logo` |
| `email_bimi_lookup_failed` | crates/zombo-core/src/email_auth/findings.rs:431 | warning | `zombo-core/tests/email_records.rs::a_failed_lookup_is_a_warning_not_a_missing_record` |
| `email_bimi_missing` | crates/zombo-core/src/email_auth/findings.rs:449 | info | `zombo-core/tests/email_records.rs::absent_records_are_info_not_a_problem`, `zombo-core/tests/email_records.rs::a_record_with_another_version_or_a_stray_txt_is_not_one_of_them` |
| `email_bimi_multiple` | crates/zombo-core/src/email_auth/findings.rs:480 | warning | `zombo-core/tests/email_records.rs::two_records_are_a_warning_for_each_kind` |
| `email_bimi_ok` | crates/zombo-core/src/email_auth/findings.rs:461 | ok | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/email_records.rs::published_records_are_ok_and_say_where_reports_go` (+2) |
| `email_headers_clock_skew` | crates/zombo-core/src/evidence/headers.rs:719 | info | `zombo-core/tests/evidence_headers.rs::hops_dated_backwards_are_an_anomaly` |
| `email_headers_multiple_from` | crates/zombo-core/src/evidence/headers.rs:710 | warning | `zombo-core/tests/evidence_headers.rs::two_from_headers_are_an_anomaly` |
| `email_headers_too_many_hops` | crates/zombo-core/src/evidence/headers.rs:729 | info | NONE |
| `email_headers_truncated` | crates/zombo-core/src/evidence/headers.rs:738 | info | `zombo-core/tests/evidence_headers.rs::a_megabyte_single_line_is_bounded` |
| `email_mtasts_invalid` | crates/zombo-core/src/email_auth/findings.rs:524 | warning | `zombo-core/tests/email_records.rs::an_mta_sts_id_is_one_to_thirty_two_letters_and_digits` |
| `email_mtasts_lookup_failed` | crates/zombo-core/src/email_auth/findings.rs:494 | warning | `zombo-core/tests/email_records.rs::a_failed_lookup_is_a_warning_not_a_missing_record` |
| `email_mtasts_missing` | crates/zombo-core/src/email_auth/findings.rs:504 | info | `zombo-core/tests/email_records.rs::absent_records_are_info_not_a_problem`, `zombo-core/tests/email_records.rs::a_record_with_another_version_or_a_stray_txt_is_not_one_of_them` |
| `email_mtasts_multiple` | crates/zombo-core/src/email_auth/findings.rs:535 | warning | `zombo-core/tests/email_records.rs::two_records_are_a_warning_for_each_kind` |
| `email_mtasts_ok` | crates/zombo-core/src/email_auth/findings.rs:515 | ok | `zombo-core/tests/email_records.rs::published_records_are_ok_and_say_where_reports_go`, `zombo-core/tests/email_records.rs::an_mta_sts_id_is_one_to_thirty_two_letters_and_digits` |
| `email_tlsrpt_invalid` | crates/zombo-core/src/email_auth/findings.rs:401 | warning | `zombo-core/tests/email_records.rs::a_tls_rpt_record_must_have_a_mailto_or_https_address` |
| `email_tlsrpt_lookup_failed` | crates/zombo-core/src/email_auth/findings.rs:381 | warning | `zombo-core/tests/email_records.rs::a_failed_lookup_is_a_warning_not_a_missing_record` |
| `email_tlsrpt_missing` | crates/zombo-core/src/email_auth/findings.rs:392 | info | `zombo-core/tests/email_records.rs::absent_records_are_info_not_a_problem`, `zombo-core/tests/email_records.rs::a_record_with_another_version_or_a_stray_txt_is_not_one_of_them` |
| `email_tlsrpt_multiple` | crates/zombo-core/src/email_auth/findings.rs:417 | warning | `zombo-core/tests/email_records.rs::two_records_are_a_warning_for_each_kind` |
| `email_tlsrpt_ok` | crates/zombo-core/src/email_auth/findings.rs:410 | ok | `zombo-core/tests/email_records.rs::published_records_are_ok_and_say_where_reports_go`, `zombo-core/tests/email_records.rs::a_tls_rpt_record_must_have_a_mailto_or_https_address` |
| `hosting_reachability_mail_filtered` | crates/zombo-core/src/ports.rs:307 | info | `zombo-ui/src/checks.rs::a_silent_mail_port_reads_as_no_answer_and_not_as_down`, `zombo-core/tests/ports.rs::only_mail_ports_with_no_answer_blames_the_probing_network_not_the_server` |
| `mail_log_truncated` | crates/zombo-core/src/evidence/maillog.rs:709 | info | `zombo-core/tests/evidence_maillog.rs::a_megabyte_single_line_is_bounded` |
| `rdns_addresses` | crates/zombo-core/src/rdns.rs:213 | info | `zombo-core/tests/check_rdns.rs::a_host_name_target_lists_its_addresses`, `zombo-core/tests/rdns.rs::a_host_reports_each_address` |
| `rdns_confirmed` | crates/zombo-core/src/rdns.rs:298 | ok | `zombo-core/tests/check_rdns.rs::an_address_with_a_confirmed_ptr_gives_the_address_ptr_and_forward_rows`, `zombo-core/tests/rdns.rs::a_ptr_that_resolves_back_is_confirmed` (+4) |
| `rdns_forward_unknown` | crates/zombo-core/src/rdns.rs:259 | info | `zombo-core/tests/rdns.rs::a_silent_forward_lookup_is_unknown_not_a_failure` |
| `rdns_generic_name` | crates/zombo-core/src/rdns.rs:287 | info | `zombo-core/tests/rdns.rs::a_name_that_embeds_the_address_looks_generated` |
| `rdns_lookup_failed` | crates/zombo-core/src/rdns.rs:196 | warning | `zombo-core/tests/check_rdns.rs::a_resolver_that_never_answers_is_a_finding_not_an_error_after_one_query_timeout`, `zombo-core/tests/rdns.rs::a_silent_resolver_is_a_failed_lookup_not_a_missing_ptr` (+1) |
| `rdns_multiple_ptr` | crates/zombo-core/src/rdns.rs:248 | info | `zombo-core/tests/rdns.rs::several_ptrs_are_reported_and_each_is_confirmed`, `zombo-core/tests/rdns.rs::one_bad_name_among_several_denies_confirmation` |
| `rdns_no_address` | crates/zombo-core/src/rdns.rs:204 | warning | `zombo-core/tests/rdns.rs::a_host_with_no_address_is_reported` |
| `rdns_no_ptr` | crates/zombo-core/src/rdns.rs:237 | warning | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-ui/src/finding_owner.rs::a_finding_has_no_button_in_the_section_that_owns_it` (+3) |
| `rdns_not_confirmed` | crates/zombo-core/src/rdns.rs:276 | warning | `zombo-core/tests/rdns.rs::a_ptr_resolving_to_another_address_fails_forward_confirmation`, `zombo-core/tests/rdns.rs::a_ptr_name_with_no_address_fails_forward_confirmation` (+2) |
| `smtp_auth_before_tls` | crates/zombo-core/src/smtp/findings.rs:161 | warning | `zombo-core/tests/smtp.rs::auth_offered_before_tls_is_a_warning` |
| `smtp_banner_name_mismatch` | crates/zombo-core/src/smtp/findings.rs:123 | info | `zombo-core/tests/smtp.rs::the_greeting_name_is_compared_with_the_expected_names` |
| `smtp_banner_rejected` | crates/zombo-core/src/smtp/findings.rs:111 | warning | `zombo-core/tests/smtp.rs::a_greeting_that_is_not_220_stops_the_dialogue` |
| `smtp_connect_failed` | crates/zombo-core/src/smtp/findings.rs:72 | warning | NONE |
| `smtp_no_answer` | crates/zombo-core/src/smtp/findings.rs:45 | info | `zombo-core/tests/smtp.rs::silence_on_a_mail_port_says_no_answer_and_names_the_network` |
| `smtp_no_greeting` | crates/zombo-core/src/smtp/findings.rs:85 | warning | `zombo-core/tests/smtp.rs::a_silent_server_is_reported_as_no_greeting` |
| `smtp_no_route` | crates/zombo-core/src/smtp/findings.rs:63 | info | NONE |
| `smtp_no_starttls` | crates/zombo-core/src/smtp/findings.rs:135 | warning | `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section`, `zombo-core/tests/smtp.rs::a_server_without_starttls_is_flagged_and_quit_politely` |
| `smtp_protocol_error` | crates/zombo-core/src/smtp/findings.rs:99 | warning | `zombo-core/tests/smtp.rs::a_server_that_rejects_ehlo_is_reported` |
| `smtp_refused` | crates/zombo-core/src/smtp/findings.rs:54 | warning | `zombo-core/tests/smtp.rs::a_closed_port_is_refused_not_silent` |
| `smtp_starttls_failed` | crates/zombo-core/src/smtp/findings.rs:142 | warning | `zombo-core/tests/smtp.rs::a_refused_starttls_is_reported_with_its_code`, `zombo-core/tests/smtp.rs::a_failed_handshake_after_starttls_is_reported` |
| `smtp_tls_failed` | crates/zombo-core/src/smtp/findings.rs:92 | critical | NONE |
| `smtp_tls_ok` | crates/zombo-core/src/smtp/findings.rs:177 | ok | `zombo-core/tests/smtp.rs::the_whole_dialogue_is_read_and_never_sends_mail`, `zombo-core/tests/smtp.rs::implicit_tls_reads_the_greeting_inside_the_tunnel` |
| `ssl_inspection_not_yet_valid` | crates/zombo-core/src/tls.rs:562 | critical | `zombo-core/tests/tls.rs::a_certificate_not_yet_valid_gets_its_own_finding` |
| `ssl_inspection_weak_key` | crates/zombo-core/src/tls.rs:633 | warning | `zombo-core/tests/tls.rs::a_weak_key_and_a_sha1_signature_each_get_a_finding` |
| `ssl_inspection_weak_signature` | crates/zombo-core/src/tls.rs:642 | warning | `zombo-core/tests/tls.rs::a_weak_key_and_a_sha1_signature_each_get_a_finding` |
| `tls_no_ocsp_staple` | crates/zombo-core/src/tls_extras.rs:272 | info | `zombo-ui/src/finding_owner.rs::the_tls_prefixes_belong_to_the_automatic_section_not_the_on_demand_one`, `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section` (+3) |
| `tls_ocsp_stapled` | crates/zombo-core/src/tls_extras.rs:262 | ok | `zombo-core/tests/tls_extras.rs::a_server_that_staples_is_detected` |
| `web_origin_cert_not_verified` | crates/zombo-core/src/web/findings.rs:60 | info | `zombo-core/tests/web_tls.rs::insecure_origin_compares_anyway_and_says_what_it_skipped` |
| `web_redirect_downgrade` | crates/zombo-core/src/web/findings.rs:34 | warning | `zombo-core/src/web/mod.rs::the_downgrade_finding_names_both_urls`, `zombo-ui/src/finding_owner.rs::each_family_goes_to_its_section` |
| `website_asn` | crates/zombo-core/src/web/findings.rs:251 | info | `zombo-core/tests/web.rs::provider_findings_name_each_provider_and_the_asn` |
| `website_cdn_detected` | crates/zombo-core/src/web/findings.rs:224 | info | `zombo-core/tests/web.rs::a_healthy_origin_behind_a_failing_cdn_blames_the_cdn`, `zombo-core/tests/web.rs::provider_findings_name_each_provider_and_the_asn` |
| `website_host_detected` | crates/zombo-core/src/web/findings.rs:225 | info | `zombo-core/tests/web.rs::provider_findings_name_each_provider_and_the_asn` |
| `website_origin_cert_rejected` | crates/zombo-core/src/web/origin.rs:96 | warning | `zombo-core/tests/web_tls.rs::a_rejected_origin_certificate_is_not_reported_as_silence`, `zombo-core/tests/web_tls.rs::insecure_origin_compares_anyway_and_says_what_it_skipped` |
| `website_origin_headers_differ` | crates/zombo-core/src/web/origin.rs:178 | info | `zombo-core/tests/web.rs::a_healthy_origin_behind_a_failing_cdn_blames_the_cdn`, `zombo-core/tests/web.rs::an_origin_that_answers_alike_is_ok_and_header_changes_are_info` |
| `website_origin_matches` | crates/zombo-core/src/web/origin.rs:169 | ok | `zombo-core/tests/web.rs::a_healthy_origin_behind_a_failing_cdn_blames_the_cdn`, `zombo-core/tests/web.rs::an_origin_that_answers_alike_is_ok_and_header_changes_are_info` |
| `website_origin_redirect_differs` | crates/zombo-core/src/web/origin.rs:153 | warning | `zombo-core/tests/web.rs::redirects_that_differ_are_reported` |
| `website_origin_status_differs` | crates/zombo-core/src/web/origin.rs:143 | warning | `zombo-core/tests/web.rs::a_healthy_origin_behind_a_failing_cdn_blames_the_cdn`, `zombo-core/tests/web.rs::a_cdn_masking_a_broken_origin_is_called_out` (+1) |
| `website_origin_unreachable` | crates/zombo-core/src/web/origin.rs:109 | warning | `zombo-core/tests/web.rs::an_origin_that_does_not_answer_is_reported_without_blaming`, `zombo-core/tests/web_tls.rs::a_rejected_origin_certificate_is_not_reported_as_silence` |
| `website_provider_dns_failed` | crates/zombo-core/src/web/findings.rs:260 | info | NONE |

#### Rust codes that no test body names (6)

- `email_headers_too_many_hops`
- `smtp_connect_failed`
- `smtp_no_route`
- `smtp_tls_failed`
- `ssl_inspection_old_protocol` (also in Go)
- `website_provider_dns_failed`
<!-- END GENERATED findings -->

## Export to Markdown: Go against Rust

### What Go exported

The Go app exported a Write-up of one Case: `internal/app/writeup.go`, served by `GET /api/cases/{id}/writeup?format=markdown|text` and copied with `c` (Markdown) or `C` (plain text) from the Write-up pane (`w`). It built text from the Case only (Targets, Findings, Steps, runs, Rep notes), never from secrets.

```
# {Case title, or its first Target, or "Case #id"}

**Ticket:** {ref} · **Status:** Open|Resolved · **Targets:** a.com (domain), 1.2.3.4 (ip)

## Findings

- **Critical** (em dash) {title} ({target}): {message} → {recommendation}
(only non-ok Findings; "No problems found." when none)

**Looks fine:** {ok title} ({target}), ...

## Changes
- **{Check}** on {target} (hh:mm → hh:mm): {field}: `{removed}` → `{added}`; ...
- Resolved: {title} ({target}, hh:mm → hh:mm)

## Not visible from here
- {Playbook boundary notes, de-duplicated}

## Notes
{Rep notes}

_Checked with Stackwell {version}, 2006-01-02 15:04 MST_
```

The plain-text form used the same content: the title underlined with `=`, upper-case headings, no bold, code or italics, and the Ticket, Status and Targets lines on separate lines. The Findings list was the Case's Findings sorted by severity, one list across all Checks and Targets. A separate per-Step copy (`stepText`) gave one Check's result as `field: value, value` lines.

### What Rust copies

`crates/zombo-ui/src/copy.rs` builds three levels and one extra format from one shape (`Doc`). It never writes a file.

```
# Diagnosis: `example.com`

## {Section}

**{VERDICT WORD}.** {why}

- **{Severity}** {title}: {message} {recommendation}
(every Finding of the section, ok ones too)

- {Fact key}: `{value}`
### {Details title}
- {key}: `{value}`

## Not run
- {sections that did not run}
```

Section copy is the same without the `# Diagnosis` line. Section JSON carries `target`, `section`, `state`, `verdict`, `findings`, `facts` and `details`. Text passes through `single_line` and `code`, so control, bidirectional and zero-width characters never reach the clipboard and a backtick cannot end a code span.

### Differences

1. **Plain text.** Go had it. Rust has Markdown and JSON only (E02).
2. **Header.** Go printed the Case name, ticket, status and every Target with its kind. Rust prints the target in a code span. There is no ticket or status.
3. **Shape.** Go gave one flat Findings list across the Case. Rust groups by section, each with a verdict line, its Findings, then the raw facts.
4. **Ok Findings.** Go listed problems only and summed the ok ones as "Looks fine: titles". Rust lists every Finding of a section, including ok ones, and has no "Looks fine" line.
5. **Wording of one Finding.** Go: `**Critical**`, an em dash, `title (target): message → recommendation`. Rust: `**Critical** title: message recommendation`. Rust has no target in the line (the section names it), no dash, and no arrow before the recommendation. A recommendation therefore reads as part of the message.
6. **Raw data.** Go's Write-up carried no records or headers. Rust includes facts and details (record rows, resolver rows, redirect chain), so a Rust copy is longer and is the only way to copy raw results (replaces per-Step copy).
7. **Changes and "Resolved".** Go listed what changed between runs and which problems were resolved. Rust copy has no such section (E04, N6).
8. **"Not visible from here".** Go printed Playbook boundary notes. Rust has nothing (C20, N4).
9. **Notes.** Go printed Rep notes. Rust has no notes.
10. **Footer.** Go ended with "Checked with Stackwell {version}, {date}". Rust has no footer, no version, no time.
11. **Not run.** Rust adds a `## Not run` list, so an unrun Check is never mistaken for a pass. Go had no equivalent because a Case showed only what had run.
12. **Verdict words.** Rust adds a verdict word per section. Go had none.
13. **Sanitising.** Rust strips control and bidirectional characters. Go copied text as it came.
14. **Evidence.** Rust copies an Evidence tab the same way (`zombo-ui/src/evidence_model.rs::sections_as_markdown_name_the_section_and_quote_values`). Go printed Evidence Findings inside the Case Write-up.

## Packaging, release and CI

| Item | Go release | Rust release |
|---|---|---|
| Artifacts | `Stackwell-<v>-x86_64.AppImage`, `SHA256SUMS` | `Zombos-Razor-<v>-x86_64.AppImage`, `zombo-<v>-x86_64-linux.tar.gz` (the CLI), `SHA256SUMS`, `SHA256SUMS.minisig` once the key exists |
| Binary | Static Go binary, `CGO_ENABLED=0`, runs on any Linux with a browser | `zombo-razor` plus `libxkbcommon`; needs glibc 2.39, a Wayland or X11 session and Vulkan or OpenGL from the host |
| Targets | Arch and Ubuntu 22.04 and newer (ADR-0001) | Ubuntu 24.04 and newer, tested on 24.04, 26.04, 26.10 and Arch (plan.md). Ubuntu 22.04 is not supported |
| Build | `packaging/build-appimage.sh` on the runner, `npm ci`, tools fetched from `continuous` URLs without a hash | The same script in an `ubuntu:24.04` container pinned by digest, tool hashes verified, reproducible (`SOURCE_DATE_EPOCH`) |
| Desktop files | `stackwell.desktop`, `stackwell.svg` | `.desktop`, AppStream metainfo, SVG and PNG icon, OFL licence text |
| Signing | None. Update checked `SHA256SUMS` only | minisign over `SHA256SUMS`. The workflow fails on purpose until `MINISIGN_SECRET_KEY` exists. The embedded key is a test key (docs/release.md) |
| Release publication | `gh release create` published at once | Draft release for a person to read and publish |
| Version stamp | `-ldflags -X main.version` | Missing until this audit; now `ZOMBO_VERSION` (see Summary) |
| Size gate | None | 40 MB gate in `release.yml` (AppImage is 17.3 MB, progress.md) |
| Smoke test | A page smoke on the runner, plus containers `archlinux:latest` and `ubuntu:22.04` with extract-and-run | `packaging/smoke.sh` in clean Ubuntu 24.04 and 26.04 under Xvfb and llvmpipe; no Arch job in CI (progress.md "Not verified") |
| CI checks | `go vet`, `staticcheck`, `go test -race`, frontend check and build, Playwright against the real binary | `cargo test`, `clippy -D warnings`, `cargo deny`, `cargo audit` (`rust.yml`), weekly fuzzing (`fuzz.yml`). Go's `ci.yml` still runs the Go checks until the Go code is deleted |
| Not carried over | Race detector (Rust has none to match), the Playwright suite (replaced, C42) | |

## Migration for a user of the Go app

1. **Stored Cases are not readable by the new app.** They sit in `$XDG_DATA_HOME/stackwell/stackwell.db` (default `~/.local/share/stackwell/stackwell.db`, SQLite in WAL mode). The Rust app does not read, move or delete the file. The team decided on no last Go release, so there will be no export button. Anyone who needs an old Case can read the file with `sqlite3`, or use the Go release that is still published. N7.
2. **Secrets are not migrated.** They are in the system keyring under the service `stackwell`, or in `$XDG_CONFIG_HOME/stackwell/secrets.json`. No Rust feature uses a secret. Delete them when the team is ready.
3. **Settings are not migrated.** The Go settings lived in the database (team playbook folder, update state). The Rust settings are a new file, `$XDG_CONFIG_HOME/zombo-razor/config.toml`: `resolvers`, `dkim_selectors`, `timeout_seconds`, `proxy`, `notifications`, `check_updates`. Team playbook YAML files have no use any more.
4. **Recent targets and update state** are new files in `$XDG_STATE_HOME/zombo-razor/`.
5. **Platform.** Ubuntu 22.04 users must upgrade the OS: the AppImage needs glibc 2.39. The host also needs a GPU driver for Vulkan or OpenGL (the Go app needed a browser).
6. **Habits.** Shortcuts changed (K01 to K10). Cases and the Write-up are gone: the replacements are tabs, recent targets and Diagnosis copy.
7. **Name.** The app, binary, app ID and update repository changed. The AppStream metainfo still points at the old Stackwell URL (progress.md "Release work").
8. **Running both.** They do not conflict: different directories, no shared port.

## MISSING

| ID | Item | Why it is MISSING |
|---|---|---|
| C23, K07 | Cancel a running Check (`x`) | No cancel action. A Check ends by its timeout. |
| K10 | `j` and `k` list navigation | DESIGN.md promises it. Not built, and not on the "Not built" list in progress.md. |
| E04 | Changes and "Resolved" lines in the copied text | The diff is on screen only. |

## Needs a decision

| # | Question | Evidence | Recommendation |
|---|---|---|---|
| N1 | Where do the `dns_*` record Findings appear? `lookup_findings(target, apex, &LookupResult)` exists and is tested, but no code calls it. | The DNS section takes its Findings from `propagation_findings` (`zombo-ui/src/diagnosis.rs`). `dns_propagation_nxdomain` already covers the NXDOMAIN case for resolvers. `Scope::Mail` and `Scope::Web` do not ask every type, so the rules must run only on a full-scope answer. | Wire it into the DNS section from the authoritative answer (else the first agreeing resolver), for scope `all` and domain or hostname targets only, and drop `dns_nxdomain` when `dns_propagation_nxdomain` fires. |
| N2 | A server that speaks only TLS 1.0 or 1.1 gives a handshake error with a hint, not the Go warning. | `rustls` has no TLS 1.0 or 1.1. `handshake_error` in `tls.rs` builds the hint. No test covers it. | Accept the deviation. Add a test for the hint. Record it in ADR or DESIGN so the hint is the documented replacement. |
| N3 | The UI offers no Check options: TLS port (465, 993, 995, 8443), propagation scope, email scope. The CLI has the first two. | Go offered all three. progress.md and DESIGN.md say nothing about options. | Accept the scopes (the Diagnosis runs everything). Add an on-demand TLS port field, because a rep checks mail certificates on 993 and 995. Write the rest into DESIGN.md. |
| N4 | The Playbook boundary notes ("Not visible from here") are gone. | They said what a Check cannot see: registrar account, CDN origin, application logs, recipient-side filtering. Go printed them in every Write-up. | Keep three or four fixed lines per section in the section pane and in the copied Markdown. They are data, not Playbooks. |
| N5 | No Vantage for "this machine's resolver" in the DNS and email Checks. | CONTEXT.md names the local machine as a Vantage. Go asked the machine's resolver. Rust uses it only for the blacklist, rDNS and MX. It answers "is my own network caching this?" and shows split-horizon DNS. | Add the machine's resolver as an eleventh row, labelled "This machine". |
| N6 | Diagnosis copy has no "Changed since the previous run" section and no footer with version and time. | E04 and Differences 7 and 10. | Add the change lines to the copied Markdown, and a one-line footer with `zombo_core::VERSION` and the time. Skip plain text. |
| N7 | Old Cases. The team chose no last Go release. | Migration item 1. | Put a short `sqlite3` recipe in the release notes, or accept the loss. The lead decides. |
| N8 | Should the app allow only one running window? | The Go app enforced it. Two Rust windows can run the same Watch twice. | Do not enforce it. Each window is independent and nothing is shared. |
| N9 | Cancel a running Check, and `j` and `k` through findings. | C23 and K10. | Build both. Cancel: `Escape` in a section that is running. `j` and `k`: move focus through findings and rows when not typing. |

## Other observations

- DESIGN.md says an IP target runs reverse DNS and the blacklist on its own. `automatic(Kind::Ip)` in `zombo-ui/src/checks.rs` is empty, so an IP target starts nothing until a rep asks. Go had no reverse DNS, so this is not a regression.
- The web Check sends `zombo/<crate version>` as its User-Agent. `ZOMBO_VERSION` does not reach it, so a release says `zombo/0.0.0`. Cosmetic.
- Go tests with no Rust equivalent were not found: every Go Check test scenario named in the inventory has a Rust test above, except the Go `TestSSLInspectionWarnsAboutOldProtocols` (C12) and the Go update tests that assumed an unsigned release.
