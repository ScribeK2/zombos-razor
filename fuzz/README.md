# Fuzzing

One libFuzzer target per parser of untrusted input, in `fuzz_targets/`. The crate is outside the workspace and has its own `Cargo.lock`.

```sh
cargo install cargo-fuzz --locked
python3 fuzz/seed.py                      # seed fuzz/corpus/ from testdata/
cd fuzz
cargo fuzz run -O whois_text -- -max_total_time=60 -timeout=10 -rss_limit_mb=2048
```

`cargo-fuzz` needs a nightly compiler. On a stable `rustc` that ships the sanitizer runtimes (Arch, for one) set `RUSTC_BOOTSTRAP=1` instead. Add `RUSTFLAGS=-Coverflow-checks=on` to also catch arithmetic overflow, which release builds hide.

Parsers with no public bytes-in entry are reached through `zombo_core::untrusted`. A crash found here gets a regression test with the minimised input in `crates/zombo-core/tests/fuzz_regressions.rs`.
