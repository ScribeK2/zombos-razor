# Module design

Zombo's Razor favours deep modules: a lot of behaviour behind a small interface. Stackwell went wrong the other way. Each new feature stacked on an older one and blurred what each part was for. These rules stop that here. Read them before you add or change a module.

## Words

Use these terms and no others for design talk. Domain words (Check, Lookup, Vantage, Finding, Target, Evidence) stay in `CONTEXT.md`.

- **Module.** Anything with an interface and an implementation: a function, a file, a crate.
- **Interface.** Everything a caller must know: types, invariants, ordering, error modes, configuration.
- **Depth.** How much behaviour a caller gets per unit of interface. Deep is good. Shallow means the interface is nearly as complex as the implementation.
- **Seam.** The place where a module's interface lives. You can change behaviour there without editing there.
- **Adapter.** A concrete thing that fills an interface at a seam, such as the local resolver or a fake DNS server.

## Rules

1. **Place a feature by the question the rep asks, not by the mechanism it uses.** Name the Check whose question the feature answers. If it extends that question, it goes inside that Check. If it needs a new word in `CONTEXT.md`, it is a new Check. CAA, OCSP, TLSA and a protocol scan all answer "is this host's TLS sound?", so they belong in one TLS Check.
2. **Write the interface before the code.** List the public items of each module you add or change. Fewer is better. A new `pub` item needs a caller outside its crate.
3. **Run the deletion test.** Imagine you delete the module. If its code only moves into its callers, the module was a pass-through. If the complexity reappears in many callers, it earns its place.
4. **Do not stack siblings.** No `x_extras.rs` and no `x_plus.rs`. No glue in a caller that merges the results of two modules into one answer. The caller should receive one answer from one module.
5. **Keep the surface narrow.** Use `pub(crate)` unless a caller outside the crate needs the item. Tests in `crates/*/tests/` and the `fuzz/` targets are outside the crate, and `docs/parity.md` cites those tests by path. Keep an item `pub` while one of them calls it. Add a new test-only variant (`_with`, `_via`) only when such a test needs it.
6. **Put test seams in one place.** When a test must inject a fake (a port, a clock, a resolver list, a fake server address), add the field to the module's seams value, for example `Request::seams`, and give it its production value as the default. Do not add a top-level input for it. Production code and the UI never set a seam. Callers build a value with struct update (`..Default::default()`), so a new seam changes no existing caller.
7. **One adapter is a guess. Two adapters are a seam.** Add a port only when two adapters are real, for example production and a test fake. Resolvers are plain data (`propagation::Vantage`), not adapters. The seam that may become real is where a whole Check runs: this machine, or a remote `zombo` over SSH. Do not add it before the second adapter exists.
8. **Test through the interface.** A test that must change when the internals change is testing past the seam. When a deeper module replaces shallow ones, delete their old unit tests and write new ones at the new interface.
9. **Say it in the pull request.** Add a "Module" line to the PR description. It names the module you deepened, or says why a new one is needed, and lists the public items you added or removed.

## Known shallow spots

Fixed by the Check registry refactor (PRs 48 to 55):

- The UI no longer joins CAA onto TLS: `with_caa()` is gone, and the TLS Check hands back one outcome.
- The UI no longer converts each Check's result into an `Outcome` by hand. Every Check returns an `Outcome`, and the UI reads label, automatic kinds, budget, blind spots and owner prefixes from the descriptor.
- `tls_extras.rs` is folded into the TLS module: `tls/mod.rs`, `tls/caa.rs` and `tls/ocsp.rs`. `tls` re-exports the CAA and OCSP items, so callers use `zombo_core::tls::`.

Still open:

- The CLI (`crates/zombo/src/main.rs`) still has one hand-written subcommand per Check. A generic dispatch changes the `--json` shape and the default timeouts, so it needs a decision first.
- A new Check still adds a `Section` variant, its `ALL` entry and its `home()` arm in the UI.

Cross each one off here when you fix it.
