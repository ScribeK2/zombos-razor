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
5. **Keep the surface narrow.** Use `pub(crate)` unless a caller outside the crate needs the item. A variant that exists only for tests (`_with`, `_via`) stays out of the public interface.
6. **One adapter is a guess. Two adapters are a seam.** Add a port only when two adapters are real, for example production and a test fake. The Vantage seam is real: local resolvers, public resolvers, and later a remote `zombo` over SSH.
7. **Test through the interface.** A test that must change when the internals change is testing past the seam. When a deeper module replaces shallow ones, delete their old unit tests and write new ones at the new interface.
8. **Say it in the pull request.** Add a "Module" line to the PR description. It names the module you deepened, or says why a new one is needed, and lists the public items you added or removed.

## Known shallow spots

- `tls_extras.rs` holds CAA and OCSP beside `tls.rs`. The UI joins them with `with_caa()` in `checks.rs`. Fold both into the TLS Check.
- The UI converts each Check's result into an `Outcome` by hand (13 `*_outcome()` functions), and the UI and the CLI both match on every Check by name. The Check should hand back one uniform outcome.

Cross these off here when you fix them.
