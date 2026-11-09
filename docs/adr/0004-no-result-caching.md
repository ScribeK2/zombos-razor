# No caching of Check results

ToolHarness cached tool results for up to an hour. Stackwell fetches every Step live: reps re-run a Check precisely because they expect something changed (a DNS fix, a renewed certificate), and a cached answer silently defeats that. Only static reference data that ships with the app (disposable-domain list, RDAP bootstrap) is reused.

## Status

Review against the new design. The rule still holds and now defines a Lookup: every Lookup is live. It also drives the Agreement verdict.
