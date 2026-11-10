# Saved queries are read-only, with no write mode

ToolHarness's SQL Workbench had a write toggle behind a typed confirmation. Stackwell drops it: Saved queries run in a read-only database session and anything other than a single `SELECT` is refused. A support rep's diagnostic tool should never be able to change production data; ad-hoc writes belong in a real database client.

## Status

Review against the new design. Saved queries are not in the new Check catalog; this ADR is moot unless internal database lookups return.
