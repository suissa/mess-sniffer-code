# Multi-language analysis examples

Each folder contains intentionally problematic source files for `fallow --export-dashboard` demos.
The examples focus on the analyses currently available for Python, Rust, Go, and Zig source discovery:

- duplicated code blocks (`fallow dupes` / combined mode)
- unused source files when no entry point reaches them (`fallow` / dead-code file analysis)
- stale or invalid suppression comments (`fallow` / stale suppression analysis)

Run from the repository root:

```bash
cargo run -p fallow-cli --bin fallow -- --root examples/languages --dupes-min-tokens 8 --dupes-min-lines 3 --export-dashboard fallow-dashboard.json
```

Then open `report-dashboard.html` and load `fallow-dashboard.json`.
