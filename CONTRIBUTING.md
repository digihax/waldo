# Contributing

Keep changes focused and preserve operator control. Explain observed facts,
false-positive limits and denied/partial coverage. Avoid broad rewrites and new
runtime dependencies. Separate bug fixes, tests and optional features.

Run the relevant synthetic checks in [tests/README.md](tests/README.md), check
syntax and identify tests not run. Tests that mirror a rule can drift from it;
prefer importing production helpers where practical. Use isolated disposable
hosts for tests that execute collection.

Reports should contain the script revision, platform, mode and a minimal sanitized
reproduction. Never include credentials, customer evidence, internal hostnames or
raw assessment output. For sensitive vulnerabilities, use GitHub private reporting
if enabled; otherwise request a private contact without posting technical details.
Preserve the MIT license and attribution.
