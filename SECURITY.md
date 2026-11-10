# Security policy

This experimental tool is an additional guardrail, not a security boundary.
See the scope and limitations in [README.md](README.md).

For a reproducible detection gap or false positive, open a GitHub issue with
synthetic data constructed at runtime, the tool/Python/Git versions, expected
behavior, and actual exit code. Do not include real credentials, private paths,
raw Git error output, or screenshots containing secrets.

If an actual credential has been exposed, revoke or rotate it at its provider
before investigating. A clean scan does not establish that it was never exposed.

Changes to detection rules should include positive and negative regression
cases. Changes to Git access must preserve staged-content semantics, fail-closed
errors, and safe diagnostics. Supported fixes target the latest project version;
there is no guaranteed response time or vulnerability disclosure service.
