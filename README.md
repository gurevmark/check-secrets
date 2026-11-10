# check-secrets

[![CI](https://github.com/gurevmark/check-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/gurevmark/check-secrets/actions/workflows/ci.yml)

An offline Python tool that checks **the Git index** for possible secrets before
a commit. It has no third-party runtime dependencies and does not call credential
providers. Developed by Mark Gurevich in collaboration with OpenAI Codex.

This is a small, heuristic guardrail. A successful scan means no configured
pattern matched within its scope; it does **not** certify that a repository is
safe to publish. See [limitations](#limitations) and [provenance](PROVENANCE.md).

## Requirements and installation

- Python 3.10 or newer.
- Git supporting `--no-lazy-fetch`. Check with `git --no-lazy-fetch --version`.
  An unsupported Git version fails closed with exit 2.
- A non-bare Git working tree. Linked worktrees are supported.

Install into a virtual environment from this repository (no PyPI release is
implied):

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'git+https://github.com/gurevmark/check-secrets.git@v0.1.1'
check-secrets --version
```

On Windows, use `py -m venv .venv` and activate `.venv\Scripts\Activate.ps1` in
PowerShell. Ensure the environment is available when Git runs the hook, including
from an IDE. Installation can download build tools; **scanning** is offline.

Alternatively, clone the repository and run without installing anything:

```sh
python3 /path/to/check-secrets/scripts/secrets_check.py --repo /path/to/project
```

The launcher resolves its package relative to itself. It has no dependency on
the author's machine, agent skills, or any original installation.

## What gets scanned

```sh
git add -- path/to/file
check-secrets
check-secrets --repo /path/to/project
check-secrets --all
check-secrets --show-paths
check-secrets --max-bytes 20971520
```

By default, the tool reads the **entire staged blob** of each added, modified,
renamed, or type-changed file. It does not limit matching to changed lines.
Deleted files are excluded. On the first commit, all staged files are checked.
`--all` includes unchanged files in the current index; it does not scan history.

If you stage a secret and then fix only the working copy, the staged secret still
blocks the commit. If a secret exists only in an unstaged hunk, it is outside the
pending commit and this scan. Run `git add` again after fixing a staged finding.
The scanner does not stage, stash, reset, or rewrite files. It respects the
temporary `GIT_INDEX_FILE` supplied by Git, including `git commit --only`.

| Exit | Meaning | Hook behavior |
| --- | --- | --- |
| 0 | No matches in scanned index blobs | May proceed |
| 1 | Possible secret or sensitive filename | Block |
| 2 | Scan incomplete or invalid invocation | Block |

Errors take priority over findings. Unresolved conflicts, missing objects, Git
failures/timeouts, detected concurrent index changes, Git LFS pointers, and blobs
over the default 10 MiB limit return 2. Increase `--max-bytes` deliberately when a
larger blob needs inspection; oversized files are never silently accepted.

## Findings and privacy

Default output contains only a stable identifier derived from the path, line
number, rule name, and a redaction marker:

```text
file[0123456789abcdef]:12: github-token [REDACTED]
```

No matched values, source lines, raw Git errors, or invalid command arguments are
printed. Paths are hidden by default because filenames can contain secrets.
Use `--show-paths` **locally** to locate a finding. That flag prints JSON-escaped
paths, which can reveal sensitive filenames; do not use it in public CI logs.
Path identifiers are truncated SHA-256 digests, not encrypted filenames.

For a false positive, inspect the staged content locally, establish why the rule
matched, and use a supported placeholder or runtime secret lookup where
appropriate. There is no blanket ignore list or inline suppression directive.
Rule changes should include both an allowed example and a credential-shaped
example that must still be rejected. Test fixtures in this repository construct
synthetic values at runtime instead of embedding complete credentials.

## Integrate with pre-commit

Install the [pre-commit framework](https://pre-commit.com/#install), then add:

```yaml
repos:
  - repo: https://github.com/gurevmark/check-secrets
    rev: v0.1.1  # Use a reviewed full commit SHA for an immutable pin.
    hooks:
      - id: check-secrets
```

Inspect any existing hook and `core.hooksPath` before installing:

```sh
git config --show-origin --get core.hooksPath
git rev-parse --git-path hooks/pre-commit
pre-commit install
pre-commit run check-secrets
```

Preserve existing hooks; the framework supports migration of an existing hook.
Consult its [installation documentation](https://pre-commit.com/#pre-commit-install)
before replacing anything. New clones need their own installation. Linked
worktrees normally share hooks unless Git configuration selects another path.

The supplied manifest uses `language: python`, `pass_filenames: false`,
`always_run: true`, and `require_serial: true`. The scanner selects its own index
entries. Framework `files`, `exclude`, `--files`, and `--all-files` do **not**
change its scan scope. To scan all index blobs through the framework, add
`args: [--all]` to the hook. Otherwise `pre-commit run --all-files` still scans
only staged changes, which can be empty in CI.

The scanner itself leaves the index and working copy untouched; the pre-commit
framework may temporarily stash unstaged changes as part of its own lifecycle.

For an existing POSIX hook, add `check-secrets || exit $?` before later commands,
or use the supplied [launcher](scripts/pre-commit) if it is the only hook.
`check-secrets` must be on PATH; a missing executable must also block the commit.
No installer in this project overwrites hooks or changes global Git settings.

## CI

After installing the reviewed version, run:

```sh
check-secrets --all
```

In a clean CI checkout the default staged-only scan is normally empty, so
**`--all` is required** for useful coverage. The included [GitHub Actions
workflow](.github/workflows/ci.yml) runs tests across Python 3.10–3.14 on Linux,
plus Python 3.14 on macOS and Windows, scans the complete checkout index, builds
and checks distributions, and tests the actual pre-commit Python hook. Actions
are pinned to commit SHAs and use read-only repository permissions.

## Detection and limitations

Rules cover selected AWS access-key IDs, GitHub/API/Stripe/Slack/Telegram/Google
token formats, private-key headers, JWTs, bearer values, credential URLs, and
literal assignments to names such as password or API key. Filenames such as
`.env`, SSH private-key names, and key containers are blocked independently of
content. `.env.example` and similar templates still receive content checks.

- This is line-oriented regex matching, not a parser, entropy scanner, or secret
  validity checker. Formats change. False positives and false negatives are
  expected. It has not undergone an independent security audit.
- Explicit placeholders, selected runtime references, native GitHub Actions
  secret lookups, and OIDC permissions have narrow exceptions. A real credential
  equal to an allowed placeholder can be missed. Unquoted expressions in source
  files are mostly skipped and can hide embedded values.
- History, other branches, unstaged/untracked/ignored files outside the index,
  remote objects, archives, encrypted data, encoded/fragmented secrets, and
  external symlink targets are not scanned. Binary bytes are searched as text;
  this is not binary-format inspection. UTF-16/32 requires a BOM.
- Submodule commit pointers are counted and reported, but their content is
  outside scope and does not itself cause failure. Scan each submodule separately.
  Git LFS payloads cannot be inspected from the index, so detected pointers
  return 2 rather than claiming the payload was checked.
- Git object replacements and automatic lazy fetching are disabled. Git commands
  have a 30-second timeout each. Very large repositories can still take time.
  The index is checked again before success, but no lock is held: avoid concurrent
  Git mutations. Git, Python, the scanner, and the local environment must be trusted.
- A local hook is bypassable and cannot undo a previous disclosure. Use repository
  protections and independent scanning as additional controls. Revoke exposed
  credentials; removing a value from one commit does not remove history.
- The CLI emits 0/1/2 for handled outcomes; an OS kill or a missing interpreter
  can produce other nonzero statuses. Hooks must reject **every** nonzero result.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m pip install build twine pre-commit
python3 -m build
python3 -m twine check dist/*
python3 tests/check_pre_commit.py
```

The main suite uses only the standard library and disposable Git repositories,
with global Git configuration disabled. It covers actual partial `git add`,
linked worktrees, temporary/alternate indexes, hooks, false positives, output
redaction, conflicts, missing objects, sparse and partial clones, and failure
precedence. Platform-incompatible filename/symlink tests are explicitly skipped.
The separate framework smoke test requires pre-commit and may download its
isolated build dependencies. It must be run after committing the project.

The original installed skill was preserved during extraction so existing hooks
continue using that copy. It is not automatically upgraded by this project.

## License and AI collaboration

[MIT](LICENSE). Mark Gurevich directed the requirements and publication. OpenAI
Codex assisted with the original implementation, the standalone adaptation,
tests, documentation, and automated review. This is not represented as wholly
handwritten code or as independently audited software. [PROVENANCE.md](PROVENANCE.md)
records the reviewed origin and the scope of the pre-publication check.
