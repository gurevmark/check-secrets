# Initial publication review

Date: 2026-11-10. Versions: initial 0.1.0 extraction and 0.1.1 fixture correction.

This records the local publication gate performed with Codex assistance. It is
not an independent security audit, a legal opinion, or a guarantee that every
secret can be detected.

## Origin and public contents

- Reviewed the installed scanner, original tests, applicable local instructions,
  and the available original creation record. Baseline fingerprints and scope
  are documented in [PROVENANCE.md](PROVENANCE.md).
- Imported reusable code and tests into a new Git history. No original private
  project history, skill instructions, operator configuration, session logs, or
  personal installation paths were included.
- Reviewed the staged file inventory, Python imports, copyright/license text,
  synthetic fixtures, documentation, hooks, and workflow. Python runtime imports
  are standard-library only. No third-party implementation or upstream license
  notice was identified in the reviewed imported source.
- Checked for private filesystem paths, unrelated operator/project references,
  credential patterns, and accidental cache/environment files. No such findings
  remained in the staged tree or distribution contents. This review has the
  limitations described in the README.
- Verified that the MIT permission and warranty terms match the SPDX MIT text.
  Commits use the maintainer's public GitHub noreply identity.

## Local validation evidence

Environment: macOS ARM64, Python 3.14.3, Git 2.54.0, pre-commit 4.7.0.

| Check | Result |
| --- | --- |
| Original installed regression suite | 24 tests passed |
| Standalone suite, `python3 -B -m unittest discover -s tests` | 57 tests passed |
| Python 3.10 syntax parsing | Passed for every Python source |
| Full index scan using original and extracted scanners | Exit 0 |
| `git diff --cached --check` | Passed |
| `python -m build` | Source archive and universal wheel built |
| `python -m twine check dist/*` | Both distributions passed |
| Distribution file/content inspection | No private paths, credential matches, or caches found |
| Wheel install with `--no-deps` | Passed |
| Installed CLI and module execution outside the source directory | Passed |
| pre-commit manifest/config validation | Passed |
| Actual Python hook installed from the committed local repository | Passed |

The real framework smoke test rejected a staged synthetic secret even when the
working copy was fixed, restored the unstaged fix, accepted the corrected staged
file, and rejected an incomplete scan. The main suite separately covers real
partial `git add`, linked worktrees, `git commit --only`, alternate indexes,
conflicts, missing objects, partial/sparse clones, false positives, and redaction.

The original installed scanner retained its baseline SHA-256 and executable mode.
It remains in place for existing hooks. No hooks in unrelated repositories were
rewritten during extraction.

## CI boundary

The local gate above precedes publication. Linux, macOS, and Windows matrix
results are produced by [GitHub Actions](https://github.com/gurevmark/check-secrets/actions/workflows/ci.yml)
after pushing. Treat the check results for the exact commit being consumed as
the evidence for those platforms, rather than extrapolating from the local run.
Some filename and symlink tests explicitly skip when a platform cannot represent
the fixture. The workflow does not publish packages to PyPI.

The first Windows run exposed newline translation in the partial-add test
fixtures: a text write converted LF to CRLF, changing every line and merging two
intended hunks. Version 0.1.1 writes those fixtures as UTF-8 bytes, matching the
baseline on all platforms. The detection rules did not change. The original
0.1.0 tag is preserved; use 0.1.1 or a reviewed later commit.
