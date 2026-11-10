# Provenance and publication review

Review date: 2026-11-10. Maintainer: Mark Gurevich.

## Source

This project was extracted, with the maintainer's explicit publication request,
from his local `check-secrets` Codex skill. The available creation record shows
the initial Python scanner and regression tests being written in a Codex session
on 2026-11-03 and installed as a reusable skill on 2026-11-04. The installed files
also contained subsequent rule refinements when copied for this project.

Imported baseline fingerprints (SHA-256, before adaptation):

| Source file in the skill | SHA-256 |
| --- | --- |
| `scripts/secrets_check.py` | `d87f82d7cff9406f655c4afe7002bfbcb5c208fb4090f78c0cef1dcb0f0b2ff0` |
| `scripts/test_secrets_check.py` | `23cfe9ab0ce30cd21d0c915af918feeffaa9b67fd1f8143e7d506ed5c70816ed` |

The scanner was copied into `src/check_secrets/scanner.py`; the original tests
became `tests/test_original.py`. Both were then adapted. Packaging, portable
launchers, expanded tests, CI, and public documentation were added here. The
original installation and hooks were left unchanged and remain independent.

The reviewed source imports only the Python standard library. No third-party
implementation, copyright header, or upstream license notice was identified in
those files or the reviewed creation record. No third-party runtime code was
vendored. Build tools and the optional pre-commit framework are external
dependencies with their own licenses. This is a limited source/provenance review,
not an exhaustive code-similarity search, independent audit, or legal clearance.

## Public boundary

Only the reusable scanner and tests were imported from the skill. The original
skill instructions, operator configuration, machine-specific hook, session logs,
private project names, and absolute installation paths are not part of this
repository. The public history starts with this extraction; private repository
history was not imported. Copyright and Git authorship use the maintainer's
public identity; a private email address is not needed in the commit.

Before publishing, inspect the exact staged tree and built distributions for
credentials, private paths, unrelated files, and accidental fixtures. Run the
full test suite, this scanner with `--all`, and distribution validation. Record
the resulting evidence in [PUBLICATION_REVIEW.md](PUBLICATION_REVIEW.md).

## AI collaboration

Mark Gurevich set the requirements and authorized publication. OpenAI Codex
assisted in writing and refining code, tests, documentation, and packaging,
and performed automated review and validation. AI assistance is not evidence of
correctness, ownership clearance, or security certification. The documented
limitations and the MIT warranty disclaimer apply.
