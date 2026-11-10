"""Smoke-test the committed hook manifest through the real pre-commit framework.

Run separately after creating a commit. This may download isolated Python build
dependencies. All consumer files, indexes, hooks, and caches are temporary.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

from support import ROOT, SAMPLE_GITHUB


def main():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k != "SKIP"}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, PYTHONDONTWRITEBYTECODE="1")
    revision = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"],
        env=env, capture_output=True, text=True, check=True,
    ).stdout.strip()

    with tempfile.TemporaryDirectory(prefix="check-secrets-hook-") as temporary:
        root = Path(temporary)
        repo = root / "consumer repo"
        repo.mkdir()
        env["PRE_COMMIT_HOME"] = str(root / "cache")

        def run(*args, expected=0):
            result = subprocess.run(args, cwd=repo, env=env, capture_output=True, text=True, timeout=180)
            output = result.stdout + result.stderr
            if SAMPLE_GITHUB in output:
                raise AssertionError("Synthetic fixture leaked in framework output")
            if result.returncode != expected:
                # Framework installation errors can contain paths or URLs;
                # do not forward raw subprocess diagnostics into public CI.
                raise AssertionError("Framework smoke test failed at " + args[0] + " (exit " + str(result.returncode) + ")")
            return result

        run("git", "init", "-q", "-b", "main")
        run("git", "config", "user.name", "Scanner Test")
        run("git", "config", "user.email", "scanner@example.invalid")
        (repo / ".pre-commit-config.yaml").write_text(
            "repos:\n  - repo: '" + ROOT.as_uri() + "'\n    rev: " + revision
            + "\n    hooks:\n      - id: check-secrets\n", encoding="utf-8",
        )
        (repo / "sample.txt").write_text("clean baseline\n")
        run("git", "add", "--", ".pre-commit-config.yaml", "sample.txt")
        run("git", "commit", "-qm", "Baseline")
        run(sys.executable, "-m", "pre_commit", "install")

        (repo / "sample.txt").write_text(SAMPLE_GITHUB + "\n")
        run("git", "add", "--", "sample.txt")
        # A later working-copy fix must not hide a still-staged secret. The
        # framework temporarily stashes it and must restore it after rejection.
        (repo / "sample.txt").write_text("fixed only on disk\n")
        result = run("git", "commit", "-qm", "Must reject staged secret", expected=1)
        if "github-token" not in result.stderr + result.stdout:
            raise AssertionError("Hook did not report the expected detection rule")
        if (repo / "sample.txt").read_text() != "fixed only on disk\n":
            raise AssertionError("Framework failed to restore the working copy")
        staged = subprocess.run(["git", "show", ":sample.txt"], cwd=repo, env=env, capture_output=True, check=True).stdout
        if SAMPLE_GITHUB.encode() not in staged:
            raise AssertionError("Framework changed staged content")

        run("git", "add", "--", "sample.txt")
        run("git", "commit", "-qm", "Accept corrected staged file")

        (repo / "large.txt").write_bytes(b"a" * (10 * 1024 * 1024 + 1))
        run("git", "add", "--", "large.txt")
        result = run("git", "commit", "-qm", "Must reject incomplete scan", expected=1)
        if "INCOMPLETE" not in result.stdout + result.stderr:
            raise AssertionError("Hook did not report the incomplete scan")

    print("OK: Python hook installed from committed manifest; staged secret and incomplete scan blocked; clean commit accepted.")


if __name__ == "__main__":
    main()
