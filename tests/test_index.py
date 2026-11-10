"""Real Git integration tests for index boundaries and failure behavior."""

import hashlib
import os
from pathlib import Path
import subprocess
import unittest

from support import RepositoryCase, SAMPLE_GITHUB, assignment


class IndexTests(RepositoryCase):
    def partial_add(self, name):
        """Accept the first hunk and reject the distant second hunk."""
        self.git("-c", "interactive.singleKey=false", "add", "--patch", "--", name, input=b"y\nn\n")

    def baseline(self):
        content = ["line " + str(n) + "\n" for n in range(40)]
        self.stage("sample.txt", "".join(content))
        self.git("commit", "-qm", "Clean baseline")
        return content

    def test_real_partial_add_staged_secret_survives_worktree_fix(self):
        content = self.baseline()
        content[0] = SAMPLE_GITHUB + "\n"
        content[-1] = "unstaged edit\n"
        path = self.repo / "sample.txt"
        path.write_text("".join(content))
        self.partial_add("sample.txt")
        staged = self.git("show", ":sample.txt")
        self.assertIn(SAMPLE_GITHUB.encode(), staged)
        self.assertNotIn(b"unstaged edit", staged)
        content[0] = "fixed only on disk\n"
        path.write_text("".join(content))
        index_before = (self.repo / ".git/index").read_bytes()
        work_before = path.read_bytes()
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(SAMPLE_GITHUB, result.stdout + result.stderr)
        self.assertEqual((self.repo / ".git/index").read_bytes(), index_before)
        self.assertEqual(path.read_bytes(), work_before)

    def test_real_partial_add_does_not_scan_unstaged_hunk(self):
        content = self.baseline()
        content[0] = "safe staged edit\n"
        content[-1] = SAMPLE_GITHUB + "\n"
        (self.repo / "sample.txt").write_text("".join(content))
        self.partial_add("sample.txt")
        self.assertNotIn(SAMPLE_GITHUB.encode(), self.git("show", ":sample.txt"))
        self.assertEqual(self.scan().returncode, 0)

    def test_whole_changed_blob_is_scanned_not_only_diff_lines(self):
        self.stage("sample.txt", SAMPLE_GITHUB + "\n" + "unchanged\n" * 20)
        self.git("commit", "-qm", "Synthetic historical fixture")
        self.stage("sample.txt", SAMPLE_GITHUB + "\n" + "unchanged\n" * 20 + "safe edit\n")
        self.assertEqual(self.scan().returncode, 1)

    def test_worktree_has_independent_index_and_inherits_shared_hook(self):
        self.stage("baseline.txt", "clean\n")
        self.git("commit", "-qm", "Clean baseline")
        self.install_hook()
        original = self.repo
        worktree = self.repo.parent / "linked worktree"
        self.git("worktree", "add", "-qb", "feature", str(worktree))
        main_index = (original / ".git/index").read_bytes()
        self.repo = worktree
        self.stage("sample.txt", SAMPLE_GITHUB)
        self.assertEqual(self.scan().returncode, 1)
        self.assertNotEqual(self.commit_result().returncode, 0)
        self.stage("sample.txt", "fixed\n")
        self.assertEqual(self.commit_result().returncode, 0)
        self.assertEqual((original / ".git/index").read_bytes(), main_index)
        self.assertEqual(self.scan("--repo", str(original)).returncode, 0)

    def test_relative_alternate_index_from_nested_directory(self):
        self.stage("baseline.txt", "clean\n")
        self.git("commit", "-qm", "Clean baseline")
        original = self.repo
        original_index = (original / ".git/index").read_bytes()
        self.repo = original / "nested"
        self.repo.mkdir()
        self.env["GIT_INDEX_FILE"] = "alternate.index"
        self.git("read-tree", "HEAD")
        self.stage("sample.txt", SAMPLE_GITHUB)
        # Git resolves this relative index against the worktree root.
        alternate_before = (original / "alternate.index").read_bytes()
        self.assertEqual(self.scan().returncode, 1)
        self.assertEqual(self.scan("--all").returncode, 1)
        self.assertEqual((original / "alternate.index").read_bytes(), alternate_before)
        self.assertEqual((original / ".git/index").read_bytes(), original_index)

    def test_relative_git_dir_and_work_tree_from_nested_directory(self):
        self.stage("sample.txt", SAMPLE_GITHUB)
        nested = self.repo / "nested"
        nested.mkdir()
        self.env.update(GIT_DIR="../.git", GIT_WORK_TREE="..")
        self.assertEqual(self.scan(cwd=nested).returncode, 1)
        self.assertEqual(self.scan("--all", cwd=nested).returncode, 1)

    def test_commit_only_uses_the_temporary_index_supplied_by_git(self):
        self.stage("selected.txt", "original\n")
        self.git("commit", "-qm", "Clean baseline")
        self.stage("other.txt", SAMPLE_GITHUB)
        (self.repo / "selected.txt").write_text("safe selected change\n")
        self.install_hook()
        result = self.commit_result("--only", "--", "selected.txt")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(SAMPLE_GITHUB.encode(), self.git("show", ":other.txt"))
        self.assertEqual(self.scan().returncode, 1)

    def test_nested_scan_includes_siblings_even_with_diff_relative(self):
        self.stage("outside.txt", SAMPLE_GITHUB)
        nested = self.repo / "nested"
        nested.mkdir()
        self.git("config", "diff.relative", "true")
        self.assertEqual(self.scan(cwd=nested).returncode, 1)
        self.assertEqual(self.scan("--all", cwd=nested).returncode, 1)

    def test_merge_conflict_is_incomplete(self):
        object_id = self.git("hash-object", "-w", "--stdin", input=b"clean\n").decode().strip()
        entries = "".join("100644 " + object_id + " " + str(stage) + "\tconflict.txt\n" for stage in (1, 2, 3))
        self.git("update-index", "--index-info", input=entries.encode())
        result = self.scan()
        self.assertEqual(result.returncode, 2)
        self.assertIn("unresolved merge conflict", result.stderr)

    def test_missing_object_is_incomplete(self):
        self.git("update-index", "--add", "--cacheinfo", "100644," + "f" * 40 + ",missing.txt")
        self.assertEqual(self.scan().returncode, 2)

    def test_error_has_priority_over_findings(self):
        self.stage("finding.txt", SAMPLE_GITHUB)
        self.stage("large.txt", "a" * 200)
        result = self.scan("--max-bytes", "100")
        self.assertEqual(result.returncode, 2)
        self.assertIn("github-token", result.stderr)
        self.assertNotIn(SAMPLE_GITHUB, result.stderr)

    def test_git_lfs_pointer_fails_closed_without_fetching_payload(self):
        self.stage("asset.bin", "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 100\n")
        self.assertEqual(self.scan().returncode, 2)

    def test_submodule_pointer_is_reported_as_outside_scope(self):
        self.stage("baseline.txt", "clean\n")
        self.git("commit", "-qm", "Clean baseline")
        head = self.git("rev-parse", "HEAD").decode().strip()
        self.git("update-index", "--add", "--cacheinfo", "160000," + head + ",nested")
        result = self.scan()
        self.assertEqual(result.returncode, 0)
        self.assertIn("1 submodule pointer", result.stderr)

    def test_missing_git_fails_closed_without_traceback(self):
        self.env["PATH"] = str(self.repo / "no-such-bin")
        result = self.scan()
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_arguments_are_not_echoed(self):
        for args in [("--max-bytes", SAMPLE_GITHUB), ("--" + SAMPLE_GITHUB,),
                     (SAMPLE_GITHUB,), ("--max-bytes", "0"), ("--max-bytes", "-1")]:
            with self.subTest(kind=args[0].split("=")[0] if args[0].startswith("--max") else "private input"):
                result = self.scan(*args)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(SAMPLE_GITHUB, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_repository_error_does_not_echo_path(self):
        result = self.scan("--repo", str(self.repo / SAMPLE_GITHUB))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(SAMPLE_GITHUB, result.stderr)

    def test_paths_are_private_by_default_and_identifiers_are_stable(self):
        name = SAMPLE_GITHUB + ".txt"
        self.stage(name, assignment("password", "synthetic-value"))
        result = self.scan()
        expected = hashlib.sha256(name.encode()).hexdigest()[:16]
        self.assertEqual(result.returncode, 1)
        self.assertIn("file[" + expected + "]:1", result.stderr)
        self.assertNotIn(name, result.stderr)
        self.assertNotIn("synthetic-value", result.stderr)
        self.assertEqual(self.scan().stderr, result.stderr)

    @unittest.skipIf(os.name == "nt", "Windows forbids control characters in file names")
    def test_opt_in_paths_escape_terminal_control_characters(self):
        self.stage("odd\n\t\x1b[31m.txt", SAMPLE_GITHUB)
        result = self.scan("--show-paths")
        self.assertEqual(result.returncode, 1)
        self.assertIn(r"\n\t\u001b", result.stderr)
        self.assertNotIn("\x1b", result.stderr)
        self.assertNotIn(SAMPLE_GITHUB, result.stderr)

    @unittest.skipIf(os.name == "nt", "Windows forbids newline directory names")
    def test_repository_name_can_end_in_newline(self):
        new_path = self.repo.with_name("repository\n")
        self.repo.rename(new_path)
        self.repo = new_path
        self.stage("sample.txt", SAMPLE_GITHUB)
        self.assertEqual(self.scan().returncode, 1)

    def test_sha256_object_repository(self):
        other = self.repo.parent / "sha256 repo"
        subprocess.run(["git", "init", "-q", "--object-format=sha256", str(other)],
                       env=self.env, check=True, capture_output=True)
        self.repo = other
        self.stage("sample.txt", SAMPLE_GITHUB)
        self.assertEqual(self.scan().returncode, 1)

    def test_sparse_checkout_scans_objects_outside_worktree(self):
        self.stage("visible/clean.txt", "clean\n")
        self.stage("hidden/sample.txt", SAMPLE_GITHUB)
        self.git("commit", "-qm", "Synthetic sparse baseline")
        self.git("sparse-checkout", "set", "--cone", "--sparse-index", "visible")
        self.assertFalse((self.repo / "hidden/sample.txt").exists())
        index_before = (self.repo / ".git/index").read_bytes()
        self.assertEqual(self.scan("--all").returncode, 1)
        self.assertEqual((self.repo / ".git/index").read_bytes(), index_before)

    def test_native_hook_also_blocks_incomplete_scan(self):
        self.install_hook()
        self.stage("huge.txt", b"a" * (10 * 1024 * 1024 + 1))
        result = self.commit_result()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("INCOMPLETE", result.stderr)

    def test_custom_hooks_path_is_respected(self):
        self.git("config", "core.hooksPath", ".custom-hooks")
        self.install_hook()
        self.stage("sample.txt", SAMPLE_GITHUB)
        self.assertNotEqual(self.commit_result().returncode, 0)


if __name__ == "__main__":
    unittest.main()
