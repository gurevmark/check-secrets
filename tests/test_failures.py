"""Inject rare Git failures without depending on corrupt machine state."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from check_secrets import scanner
from support import SAMPLE_GITHUB


class FailureTests(unittest.TestCase):
    def run_cli(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            result = scanner.main([])
        return result, out.getvalue() + err.getvalue()

    def assert_private_error(self):
        result, output = self.run_cli()
        self.assertEqual(result, 2)
        self.assertNotIn(SAMPLE_GITHUB, output)
        self.assertNotIn("Traceback", output)

    def test_raw_git_stderr_and_stdout_are_suppressed_on_failure(self):
        result = subprocess.CompletedProcess([], 128, SAMPLE_GITHUB.encode(), SAMPLE_GITHUB.encode())
        with patch.object(scanner.subprocess, "run", return_value=result):
            self.assert_private_error()

    def test_timeouts_do_not_echo_command_or_partial_output(self):
        error = subprocess.TimeoutExpired(["git", SAMPLE_GITHUB], 30, output=SAMPLE_GITHUB, stderr=SAMPLE_GITHUB)
        with patch.object(scanner.subprocess, "run", side_effect=error):
            self.assert_private_error()

    def test_os_errors_are_redacted(self):
        with patch.object(scanner.subprocess, "run", side_effect=OSError(SAMPLE_GITHUB)):
            self.assert_private_error()

    def test_malformed_index_is_redacted(self):
        with patch.object(scanner, "run_git", side_effect=[b"true\n", SAMPLE_GITHUB.encode(), b"sample.txt\0"]):
            self.assert_private_error()

    def test_malformed_size_is_redacted(self):
        entry = b"100644 " + b"a" * 40 + b" 0\tsample.txt\0"
        with patch.object(scanner, "run_git", side_effect=[b"true\n", entry, b"sample.txt\0", SAMPLE_GITHUB.encode()]):
            self.assert_private_error()

    def test_unexpected_object_id_cannot_become_a_git_option(self):
        entry = b"100644 --help 0\tsample.txt\0"
        with patch.object(scanner, "run_git", side_effect=[b"true\n", entry, b"sample.txt\0"]):
            self.assert_private_error()

    def test_blob_size_mismatch_is_incomplete(self):
        entry = b"100644 " + b"a" * 40 + b" 0\tsample.txt\0"
        with patch.object(scanner, "run_git", side_effect=[b"true\n", entry, b"sample.txt\0", b"10\n", b"short"]):
            self.assert_private_error()

    def test_concurrent_index_change_is_incomplete(self):
        entry = b"100644 " + b"a" * 40 + b" 0\tsample.txt\0"
        with patch.object(scanner, "run_git", side_effect=[b"true\n", entry, b"sample.txt\0", b"5\n", b"clean", b""]):
            self.assert_private_error()

    def test_concurrent_staged_selection_change_is_incomplete(self):
        with patch.object(scanner, "run_git", side_effect=[b"true\n", b"", b"", b"", b"new.txt\0"]):
            self.assert_private_error()

    def test_keyboard_interrupt_is_incomplete(self):
        with patch.object(scanner, "run_git", side_effect=KeyboardInterrupt):
            self.assert_private_error()


if __name__ == "__main__":
    unittest.main()
