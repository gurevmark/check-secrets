"""Integration tests using real temporary Git repositories.

Each test has its own directory and isolated Git configuration. Credentials
are synthetic; the tests never use the developer's repositories or hooks.
"""

import os
import subprocess
import unittest


from support import RepositoryCase, SAMPLE_GITHUB, assignment


class SecretsCheckTests(RepositoryCase):
    """Original regression coverage adapted to the standalone package."""

    def test_native_workflow_secret_lookups_and_oidc_permission(self):
        self.stage(".github/workflows/ci.yml", "permissions:\n  id-token: write\nenv:\n"
                   + assignment("  DB_PASSWORD", "${{ secrets.DB_PASSWORD }}", ": ", "")
                   + assignment("  GH_TOKEN", "${{ github.token }}", ": ", "'"))
        self.assertEqual(self.scan().returncode, 0)

    def test_workflow_literals_and_mixed_expressions_still_block(self):
        for line in [assignment("DB_PASSWORD", "currently-private", ": ", ""),
                     assignment("DB_PASSWORD", "${{ secrets.DB_PASSWORD }}suffix", ": ", "'"),
                     assignment("DB_PASSWORD", "${{ secrets.X || 'literal-value' }}", ": ", ""),
                     "id-token: currently-private", "id-token: write"]:
            with self.subTest(line=line):
                self.stage(".github/workflows/ci.yml", "permissions:\n  contents: read\nenv:\n  " + line + "\n")
                self.assertEqual(self.scan().returncode, 1)

    def test_module_property_references_and_literals(self):
        for suffix in ["mjs", "cjs"]:
            self.stage("module." + suffix, "const settings = {\n  DB_PASSWORD: credentials.database,\n};\n")
            self.assertEqual(self.scan().returncode, 0)
            for value in ["'sensitive-value'", "'credentials.database'", "54321", "invalid-hardcoded-value"]:
                self.stage("module." + suffix, "const settings = {\n" + assignment("  DB_PASSWORD", value + ",", ": ", "") + "};\n")
                self.assertEqual(self.scan().returncode, 1)
            self.stage("module." + suffix, "// clean\n")

    def test_clean_code_and_runtime_references_pass(self):
        """Environment lookups and explicit placeholders do not block a commit."""
        self.stage("app.py", 'api_key = os.getenv("API_KEY")\npassword = "${PASSWORD}"\n')
        result = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK", result.stdout)

    def test_code_expressions_are_not_hardcoded_credentials(self):
        """None, attribute references, and function calls are not passwords."""
        self.stage(
            "app.py",
            'token = None\n'
            'password = settings.password\n'
            'API_KEY = get_config("API_KEY")\n',
        )
        self.assertEqual(self.scan().returncode, 0)

    def test_staged_secret_blocks_even_after_working_file_is_fixed(self):
        """Fixing a file without another git add leaves the secret in the index."""
        path = self.stage("app.py", 'value = "' + SAMPLE_GITHUB + '"\n')
        path.write_text('value = "removed"\n')
        result = self.scan("--show-paths")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('"app.py":1', result.stderr)
        self.assertNotIn(SAMPLE_GITHUB, result.stdout + result.stderr)

    def test_unstaged_secret_is_outside_commit(self):
        """Working-copy edits after git add are outside the scanned snapshot."""
        path = self.stage("app.py", 'message = "hello"\n')
        path.write_text('value = "' + SAMPLE_GITHUB + '"\n')
        self.assertEqual(self.scan().returncode, 0)

    def test_untracked_secret_is_outside_commit(self):
        """An untracked file is outside the pending ordinary commit."""
        (self.repo / "untracked.py").write_text(SAMPLE_GITHUB)
        self.assertEqual(self.scan().returncode, 0)

    def test_provider_tokens_and_private_keys_are_found(self):
        """Recognizable formats are detected without sensitive variable names."""
        samples = {
            "aws": "AKIA" + "7Q4W6E9R2T5Y8U3I",
            "github": SAMPLE_GITHUB,
            "openai": "sk-proj-" + "z9Vx8Cu7By6Nt5Mr4Eq3Wp2Lo1Ki0Jh9Gf8Ds7Aa6",
            "slack": "xoxb-" + "123456789012-234567890123-aB7cD8eF9gH0iJ1kL2mN3oP4",
            "telegram": "123456789:" + "aB7cD8eF9gH0iJ1kL2mN3oP4qR5sT6uV7wX",
            "key-header": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "jwt": (
                "eyJhbGciOiJIUzI1NiJ9."
                "eyJzdWIiOiJzY2FubmVyLXRlc3QifQ."
                "dW5zaWduZWQtdGVzdC1zaWduYXR1cmU"
            ),
        }
        for label, value in samples.items():
            with self.subTest(label=label):
                self.stage("sample.txt", value + "\n")
                result = self.scan()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_generic_secrets_and_credential_urls_are_found(self):
        """Detect credentials in configuration and URLs across supported syntax."""
        samples = [
            assignment("password", "s3curePass!"),
            assignment('"clientSecret"', "aLongSecretValue432", ": "),
            assignment("DATABASE_PASSWORD", "s3curePass!", "=", ""),
            assignment("CRM_SECRET_KEY", "a-long-encryption-key-987"),
            assignment("apiKey", "anyRealValue123", ": "),
            assignment("Authorization", "Bearer " + "someActualCredential123", ": "),
            "postgresql://alice:" + "actualPass123" + "@db.example.invalid/app",
            assignment("password", "abc123"),
            assignment("password", "plainYamlPassword123", ": ", ""),
            assignment("DATABASE_PASSWORD", "Secr[et123!", "=", ""),
            assignment("api_key: str", "aRealTypedCredential123"),
        ]
        for value in samples:
            with self.subTest(value=value):
                self.stage("config.txt", value + "\n")
                result = self.scan()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_environment_and_key_containers_are_blocked_by_name(self):
        """Sensitive filenames are blocked even when their contents look harmless."""
        for name in [".env", "config/.env.production", "identity.p12", "id_ed25519"]:
            with self.subTest(name=name):
                self.stage(name, b"opaque\x00content")
                self.assertEqual(self.scan().returncode, 1)
                self.git("rm", "-qf", "--", name)

    def test_example_env_is_scanned_but_placeholders_are_allowed(self):
        """An .env template is allowed by name, but its contents are still scanned."""
        self.stage(".env.example", "API_KEY=your_api_key_here\nPASSWORD=changeme\n")
        self.assertEqual(self.scan().returncode, 0)
        self.stage(".env.example", assignment("API_KEY", SAMPLE_GITHUB, "=", ""))
        self.assertEqual(self.scan().returncode, 1)

    def test_placeholder_word_inside_real_secret_is_not_ignored(self):
        """The word test within a value does not make the whole value a placeholder."""
        self.stage("config.py", assignment("api_key", "test_real_value_AbC987654321"))
        self.assertEqual(self.scan().returncode, 1)

    def test_deleted_secret_file_does_not_block_removal(self):
        """Removing a previously committed secret must not be blocked."""
        self.stage(".env", "PASSWORD=actualPass123\n")
        self.git("commit", "-qm", "Synthetic baseline")
        self.git("rm", "-q", ".env")
        self.assertEqual(self.scan().returncode, 0)

    def test_all_checks_unchanged_index_files(self):
        """The --all flag also scans existing unchanged index files."""
        self.stage("old.txt", SAMPLE_GITHUB)
        self.git("commit", "-qm", "Synthetic baseline")
        self.assertEqual(self.scan().returncode, 0)
        self.assertEqual(self.scan("--all").returncode, 1)

    def test_repo_option_and_subdirectories(self):
        """Find the repository from a subdirectory or an explicit option."""
        self.stage("a.txt", SAMPLE_GITHUB)
        nested = self.repo / "nested"
        nested.mkdir()
        self.assertEqual(self.scan(cwd=nested).returncode, 1)
        self.assertEqual(self.scan("--repo", str(self.repo), cwd=self.repo.parent).returncode, 1)

    @unittest.skipIf(os.name == "nt", "Windows forbids control characters in file names")
    def test_rename_and_unusual_filename_are_checked(self):
        """Renames and control characters in filenames do not hide secrets."""
        self.stage("old.txt", SAMPLE_GITHUB)
        self.git("commit", "-qm", "Synthetic baseline")
        self.git("mv", "old.txt", "new\tname\nfile.txt")
        self.assertEqual(self.scan().returncode, 1)

    def test_non_repository_fails_closed(self):
        """Running outside a repository returns a scan error rather than success."""
        result = self.scan(cwd=self.repo.parent)
        self.assertEqual(result.returncode, 2)

    def test_git_replace_cannot_hide_original_index_secret(self):
        """An object replacement cannot hide the original index content."""
        self.stage("app.py", SAMPLE_GITHUB)
        original = self.git("rev-parse", ":app.py").decode().strip()
        clean = subprocess.run(
            ["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
            input=b"clean\n", capture_output=True, check=True, env=self.env,
        ).stdout.decode().strip()
        self.git("replace", original, clean)
        self.assertEqual(self.scan().returncode, 1)

    def test_partial_clone_does_not_fetch_missing_blobs(self):
        """A missing object causes an error without triggering an automatic fetch."""
        self.stage("missing.txt", SAMPLE_GITHUB)
        self.git("commit", "-qm", "Synthetic source")
        self.git("config", "uploadpack.allowFilter", "true")
        clone = self.repo.parent / "partial clone"
        subprocess.run(
            ["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
             self.repo.as_uri(), str(clone)], env=self.env,
            capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "-C", str(clone), "read-tree", "HEAD"],
            env=self.env, capture_output=True, check=True,
        )
        # The clone source is local; this test does not need an external server.
        # An automatic fetch would retrieve the secret and produce exit 1.
        # The expected exit 2 confirms that the missing object was not fetched.
        result = self.scan("--all", cwd=clone)
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_oversized_file_fails_closed(self):
        """An oversized file causes a scan error rather than being skipped."""
        self.stage("large.txt", "a" * 200)
        result = self.scan("--max-bytes", "100")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_unicode_and_binary_content_are_checked(self):
        """UTF-16/32 and binary data do not hide a text token from detection."""
        for content in [
            ("value=" + SAMPLE_GITHUB).encode("utf-16"),
            ("value=" + SAMPLE_GITHUB).encode("utf-32"),
            b"\x00binary\xff" + SAMPLE_GITHUB.encode(),
        ]:
            with self.subTest(content_type=type(content)):
                self.stage("data-\N{SNOWMAN}.bin", content)
                self.assertEqual(self.scan().returncode, 1)

    def test_symlink_does_not_read_external_target(self):
        """Read a symlink's Git blob rather than its external target file."""
        outside = self.repo.parent / "outside.txt"
        outside.write_text(SAMPLE_GITHUB)
        try:
            (self.repo / "link.txt").symlink_to(outside)
        except OSError:
            if os.name == "nt":
                self.skipTest("Windows symlink creation is unavailable")
            raise
        self.git("add", "link.txt")
        self.assertEqual(self.scan().returncode, 0)

    def test_pre_commit_hook_rejects_secret_and_allows_clean_commit(self):
        """A real hook rejects a secret and accepts the corrected commit."""
        self.install_hook()
        self.stage("a.txt", SAMPLE_GITHUB)
        blocked = subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "Must fail"],
            env=self.env, capture_output=True,
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.stage("a.txt", "clean\n")
        self.git("commit", "-qm", "Must pass")


if __name__ == "__main__":
    unittest.main()
