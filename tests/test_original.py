"""Интеграционные проверки скрипта на настоящих временных репозиториях.

Каждый тест получает отдельную папку и независимые настройки Git. Ключи
синтетические; пользовательские репозитории и hooks в тестах не участвуют.
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
        """Чтение из окружения и явные заглушки не блокируют коммит."""
        self.stage("app.py", 'api_key = os.getenv("API_KEY")\npassword = "${PASSWORD}"\n')
        result = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK", result.stdout)

    def test_code_expressions_are_not_hardcoded_credentials(self):
        """None, ссылки на атрибуты и вызовы функций не считаются паролями."""
        self.stage(
            "app.py",
            'token = None\n'
            'password = settings.password\n'
            'API_KEY = get_config("API_KEY")\n',
        )
        self.assertEqual(self.scan().returncode, 0)

    def test_staged_secret_blocks_even_after_working_file_is_fixed(self):
        """Исправление без повторного git add оставляет секрет в индексе."""
        path = self.stage("app.py", 'value = "' + SAMPLE_GITHUB + '"\n')
        path.write_text('value = "removed"\n')
        result = self.scan("--show-paths")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('"app.py":1', result.stderr)
        self.assertNotIn(SAMPLE_GITHUB, result.stdout + result.stderr)

    def test_unstaged_secret_is_outside_commit(self):
        """Изменения рабочей копии после git add не входят в проверяемый снимок."""
        path = self.stage("app.py", 'message = "hello"\n')
        path.write_text('value = "' + SAMPLE_GITHUB + '"\n')
        self.assertEqual(self.scan().returncode, 0)

    def test_untracked_secret_is_outside_commit(self):
        """Новый файл вне индекса не входит в будущий обычный коммит."""
        (self.repo / "untracked.py").write_text(SAMPLE_GITHUB)
        self.assertEqual(self.scan().returncode, 0)

    def test_provider_tokens_and_private_keys_are_found(self):
        """Узнаваемые форматы обнаруживаются без чувствительных имён переменных."""
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
        """Пароли в настройках и URL обнаруживаются в разных вариантах записи."""
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
        """Опасное имя блокируется, даже когда содержимое не похоже на секрет."""
        for name in [".env", "config/.env.production", "identity.p12", "id_ed25519"]:
            with self.subTest(name=name):
                self.stage(name, b"opaque\x00content")
                self.assertEqual(self.scan().returncode, 1)
                self.git("rm", "-qf", "--", name)

    def test_example_env_is_scanned_but_placeholders_are_allowed(self):
        """Шаблон .env разрешён по имени, но содержимое продолжает проверяться."""
        self.stage(".env.example", "API_KEY=your_api_key_here\nPASSWORD=changeme\n")
        self.assertEqual(self.scan().returncode, 0)
        self.stage(".env.example", assignment("API_KEY", SAMPLE_GITHUB, "=", ""))
        self.assertEqual(self.scan().returncode, 1)

    def test_placeholder_word_inside_real_secret_is_not_ignored(self):
        """Слово test внутри значения не делает всё значение заглушкой."""
        self.stage("config.py", assignment("api_key", "test_real_value_AbC987654321"))
        self.assertEqual(self.scan().returncode, 1)

    def test_deleted_secret_file_does_not_block_removal(self):
        """Удаление уже закоммиченного секрета не должно блокироваться."""
        self.stage(".env", "PASSWORD=actualPass123\n")
        self.git("commit", "-qm", "Synthetic baseline")
        self.git("rm", "-q", ".env")
        self.assertEqual(self.scan().returncode, 0)

    def test_all_checks_unchanged_index_files(self):
        """Флаг --all включает в проверку и прежние неизменённые файлы индекса."""
        self.stage("old.txt", SAMPLE_GITHUB)
        self.git("commit", "-qm", "Synthetic baseline")
        self.assertEqual(self.scan().returncode, 0)
        self.assertEqual(self.scan("--all").returncode, 1)

    def test_repo_option_and_subdirectories(self):
        """Репозиторий определяется из вложенной папки или явного параметра."""
        self.stage("a.txt", SAMPLE_GITHUB)
        nested = self.repo / "nested"
        nested.mkdir()
        self.assertEqual(self.scan(cwd=nested).returncode, 1)
        self.assertEqual(self.scan("--repo", str(self.repo), cwd=self.repo.parent).returncode, 1)

    @unittest.skipIf(os.name == "nt", "Windows forbids control characters in file names")
    def test_rename_and_unusual_filename_are_checked(self):
        """Переименование и управляющие символы в имени не скрывают секрет."""
        self.stage("old.txt", SAMPLE_GITHUB)
        self.git("commit", "-qm", "Synthetic baseline")
        self.git("mv", "old.txt", "new\tname\nfile.txt")
        self.assertEqual(self.scan().returncode, 1)

    def test_non_repository_fails_closed(self):
        """Запуск вне репозитория возвращает ошибку проверки, а не успех."""
        result = self.scan(cwd=self.repo.parent)
        self.assertEqual(result.returncode, 2)

    def test_git_replace_cannot_hide_original_index_secret(self):
        """Подменённое представление объекта не скрывает его исходное содержимое."""
        self.stage("app.py", SAMPLE_GITHUB)
        original = self.git("rev-parse", ":app.py").decode().strip()
        clean = subprocess.run(
            ["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
            input=b"clean\n", capture_output=True, check=True, env=self.env,
        ).stdout.decode().strip()
        self.git("replace", original, clean)
        self.assertEqual(self.scan().returncode, 1)

    def test_partial_clone_does_not_fetch_missing_blobs(self):
        """Отсутствующий объект приводит к ошибке без автоматической загрузки."""
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
        # Источник клона локальный: тест не требует доступа к внешнему серверу.
        # При автоматической загрузке скрипт получил бы секрет и вернул код 1;
        # ожидаемый код 2 означает, что недоступный объект не был загружен.
        result = self.scan("--all", cwd=clone)
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_oversized_file_fails_closed(self):
        """Слишком большой файл завершает проверку с ошибкой, а не пропускается."""
        self.stage("large.txt", "a" * 200)
        result = self.scan("--max-bytes", "100")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_unicode_and_binary_content_are_checked(self):
        """UTF-16 и бинарные данные не скрывают текстовый токен от поиска."""
        for content in [
            ("value=" + SAMPLE_GITHUB).encode("utf-16"),
            ("value=" + SAMPLE_GITHUB).encode("utf-32"),
            b"\x00binary\xff" + SAMPLE_GITHUB.encode(),
        ]:
            with self.subTest(content_type=type(content)):
                self.stage("данные.bin", content)
                self.assertEqual(self.scan().returncode, 1)

    def test_symlink_does_not_read_external_target(self):
        """Для символьной ссылки читается объект Git, а не внешний целевой файл."""
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
        """Настоящий hook отклоняет коммит с секретом и пропускает исправленный."""
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
