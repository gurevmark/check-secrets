#!/usr/bin/env python3
"""Scan staged Git blobs offline for possible secrets.

By default, scan the complete index version of each added or modified file,
including renames and mode changes. --all scans every index file. Working-tree
file contents and Git history are outside this scan.

Exit codes: 0 = no matches in scope, 1 = possible secret, 2 = incomplete/error.
Hooks must block on every nonzero result. Findings never include source lines
or matched values. Paths are hidden unless --show-paths is explicitly used.

Requires Python 3.10+ and Git with --no-lazy-fetch support. No runtime packages,
network access, or index writes. Pattern matching cannot find every secret.
"""

import argparse
import codecs
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import PurePosixPath
from typing import Iterator, Optional

from . import __version__


EXIT_CLEAN = 0
EXIT_SECRET_FOUND = 1
EXIT_INCOMPLETE = 2
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 30

# Узнаваемые форматы токенов проверяются независимо от имени переменной.
# Группа «value» выделяет значение, для которого допустимы явные заглушки.
# Для остальных правил совпадение с форматом само по себе считается находкой.
TOKEN_RULE_PATTERNS = [
    ("private-key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    ("aws-access-key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    (
        "github-token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
    ),
    ("api-token", r"\bsk-(?:(?:proj|svcacct|ant-api\d+)-)?[A-Za-z0-9_-]{20,}\b"),
    ("stripe-key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
    ("telegram-token", r"\b\d{6,16}:[A-Za-z0-9_-]{30,}\b"),
    ("google-api-key", r"\bAIza[A-Za-z0-9_-]{35}\b"),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b",
    ),
    (
        "credential-url",
        r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<value>[^\s/@]+)@",
    ),
    ("bearer-token", r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9._~+/-]{8,}=*)"),
]
TOKEN_RULES = [
    (rule_name, re.compile(pattern))
    for rule_name, pattern in TOKEN_RULE_PATTERNS
]

# Общие правила ищут литералы рядом с именами password, api_key, token и т. п.
# Префикс позволяет распознать, например, DATABASE_PASSWORD и clientSecret.
SECRET_NAME_PATTERN = (
    r"[\w.-]*?(?:api[_-]?key|token|password|passwd|pwd|secret|"
    r"secret[_-]?key|private[_-]?key|authorization)"
)

# Поддерживаются присваивания, JSON/YAML и аннотации вида api_key: str = ...
# Именованная группа «quote» требует одинаковые открывающую и закрывающую
# кавычки; «value» содержит только проверяемое значение без кавычек.
QUOTED_SECRET_PATTERN = re.compile(
    r'''(?i)(?<![\w.-])["']?'''
    + SECRET_NAME_PATTERN
    + r'''["']?(?:\s*:\s*[A-Za-z_][\w.\[\], |]*)?\s*[:=]\s*'''
    + r'''(?P<quote>["'`])(?P<value>[^\r\n]*?)(?P=quote)'''
)

# В настройках значение может идти без кавычек, в том числе после export.
UNQUOTED_SECRET_PATTERN = re.compile(
    r"(?i)^\s*(?:export\s+)?"
    + SECRET_NAME_PATTERN
    + r'''\s*[:=]\s*(?P<value>[^\s"'`#;,]+)'''
)

# В исходном коде password = settings.password — ссылка на переменную.
# В конфигурационном файле password = actualPassword — готовый пароль.
CODE_FILE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs",
    ".c", ".cpp", ".h", ".cs", ".rb", ".php", ".swift", ".tf",
}

# Исключаем только точные заглушки, а не любую строку со словом «example».
PLACEHOLDER_VALUES = {
    "changeme", "change_me", "change-me", "replace_me", "replace-me",
    "your_api_key_here", "your-api-key-here", "your_token_here",
    "your_password_here", "example", "example_secret", "example_token",
    "placeholder", "redacted", "<redacted>", "***", "...",
}
PLACEHOLDER_REFERENCE_PATTERN = re.compile(
    r"\$\{[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^<>]+>"
)
NON_SECRET_LITERALS = {"none", "null", "true", "false", "undefined"}

# Only an entire native lookup is nonliteral. Additional text or a fallback
# expression must still be inspected as a potential embedded credential.
WORKFLOW_LOOKUP = re.compile(
    r"""\s*[\w.-]+:\s*(?P<quote>["']?)\$\{\{\s*(?:secrets\.[A-Za-z_][\w]*|github\.token)\s*\}\}(?P=quote)\s*"""
)
JS_MEMBER = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+")


class CheckError(Exception):
    """Ошибка, из-за которой нельзя подтвердить завершение проверки."""


def run_git(repository: str, *arguments: str) -> bytes:
    """Выполнить читающую команду Git и вернуть stdout в исходных байтах.

    Подмены объектов и загрузка отсутствующих объектов отключены: проверять
    нужно реальные локальные данные будущего коммита. Переменные окружения
    Git сохраняются, поскольку hook может получать отдельный временный индекс.

    При ошибке или тайм-ауте возбуждается CheckError. Исходный stderr Git
    не включается в сообщение: в нём могут оказаться чувствительные данные.
    """
    command = [
        "git",
        "--no-replace-objects",  # Не позволять git replace скрыть исходный секрет.
        "--no-lazy-fetch",  # Не скачивать недостающие объекты даже в partial clone.
        "--no-optional-locks",  # Не делать необязательные записи в индекс.
        "-c",
        "core.fsmonitor=false",  # Do not invoke a configured external helper.
        "-C",
        repository,
        *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError(
            "Cannot run Git (missing Git, invalid path, or timeout)."
        ) from exc

    if result.returncode:
        raise CheckError(
            "Git failed; check the repository/index and support for --no-lazy-fetch."
        )
    return result.stdout


def is_placeholder(value: str) -> bool:
    """Проверить, является ли значение пустым, заглушкой или ссылкой ${VAR}."""
    value = value.strip()
    if not value or value.lower() in PLACEHOLDER_VALUES:
        return True
    return PLACEHOLDER_REFERENCE_PATTERN.fullmatch(value) is not None


def is_sensitive_filename(path: str) -> bool:
    """Определить файлы, которые блокируются по имени независимо от содержимого.

    Шаблоны вроде .env.example не блокируются по имени, но их содержимое
    проходит обычный поиск секретов вместе с остальными файлами.
    """
    filename = PurePosixPath(path).name.lower()
    is_template = filename.endswith((".example", ".sample", ".template", ".dist"))
    is_environment_file = filename == ".env" or filename.startswith(".env.")
    is_ssh_private_key = filename in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
    is_key_container = filename.endswith((".p12", ".pfx", ".jks", ".keystore"))
    return (
        (is_environment_file and not is_template)
        or is_ssh_private_key
        or is_key_container
    )


def decode_file_content(data: bytes) -> str:
    """Получить текст для поиска, распознав UTF-16/32 по отметке BOM.

    Остальные данные читаются как UTF-8 с заменой повреждённых символов.
    Бинарные файлы не пропускаются: внутри них могут быть обычные ASCII-токены.
    """
    # BOM UTF-32 начинается так же, как BOM UTF-16: порядок проверок важен.
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return data.decode("utf-32", errors="replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def find_secrets(text: str, path: str) -> Iterator[tuple[int, str]]:
    """Выдать пары (номер строки, имя правила) для возможных секретов.

    Сначала ищутся узнаваемые форматы токенов, затем значения переменных
    с чувствительными именами. Сами найденные значения наружу не передаются.
    Путь нужен для различения исходного кода и конфигурационных файлов.
    """
    file = PurePosixPath(path)
    is_source_code = file.suffix.lower() in CODE_FILE_SUFFIXES
    is_module = file.suffix.lower() in {".mjs", ".cjs"}
    is_workflow = file.parent == PurePosixPath(".github/workflows") and file.suffix.lower() in {".yml", ".yaml"}
    permissions_indent = None

    for line_number, line in enumerate(text.splitlines(), 1):
        permission = False
        if is_workflow and line.strip() and not line.lstrip().startswith("#"):
            indent = len(line) - len(line.lstrip(" "))
            if permissions_indent is not None and indent <= permissions_indent:
                permissions_indent = None
            if line.strip() == "permissions:":
                permissions_indent = indent
            permission = permissions_indent is not None and bool(re.fullmatch(r"\s*id-token:\s*(?:write|none)\s*", line))
        for rule_name, pattern in TOKEN_RULES:
            for match in pattern.finditer(line):
                if "value" in match.groupdict() and is_placeholder(match["value"]):
                    continue
                yield line_number, rule_name
                break  # Достаточно одной находки этого правила на строке.

        for pattern in (QUOTED_SECRET_PATTERN, UNQUOTED_SECRET_PATTERN):
            for match in pattern.finditer(line):
                value = match["value"]
                if is_placeholder(value):
                    continue
                if is_workflow and (permission or WORKFLOW_LOOKUP.fullmatch(line)):
                    continue
                if pattern is UNQUOTED_SECRET_PATTERN:
                    if value.lower() in NON_SECRET_LITERALS:
                        continue
                    # В коде неквотированные имена и вызовы считаются выражениями.
                    # Числовой литерал при этом всё ещё может быть паролем/PIN.
                    if is_source_code and not value.isdecimal():
                        continue
                    tail = line[match.end():].lstrip()
                    if is_module and JS_MEMBER.fullmatch(value) and (not tail or tail[0] in ",;}"):
                        continue
                yield line_number, "hardcoded-secret"


def get_staged_paths(repository: str) -> set[bytes]:
    """Получить пути изменённых файлов из индекса, исключая удалённые.

    Без распознавания переименований Git выдаёт удаление старого пути и
    добавление нового. Так новое содержимое обязательно попадает в проверку.
    Разделитель NUL сохраняет пробелы, табуляции и переводы строк в путях.
    """
    output = run_git(
        repository,
        "diff",
        "--cached",
        "--no-ext-diff",
        "--no-textconv",
        "--no-relative",
        "--no-renames",
        "--name-only",
        "--diff-filter=ACMTU",
        "-z",
        "--",
    )
    return {path for path in output.split(b"\0") if path}


def report_results(
    secret_findings: set[tuple[str, int, str]],
    scan_errors: list[str],
    checked_file_count: int,
    submodule_count: int,
    show_paths: bool = False,
) -> int:
    """Вывести безопасный отчёт и вернуть код выхода для Git hook.

    Находка содержит только экранированный путь, номер строки и имя правила.
    Ошибка проверки имеет приоритет над находками: код 2 сообщает, что часть
    файлов проверить не удалось, даже если в остальных уже найдены секреты.
    """
    for display_path, line_number, rule_name in sorted(secret_findings):
        print(
            f"{display_path}:{line_number}: {rule_name} [REDACTED]",
            file=sys.stderr,
        )
    for error in scan_errors:
        print("ERROR: " + error, file=sys.stderr)
    if (secret_findings or scan_errors) and not show_paths:
        print("Paths hidden; use --show-paths locally to locate files.", file=sys.stderr)
    if submodule_count:
        print(
            f"NOTE: {submodule_count} submodule pointer(s); "
            "run separately inside each submodule.",
            file=sys.stderr,
        )
    if scan_errors:
        print("INCOMPLETE: commit must be blocked (exit 2).", file=sys.stderr)
        return EXIT_INCOMPLETE
    if secret_findings:
        print(
            "BLOCKED: possible secrets. Remove them, then git add the corrected files.",
            file=sys.stderr,
        )
        return EXIT_SECRET_FOUND

    print(f"OK: {checked_file_count} index file(s) checked; no matching secrets found.")
    return EXIT_CLEAN


def scan_repository(
    repository: str,
    include_unchanged: bool,
    max_file_bytes: int,
    show_paths: bool = False,
) -> int:
    """Проверить содержимое индекса репозитория и вернуть код результата.

    include_unchanged включает все файлы индекса вместо только изменённых.
    max_file_bytes ограничивает размер одного файла: превышение считается
    ошибкой проверки, поэтому слишком большой файл не проходит незаметно.
    Содержимое читается по ID объекта Git, а не по пути в рабочей папке.
    """
    # Keep the caller's working directory for every Git command. Resolving and
    # switching to the root would change relative GIT_INDEX_FILE/GIT_DIR paths.
    # It also breaks repository paths that end with a newline.
    if run_git(repository, "rev-parse", "--is-inside-work-tree").strip() != b"true":
        raise CheckError("A non-bare Git worktree is required.")

    # A root pathspec and --full-name include siblings when invoked in a
    # subdirectory. Store the listing before selecting paths, then check both
    # again before declaring success. This detects ordinary concurrent edits;
    # the scanner does not lock the index or serialize other Git processes.
    index_arguments = ("ls-files", "--stage", "--full-name", "-z", "--", ":/")
    index_output = run_git(repository, *index_arguments)

    # None означает проверку всего индекса; пустое множество — отсутствие изменений.
    selected_paths: Optional[set[bytes]] = None
    if not include_unchanged:
        selected_paths = get_staged_paths(repository)

    secret_findings: set[tuple[str, int, str]] = set()
    scan_errors: list[str] = []
    checked_file_count = 0
    submodule_count = 0

    for entry in index_output.split(b"\0"):
        if not entry:
            continue

        # Формат Git: «режим ID_объекта стадия<TAB>путь<NUL>».
        # Делим только по первой табуляции: остальные могут быть частью пути.
        metadata, raw_path = entry.split(b"\t", 1)
        if selected_paths is not None and raw_path not in selected_paths:
            continue
        file_mode, object_id, index_stage = metadata.decode("ascii").split()
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id):
            raise CheckError("Invalid Git object ID; scan incomplete.")
        if file_mode not in {"100644", "100755", "120000", "160000"}:
            raise CheckError("Unsupported Git index mode; scan incomplete.")
        path = os.fsdecode(raw_path)

        # File names can themselves contain credentials. Default diagnostics
        # identify paths by a stable digest, never by their text. Opt-in path
        # display escapes terminal controls but is not suitable for public logs.
        display_path = (
            json.dumps(path, ensure_ascii=True)
            if show_paths
            else "file[" + hashlib.sha256(raw_path).hexdigest()[:16] + "]"
        )
        if index_stage != "0":  # Стадии 1–3 обозначают неразрешённый конфликт.
            scan_errors.append(display_path + ": unresolved merge conflict")
            continue
        if file_mode == "160000":  # Подмодуль хранится как ссылка на чужой коммит.
            submodule_count += 1
            continue
        if is_sensitive_filename(path):
            secret_findings.add((display_path, 1, "sensitive-filename"))

        file_size = int(run_git(repository, "cat-file", "-s", object_id))
        if file_size < 0:
            raise CheckError("Invalid Git blob size; scan incomplete.")
        if file_size > max_file_bytes:
            scan_errors.append(
                display_path + ": file too large; increase --max-bytes to scan"
            )
            continue

        file_content = run_git(repository, "cat-file", "blob", object_id)
        if len(file_content) != file_size:
            raise CheckError("Git blob size mismatch; scan incomplete.")

        checked_file_count += 1
        text = decode_file_content(file_content)
        if text.startswith("version https://git-lfs.github.com/spec/v1\n"):
            scan_errors.append(display_path + ": Git LFS payload is outside the index")
        for line_number, rule_name in find_secrets(text, path):
            secret_findings.add((display_path, line_number, rule_name))

    if run_git(repository, *index_arguments) != index_output:
        raise CheckError("Git index changed during the scan; run it again.")
    if selected_paths is not None and get_staged_paths(repository) != selected_paths:
        raise CheckError("Staged selection changed during the scan; run it again.")
    return report_results(
        secret_findings, scan_errors, checked_file_count, submodule_count, show_paths
    )


class SafeArgumentParser(argparse.ArgumentParser):
    """Never echo invalid arguments: they may contain credentials or paths."""

    def error(self, message: str) -> None:
        self.exit(EXIT_INCOMPLETE, "ERROR: invalid arguments; use --help. Scan incomplete (exit 2).\n")


def main(argv: Optional[list[str]] = None) -> int:
    """Разобрать параметры запуска и преобразовать ошибки в ненулевой код выхода."""
    parser = SafeArgumentParser(prog="check-secrets", description=__doc__, allow_abbrev=False)
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="include escaped paths in diagnostics (may expose sensitive filenames)",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="repository path (default: current directory)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="scan every index file, including unchanged files",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="maximum bytes per file (default: 10 MiB)",
    )
    args = parser.parse_args(argv)
    if args.max_bytes < 1:
        parser.error("--max-bytes must be positive")
    try:
        return scan_repository(args.repo, args.all, args.max_bytes, args.show_paths)
    except CheckError as exc:
        print(f"ERROR: {exc} Scan incomplete; commit must be blocked.", file=sys.stderr)
        return EXIT_INCOMPLETE
    except (ValueError, UnicodeError):
        print(
            "ERROR: unexpected Git data; scan incomplete; commit must be blocked.",
            file=sys.stderr,
        )
        return EXIT_INCOMPLETE
    except (OSError, KeyboardInterrupt):
        print("ERROR: scan interrupted or I/O unavailable; commit must be blocked.", file=sys.stderr)
        return EXIT_INCOMPLETE


if __name__ == "__main__":
    sys.exit(main())
