from typing import List, Tuple


COMMON_FULL_SCAN_TRIGGER_FILES = {
    "Dockerfile",
}

COMMON_FULL_SCAN_TRIGGER_PREFIXES = [
    ".github/workflows/",
]


LANGUAGE_FULL_SCAN_TRIGGER_FILES = {
    "python": {
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "Pipfile.lock",
    },
    "java": {
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradle.properties",
        "mvnw",
        "mvnw.cmd",
        "gradlew",
        "gradlew.bat",
    },
}


LANGUAGE_FULL_SCAN_TRIGGER_PREFIXES = {
    "python": [],
    "java": [],
}


def _normalize_language(language: str) -> str:
    if not language:
        raise ValueError("language must not be empty")
    return language.strip().lower()


def _get_full_scan_trigger_files(language: str) -> set:
    normalized_language = _normalize_language(language)
    language_specific = LANGUAGE_FULL_SCAN_TRIGGER_FILES.get(normalized_language)
    if language_specific is None:
        raise ValueError(f"Unsupported language: {language}")
    return COMMON_FULL_SCAN_TRIGGER_FILES | language_specific


def _get_full_scan_trigger_prefixes(language: str) -> List[str]:
    normalized_language = _normalize_language(language)
    language_specific = LANGUAGE_FULL_SCAN_TRIGGER_PREFIXES.get(normalized_language)
    if language_specific is None:
        raise ValueError(f"Unsupported language: {language}")
    return COMMON_FULL_SCAN_TRIGGER_PREFIXES + language_specific


def decide_scan_mode(language: str, changed_files: List[str]) -> Tuple[str, str]:
    normalized_language = _normalize_language(language)

    if not changed_files:
        return "incremental", "no changed files detected"

    full_scan_trigger_files = _get_full_scan_trigger_files(normalized_language)
    full_scan_trigger_prefixes = _get_full_scan_trigger_prefixes(normalized_language)

    for file_path in changed_files:
        if file_path in full_scan_trigger_files:
            return "full", f"changed file matches full-scan trigger file: {file_path}"

        for prefix in full_scan_trigger_prefixes:
            if file_path.startswith(prefix):
                return "full", f"changed file matches full-scan trigger prefix: {prefix}"

    return "incremental", "no full-scan trigger matched"