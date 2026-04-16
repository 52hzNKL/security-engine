from dataclasses import dataclass
from typing import List


IMPORTANT_FILES = {
    # Python
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "setup.py",
    "Pipfile",
    "Pipfile.lock",
    # Java
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradle.properties",
    # Common / CI
    "Dockerfile",
    ".semgrepignore",
}

IMPORTANT_PREFIXES = [
    ".github/workflows/",
]

DEFAULT_MAX_CHANGED_FILES = 10


@dataclass
class DecisionResult:
    mode: str
    reason: str


def file_is_important(file_path: str) -> bool:
    if file_path in IMPORTANT_FILES:
        return True

    for prefix in IMPORTANT_PREFIXES:
        if file_path.startswith(prefix):
            return True

    return False


def decide_preliminary_mode(
    changed_files: List[str],
    max_changed_files: int = DEFAULT_MAX_CHANGED_FILES,
) -> DecisionResult:
    if len(changed_files) > max_changed_files:
        return DecisionResult(
            mode="fullscan",
            reason=f"changed_files>{max_changed_files}",
        )

    for file_path in changed_files:
        if file_is_important(file_path):
            return DecisionResult(
                mode="fullscan",
                reason=f"important_file:{file_path}",
            )

    return DecisionResult(
        mode="incremental",
        reason="eligible_incremental",
    )


def finalize_scan_mode(
    changed_files: List[str],
    existing_changed_files: List[str],
    max_changed_files: int = DEFAULT_MAX_CHANGED_FILES,
) -> DecisionResult:
    preliminary = decide_preliminary_mode(
        changed_files=changed_files,
        max_changed_files=max_changed_files,
    )

    if preliminary.mode == "incremental" and not existing_changed_files:
        return DecisionResult(
            mode="fullscan",
            reason="no_existing_changed_files_after_checkout",
        )

    return preliminary