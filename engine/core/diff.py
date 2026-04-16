from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import subprocess


@dataclass
class DiffResult:
    parent_commit: str
    commit: str
    changed_files: List[str] = field(default_factory=list)
    existing_changed_files: List[str] = field(default_factory=list)


def run_command(cmd: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def git_output(args: List[str], repo_path: Path) -> str:
    result = run_command(["git", *args], cwd=repo_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Git command failed")
    return result.stdout.strip()


def ensure_git_repo(repo_path: Path) -> None:
    result = run_command(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo_path)
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise RuntimeError(f"Not a git repository: {repo_path}")


def get_changed_files(repo_path: Path, parent_commit: str, commit: str) -> List[str]:
    output = git_output(["diff", "--name-only", parent_commit, commit], repo_path)
    return [line.strip() for line in output.splitlines() if line.strip()]


def filter_existing_files(repo_path: Path, files: List[str]) -> List[str]:
    return [f for f in files if (repo_path / f).exists() and (repo_path / f).is_file()]


def build_diff_result(repo_path: str, parent_commit: str, commit: str) -> DiffResult:
    repo = Path(repo_path).resolve()
    ensure_git_repo(repo)

    changed_files = get_changed_files(repo, parent_commit, commit)
    existing_changed_files = filter_existing_files(repo, changed_files)

    return DiffResult(
        parent_commit=parent_commit,
        commit=commit,
        changed_files=changed_files,
        existing_changed_files=existing_changed_files,
    )