from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import subprocess


@dataclass
class DiffResult:
    base_ref: str
    head_ref: str
    all_changed_files: List[str] = field(default_factory=list)
    existing_changed_files: List[str] = field(default_factory=list)
    added_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    renamed_files: List[str] = field(default_factory=list)
    status_by_file: Dict[str, str] = field(default_factory=dict)


def run_command(cmd, cwd=None):
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def git_output(args, repo_path: Path) -> str:
    result = run_command(["git", *args], cwd=repo_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Git command failed")
    return result.stdout.strip()


def ensure_git_repo(repo_path: Path) -> None:
    git_dir = repo_path / ".git"
    if git_dir.exists():
        return

    result = run_command(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo_path)
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise RuntimeError(f"Not a git repository: {repo_path}")


def resolve_merge_base(repo_path: Path, base_ref: str, head_ref: str) -> str:
    return git_output(["merge-base", base_ref, head_ref], repo_path)


def normalize_ref_range(
    repo_path: Path,
    base_ref: str,
    head_ref: str,
    use_merge_base: bool = True,
) -> tuple[str, str]:
    """
    Với PR:
      - nên dùng merge-base(base_ref, head_ref) -> head_ref
    Với push:
      - có thể dùng before -> after trực tiếp
      - hoặc vẫn dùng merge-base nếu muốn nhìn như 'delta của head branch'
    """
    if use_merge_base:
        effective_base = resolve_merge_base(repo_path, base_ref, head_ref)
        return effective_base, head_ref
    return base_ref, head_ref


def parse_name_status_line(line: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parse output của:
      git diff --name-status -M <base> <head>

    Ví dụ:
      A\tapp.py
      M\tsrc/main.py
      D\told.py
      R100\told_name.py\tnew_name.py

    Trả về:
      (status, old_path, new_path)

    Quy ước:
      - A/M/D: old_path = None, new_path = file_path
      - R*: old_path = old_name, new_path = new_name
    """
    parts = line.split("\t")
    if not parts:
        return None, None, None

    raw_status = parts[0].strip()

    if raw_status.startswith("R"):
        if len(parts) < 3:
            return None, None, None
        return "R", parts[1].strip(), parts[2].strip()

    if raw_status in {"A", "M", "D"}:
        if len(parts) < 2:
            return None, None, None
        return raw_status, None, parts[1].strip()

    return None, None, None


def get_diff_name_status(
    repo_path: Path,
    base_ref: str,
    head_ref: str,
    use_merge_base: bool = True,
) -> List[str]:
    effective_base, effective_head = normalize_ref_range(
        repo_path=repo_path,
        base_ref=base_ref,
        head_ref=head_ref,
        use_merge_base=use_merge_base,
    )

    output = git_output(
        ["diff", "--name-status", "-M", effective_base, effective_head],
        repo_path,
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def filter_existing_files(repo_path: Path, files: List[str]) -> List[str]:
    existing = []
    for rel_path in files:
        full_path = repo_path / rel_path
        if full_path.exists() and full_path.is_file():
            existing.append(rel_path)
    return existing


def get_changed_files(
    repo_path: str,
    base_ref: str,
    head_ref: str,
    use_merge_base: bool = True,
) -> DiffResult:
    repo = Path(repo_path).resolve()
    ensure_git_repo(repo)

    lines = get_diff_name_status(
        repo_path=repo,
        base_ref=base_ref,
        head_ref=head_ref,
        use_merge_base=use_merge_base,
    )

    added_files: List[str] = []
    modified_files: List[str] = []
    deleted_files: List[str] = []
    renamed_files: List[str] = []
    all_changed_files: List[str] = []
    status_by_file: Dict[str, str] = {}

    for line in lines:
        status, old_path, new_path = parse_name_status_line(line)
        if not status:
            continue

        if status == "A":
            added_files.append(new_path)
            all_changed_files.append(new_path)
            status_by_file[new_path] = "A"

        elif status == "M":
            modified_files.append(new_path)
            all_changed_files.append(new_path)
            status_by_file[new_path] = "M"

        elif status == "D":
            deleted_files.append(new_path)
            all_changed_files.append(new_path)
            status_by_file[new_path] = "D"

        elif status == "R":
            # Với rename, dùng path mới để scan nếu file vẫn tồn tại
            renamed_files.append(new_path)
            all_changed_files.append(new_path)
            status_by_file[new_path] = "R"

    # bỏ trùng nhưng giữ thứ tự
    dedup_changed_files = list(dict.fromkeys(all_changed_files))
    existing_changed_files = filter_existing_files(repo, dedup_changed_files)

    return DiffResult(
        base_ref=base_ref,
        head_ref=head_ref,
        all_changed_files=dedup_changed_files,
        existing_changed_files=existing_changed_files,
        added_files=list(dict.fromkeys(added_files)),
        modified_files=list(dict.fromkeys(modified_files)),
        deleted_files=list(dict.fromkeys(deleted_files)),
        renamed_files=list(dict.fromkeys(renamed_files)),
        status_by_file=status_by_file,
    )