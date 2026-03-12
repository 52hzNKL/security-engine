import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path


FULL_SCAN_TRIGGER_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "Dockerfile",
}

FULL_SCAN_TRIGGER_PREFIXES = [
    ".github/workflows/",
]


def run_command(cmd, cwd=None):
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    return result


def git_output(args, repo_path):
    result = run_command(["git", *args], cwd=repo_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Git command failed")
    return result.stdout.strip()


def ensure_clean_worktree(repo_path):
    status = git_output(["status", "--porcelain"], repo_path)
    if status:
        raise RuntimeError(
            "Repository has uncommitted changes. Please commit/stash them before running replay."
        )


def get_current_ref(repo_path):
    branch = git_output(["rev-parse", "--abbrev-ref", "HEAD"], repo_path)
    if branch != "HEAD":
        return branch
    return git_output(["rev-parse", "HEAD"], repo_path)


def get_last_non_merge_commits(repo_path, limit):
    output = git_output(
        ["rev-list", "--no-merges", f"--max-count={limit}", "HEAD"],
        repo_path,
    )
    commits = [line.strip() for line in output.splitlines() if line.strip()]
    commits.reverse()
    return commits


def get_parent_commit(repo_path, commit):
    result = run_command(["git", "rev-parse", f"{commit}^"], cwd=repo_path)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def get_changed_files(repo_path, parent_commit, commit):
    output = git_output(
        ["diff", "--name-only", parent_commit, commit],
        repo_path,
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def is_full_scan_needed(files):
    for file_path in files:
        if file_path in FULL_SCAN_TRIGGER_FILES:
            return True
        for prefix in FULL_SCAN_TRIGGER_PREFIXES:
            if file_path.startswith(prefix):
                return True
    return False


def filter_existing_files(repo_path, files):
    return [f for f in files if (repo_path / f).exists()]


def checkout_commit(repo_path, ref):
    result = run_command(["git", "checkout", "--detach", ref], cwd=repo_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Failed to checkout {ref}")


def restore_ref(repo_path, ref):
    result = run_command(["git", "checkout", ref], cwd=repo_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Failed to restore {ref}")


def run_semgrep(repo_path, targets, config):
    cmd = ["semgrep", "scan", "--config", "D:\Ly\Study\ITMO\Ki8\VKR\semgrep-rules\python", "--json", *targets]

    start = time.perf_counter()
    result = run_command(cmd, cwd=repo_path)
    end = time.perf_counter()

    findings_count = 0
    if result.stdout.strip():
        try:
            payload = json.loads(result.stdout)
            findings_count = len(payload.get("results", []))
        except json.JSONDecodeError:
            findings_count = -1

    elapsed_seconds = end - start

    return {
        "returncode": result.returncode,
        "duration_seconds": round(elapsed_seconds, 4),
        "duration_minutes": round(elapsed_seconds / 60, 4),
        "findings_count": findings_count,
        "stderr": result.stderr.strip(),
    }


def build_row(
    repo_name,
    commit,
    parent_commit,
    changed_files,
    scanned_files,
    incremental_result,
    full_result,
):
    return {
        "repo": repo_name,
        "commit": commit,
        "parent_commit": parent_commit,
        "changed_files_count": len(changed_files),
        "scanned_files_count": len(scanned_files),
        "changed_files": changed_files,
        "scanned_files": scanned_files,
        "incremental_time_seconds": incremental_result["duration_seconds"],
        "incremental_time_minutes": incremental_result["duration_minutes"],
        "incremental_findings": incremental_result["findings_count"],
        "incremental_returncode": incremental_result["returncode"],
        "incremental_stderr": incremental_result["stderr"],
        "full_time_seconds": full_result["duration_seconds"],
        "full_time_minutes": full_result["duration_minutes"],
        "full_findings": full_result["findings_count"],
        "full_returncode": full_result["returncode"],
        "full_stderr": full_result["stderr"],
    }


def write_csv(rows, output_csv):
    fieldnames = [
        "repo",
        "commit",
        "parent_commit",
        "changed_files_count",
        "scanned_files_count",
        "incremental_time_seconds",
        "incremental_time_minutes",
        "incremental_findings",
        "incremental_returncode",
        "incremental_stderr",
        "full_time_seconds",
        "full_time_minutes",
        "full_findings",
        "full_returncode",
        "full_stderr",
        "changed_files",
        "scanned_files",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            row_copy = row.copy()
            row_copy["changed_files"] = ";".join(row["changed_files"])
            row_copy["scanned_files"] = ";".join(row["scanned_files"])
            writer.writerow(row_copy)


def write_json(rows, output_json):
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Replay historical security scans for incremental vs full comparison"
    )
    parser.add_argument("--repo-path", required=True, help="Path to local git repository")
    parser.add_argument("--limit", type=int, default=20, help="Number of recent non-merge commits to inspect")
    parser.add_argument("--config", default="semgrep_rules.yml", help="Local Semgrep config file or directory")
    parser.add_argument("--output-csv", default="replay_results.csv", help="CSV output file")
    parser.add_argument("--output-json", default="replay_results.json", help="JSON output file")
    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    if not repo_path.exists():
        print(f"Repository path does not exist: {repo_path}", file=sys.stderr)
        sys.exit(1)

    ensure_clean_worktree(repo_path)

    original_ref = get_current_ref(repo_path)
    repo_name = repo_path.name
    rows = []
    skipped_full_only = 0

    try:
        commits = get_last_non_merge_commits(repo_path, args.limit)

        if len(commits) < 2:
            raise RuntimeError("Not enough commits to replay.")

        for commit in commits:
            parent_commit = get_parent_commit(repo_path, commit)
            if not parent_commit:
                continue

            changed_files = get_changed_files(repo_path, parent_commit, commit)

            if is_full_scan_needed(changed_files):
                print(f"Skipping commit {commit}: triggers full-scan-only rule")
                skipped_full_only += 1
                continue

            print(f"Comparing incremental vs full on commit: {commit}")

            checkout_commit(repo_path, commit)

            existing_changed_files = filter_existing_files(repo_path, changed_files)

            if not existing_changed_files:
                print(f"Skipping commit {commit}: no existing changed files to scan incrementally")
                continue

            incremental_result = run_semgrep(
                repo_path=repo_path,
                targets=existing_changed_files,
                config=args.config,
            )

            full_result = run_semgrep(
                repo_path=repo_path,
                targets=["."],
                config=args.config,
            )

            row = build_row(
                repo_name=repo_name,
                commit=commit,
                parent_commit=parent_commit,
                changed_files=changed_files,
                scanned_files=existing_changed_files,
                incremental_result=incremental_result,
                full_result=full_result,
            )
            rows.append(row)

        write_csv(rows, args.output_csv)
        write_json(rows, args.output_json)

        print("\nDone. Results written to:")
        print(f"  CSV : {args.output_csv}")
        print(f"  JSON: {args.output_json}")
        print(f"  Compared commits: {len(rows)}")
        print(f"  Skipped full-scan-only commits: {skipped_full_only}")

    finally:
        restore_ref(repo_path, original_ref)


if __name__ == "__main__":
    main()