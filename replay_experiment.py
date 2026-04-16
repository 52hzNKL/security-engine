import argparse
import csv
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path


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


def run_command(cmd, cwd=None):
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def git_output(args, repo_path):
    result = run_command(["git", *args], cwd=repo_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Git command failed")
    return result.stdout.strip()


def ensure_clean_worktree(repo_path):
    status = git_output(["status", "--porcelain"], repo_path)
    if status:
        raise RuntimeError(
            "Repository has uncommitted changes. Please commit or stash them before running."
        )


def get_current_ref(repo_path):
    branch = git_output(["rev-parse", "--abbrev-ref", "HEAD"], repo_path)
    if branch != "HEAD":
        return branch
    return git_output(["rev-parse", "HEAD"], repo_path)


def checkout_detached(repo_path, commit):
    result = run_command(["git", "checkout", "--detach", commit], cwd=repo_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Failed to checkout {commit}")


def restore_ref(repo_path, ref):
    result = run_command(["git", "checkout", ref], cwd=repo_path)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Failed to restore {ref}")


def get_last_non_merge_commits(repo_path, limit):
    output = git_output(
        ["rev-list", "--first-parent", "--no-merges", f"--max-count={limit}", "HEAD"],
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
    output = git_output(["diff", "--name-only", parent_commit, commit], repo_path)
    return [line.strip() for line in output.splitlines() if line.strip()]


def file_is_important(file_path):
    if file_path in IMPORTANT_FILES:
        return True
    for prefix in IMPORTANT_PREFIXES:
        if file_path.startswith(prefix):
            return True
    return False


def decide_scan_mode(changed_files, max_changed_files):
    if len(changed_files) > max_changed_files:
        return "fullscan", f"changed_files>{max_changed_files}"

    for file_path in changed_files:
        if file_is_important(file_path):
            return "fullscan", f"important_file:{file_path}"

    return "incremental", "eligible_incremental"


def filter_existing_files(repo_path, files):
    return [f for f in files if (repo_path / f).exists() and (repo_path / f).is_file()]


# ---------------------------
# Generic map helpers
# ---------------------------

def diff_identity_maps(current_map, base_map):
    diff_keys = set(current_map.keys()) - set(base_map.keys())
    return {k: current_map[k] for k in diff_keys}


def intersect_identity_maps(left_map, right_map):
    common_keys = set(left_map.keys()) & set(right_map.keys())
    return {k: left_map[k] for k in common_keys}


# ---------------------------
# Semgrep helpers
# ---------------------------

def extract_semgrep_findings_count(stdout_text):
    if not stdout_text.strip():
        return 0
    try:
        payload = json.loads(stdout_text)
        return len(payload.get("results", []))
    except json.JSONDecodeError:
        return -1


def safe_parse_semgrep_results(stdout_text):
    if not stdout_text or not stdout_text.strip():
        return []

    try:
        payload = json.loads(stdout_text)
    except json.JSONDecodeError:
        return []

    results = payload.get("results", [])
    return results if isinstance(results, list) else []


def semgrep_finding_identity(finding):
    check_id = finding.get("check_id", "")
    path = finding.get("path", "")
    start_line = (finding.get("start", {}) or {}).get("line")
    end_line = (finding.get("end", {}) or {}).get("line")
    return (check_id, path, start_line, end_line)


def make_semgrep_finding_summary(finding):
    return {
        "check_id": finding.get("check_id", ""),
        "path": finding.get("path", ""),
        "start_line": (finding.get("start", {}) or {}).get("line"),
        "end_line": (finding.get("end", {}) or {}).get("line"),
    }


def semgrep_results_to_identity_map(stdout_text):
    results = safe_parse_semgrep_results(stdout_text)
    return {semgrep_finding_identity(f): f for f in results}


def summarize_semgrep_identity_map(identity_map):
    return [make_semgrep_finding_summary(identity_map[k]) for k in sorted(identity_map.keys())]


def run_semgrep(repo_path, targets, config_path):
    cmd = [
        "semgrep",
        "scan",
        "--config",
        str(config_path),
        "--json",
        *targets,
    ]

    started = time.perf_counter()
    result = run_command(cmd, cwd=repo_path)
    finished = time.perf_counter()

    duration_seconds = round(finished - started, 4)
    findings_count = extract_semgrep_findings_count(result.stdout)

    return {
        "tool": "semgrep",
        "targets": targets,
        "returncode": result.returncode,
        "duration_seconds": duration_seconds,
        "findings_count": findings_count,
        "stderr": result.stderr.strip(),
        "stdout_json": result.stdout.strip(),
    }


# ---------------------------
# Gitleaks helpers
# ---------------------------

def safe_parse_gitleaks_results(stdout_text):
    if not stdout_text or not stdout_text.strip():
        return []

    try:
        payload = json.loads(stdout_text)
    except json.JSONDecodeError:
        return []

    return payload if isinstance(payload, list) else []


def gitleaks_finding_identity(finding):
    rule_id = finding.get("RuleID", "")
    file_path = finding.get("File", "")
    start_line = finding.get("StartLine")
    end_line = finding.get("EndLine")
    secret = finding.get("Secret", "")
    commit = finding.get("Commit", "")

    return (rule_id, file_path, start_line, end_line, secret, commit)


def make_gitleaks_finding_summary(finding):
    return {
        "rule_id": finding.get("RuleID", ""),
        "path": finding.get("File", ""),
        "start_line": finding.get("StartLine"),
        "end_line": finding.get("EndLine"),
        "description": finding.get("Description", ""),
    }


def gitleaks_results_to_identity_map(stdout_text):
    results = safe_parse_gitleaks_results(stdout_text)
    return {gitleaks_finding_identity(f): f for f in results}


def summarize_gitleaks_identity_map(identity_map):
    return [make_gitleaks_finding_summary(identity_map[k]) for k in sorted(identity_map.keys())]


def run_gitleaks(repo_path, targets):
    """
    Gitleaks không hỗ trợ quét nhiều file bằng cách truyền trực tiếp như semgrep.
    Cách ổn định nhất:
    - fullscan: gitleaks dir <repo>
    - incremental: copy các file thay đổi sang temp dir rồi quét temp dir
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        scan_root = None

        if targets == ["."]:
            scan_root = str(repo_path)
        else:
            temp_root = Path(tmpdir)
            for rel_path in targets:
                src = repo_path / rel_path
                if not src.exists() or not src.is_file():
                    continue
                dst = temp_root / rel_path
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())
            scan_root = str(temp_root)

        cmd = [
            "gitleaks",
            "dir",
            scan_root,
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
        ]

        started = time.perf_counter()
        result = run_command(cmd, cwd=repo_path)
        finished = time.perf_counter()

        duration_seconds = round(finished - started, 4)
        findings = safe_parse_gitleaks_results(result.stdout)
        findings_count = len(findings)

        return {
            "tool": "gitleaks",
            "targets": targets,
            "returncode": result.returncode,
            "duration_seconds": duration_seconds,
            "findings_count": findings_count,
            "stderr": result.stderr.strip(),
            "stdout_json": result.stdout.strip(),
        }


# ---------------------------
# CSV helper
# ---------------------------

def make_csv_row(tool_name, commit, parent_commit, mode, trigger_reason, changed_files, scan_result):
    return {
        "tool": tool_name,
        "commit": commit,
        "parent_commit": parent_commit,
        "mode": mode,
        "trigger_reason": trigger_reason,
        "changed_files_count": len(changed_files),
        "scan_targets_count": len(scan_result["targets"]),
        "duration_seconds": f"{scan_result['duration_seconds']:.4f}".replace(".", ","),
        "findings_count": scan_result["findings_count"],
        "returncode": scan_result["returncode"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Historical replay for incremental/full Semgrep and Gitleaks scanning"
    )
    parser.add_argument("--repo-path", required=True, help="Path to local git repository")
    parser.add_argument("--config", required=True, help="Semgrep config file or rules directory")
    parser.add_argument("--limit", type=int, default=20, help="Number of recent non-merge commits")
    parser.add_argument(
        "--max-changed-files",
        type=int,
        default=DEFAULT_MAX_CHANGED_FILES,
        help="If changed files exceed this threshold, run fullscan",
    )
    parser.add_argument(
        "--output-json",
        default="replay_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--output-csv",
        default="replay_metrics.csv",
        help="Output CSV metrics path",
    )
    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    config_path = Path(args.config).resolve()

    if not repo_path.exists():
        print(f"Repository path does not exist: {repo_path}", file=sys.stderr)
        sys.exit(1)

    if not config_path.exists():
        print(f"Semgrep config path does not exist: {config_path}", file=sys.stderr)
        sys.exit(1)

    ensure_clean_worktree(repo_path)

    original_ref = get_current_ref(repo_path)
    json_report = []
    csv_rows = []

    try:
        commits = get_last_non_merge_commits(repo_path, args.limit)

        if len(commits) < 2:
            raise RuntimeError("Not enough commits to replay.")

        for commit in commits:
            parent_commit = get_parent_commit(repo_path, commit)
            if not parent_commit:
                continue

            changed_files = get_changed_files(repo_path, parent_commit, commit)
            mode, trigger_reason = decide_scan_mode(changed_files, args.max_changed_files)

            print(f"Processing {commit} -> {mode}")

            # 1) Scan full trên commit cha làm baseline cho cả 2 tool
            checkout_detached(repo_path, parent_commit)

            parent_semgrep_full_result = run_semgrep(
                repo_path=repo_path,
                targets=["."],
                config_path=config_path,
            )
            parent_semgrep_full_map = semgrep_results_to_identity_map(
                parent_semgrep_full_result["stdout_json"]
            )

            parent_gitleaks_full_result = run_gitleaks(
                repo_path=repo_path,
                targets=["."],
            )
            parent_gitleaks_full_map = gitleaks_results_to_identity_map(
                parent_gitleaks_full_result["stdout_json"]
            )

            # 2) Quay lại current commit
            checkout_detached(repo_path, commit)
            existing_changed_files = filter_existing_files(repo_path, changed_files)

            commit_entry = {
                "commit": commit,
                "parent_commit": parent_commit,
                "changed_files": changed_files,
                "decision": {
                    "mode": mode,
                    "reason": trigger_reason,
                },
                "tools": {
                    "semgrep": {
                        "scans": [],
                        "comparisons": {},
                    },
                    "gitleaks": {
                        "scans": [],
                        "comparisons": {},
                    },
                },
            }

            if mode == "fullscan":
                current_semgrep_full_result = run_semgrep(
                    repo_path=repo_path,
                    targets=["."],
                    config_path=config_path,
                )
                current_semgrep_full_map = semgrep_results_to_identity_map(
                    current_semgrep_full_result["stdout_json"]
                )
                semgrep_delta_map = diff_identity_maps(
                    current_semgrep_full_map,
                    parent_semgrep_full_map,
                )

                current_gitleaks_full_result = run_gitleaks(
                    repo_path=repo_path,
                    targets=["."],
                )
                current_gitleaks_full_map = gitleaks_results_to_identity_map(
                    current_gitleaks_full_result["stdout_json"]
                )
                gitleaks_delta_map = diff_identity_maps(
                    current_gitleaks_full_map,
                    parent_gitleaks_full_map,
                )

                commit_entry["tools"]["semgrep"]["scans"].append({
                    "mode": "fullscan",
                    "targets": current_semgrep_full_result["targets"],
                    "returncode": current_semgrep_full_result["returncode"],
                    "duration_seconds": current_semgrep_full_result["duration_seconds"],
                    "findings_count": current_semgrep_full_result["findings_count"],
                    "stderr": current_semgrep_full_result["stderr"],
                })
                commit_entry["tools"]["semgrep"]["comparisons"]["current_full_minus_parent_full"] = {
                    "parent_commit": parent_commit,
                    "findings": summarize_semgrep_identity_map(semgrep_delta_map),
                }

                commit_entry["tools"]["gitleaks"]["scans"].append({
                    "mode": "fullscan",
                    "targets": current_gitleaks_full_result["targets"],
                    "returncode": current_gitleaks_full_result["returncode"],
                    "duration_seconds": current_gitleaks_full_result["duration_seconds"],
                    "findings_count": current_gitleaks_full_result["findings_count"],
                    "stderr": current_gitleaks_full_result["stderr"],
                })
                commit_entry["tools"]["gitleaks"]["comparisons"]["current_full_minus_parent_full"] = {
                    "parent_commit": parent_commit,
                    "findings": summarize_gitleaks_identity_map(gitleaks_delta_map),
                }

                csv_rows.append(
                    make_csv_row(
                        tool_name="semgrep",
                        commit=commit,
                        parent_commit=parent_commit,
                        mode="fullscan",
                        trigger_reason=trigger_reason,
                        changed_files=changed_files,
                        scan_result=current_semgrep_full_result,
                    )
                )
                csv_rows.append(
                    make_csv_row(
                        tool_name="gitleaks",
                        commit=commit,
                        parent_commit=parent_commit,
                        mode="fullscan",
                        trigger_reason=trigger_reason,
                        changed_files=changed_files,
                        scan_result=current_gitleaks_full_result,
                    )
                )

            else:
                if not existing_changed_files:
                    current_semgrep_full_result = run_semgrep(
                        repo_path=repo_path,
                        targets=["."],
                        config_path=config_path,
                    )
                    current_semgrep_full_map = semgrep_results_to_identity_map(
                        current_semgrep_full_result["stdout_json"]
                    )
                    semgrep_delta_map = diff_identity_maps(
                        current_semgrep_full_map,
                        parent_semgrep_full_map,
                    )

                    current_gitleaks_full_result = run_gitleaks(
                        repo_path=repo_path,
                        targets=["."],
                    )
                    current_gitleaks_full_map = gitleaks_results_to_identity_map(
                        current_gitleaks_full_result["stdout_json"]
                    )
                    gitleaks_delta_map = diff_identity_maps(
                        current_gitleaks_full_map,
                        parent_gitleaks_full_map,
                    )

                    commit_entry["decision"] = {
                        "mode": "fullscan",
                        "reason": "no_existing_changed_files_after_checkout",
                    }

                    commit_entry["tools"]["semgrep"]["scans"].append({
                        "mode": "fullscan",
                        "targets": current_semgrep_full_result["targets"],
                        "returncode": current_semgrep_full_result["returncode"],
                        "duration_seconds": current_semgrep_full_result["duration_seconds"],
                        "findings_count": current_semgrep_full_result["findings_count"],
                        "stderr": current_semgrep_full_result["stderr"],
                    })
                    commit_entry["tools"]["semgrep"]["comparisons"]["current_full_minus_parent_full"] = {
                        "parent_commit": parent_commit,
                        "findings": summarize_semgrep_identity_map(semgrep_delta_map),
                    }

                    commit_entry["tools"]["gitleaks"]["scans"].append({
                        "mode": "fullscan",
                        "targets": current_gitleaks_full_result["targets"],
                        "returncode": current_gitleaks_full_result["returncode"],
                        "duration_seconds": current_gitleaks_full_result["duration_seconds"],
                        "findings_count": current_gitleaks_full_result["findings_count"],
                        "stderr": current_gitleaks_full_result["stderr"],
                    })
                    commit_entry["tools"]["gitleaks"]["comparisons"]["current_full_minus_parent_full"] = {
                        "parent_commit": parent_commit,
                        "findings": summarize_gitleaks_identity_map(gitleaks_delta_map),
                    }

                    csv_rows.append(
                        make_csv_row(
                            tool_name="semgrep",
                            commit=commit,
                            parent_commit=parent_commit,
                            mode="fullscan",
                            trigger_reason="no_existing_changed_files_after_checkout",
                            changed_files=changed_files,
                            scan_result=current_semgrep_full_result,
                        )
                    )
                    csv_rows.append(
                        make_csv_row(
                            tool_name="gitleaks",
                            commit=commit,
                            parent_commit=parent_commit,
                            mode="fullscan",
                            trigger_reason="no_existing_changed_files_after_checkout",
                            changed_files=changed_files,
                            scan_result=current_gitleaks_full_result,
                        )
                    )
                else:
                    incremental_semgrep_result = run_semgrep(
                        repo_path=repo_path,
                        targets=existing_changed_files,
                        config_path=config_path,
                    )
                    current_semgrep_full_result = run_semgrep(
                        repo_path=repo_path,
                        targets=["."],
                        config_path=config_path,
                    )

                    incremental_semgrep_map = semgrep_results_to_identity_map(
                        incremental_semgrep_result["stdout_json"]
                    )
                    current_semgrep_full_map = semgrep_results_to_identity_map(
                        current_semgrep_full_result["stdout_json"]
                    )

                    semgrep_common_map = intersect_identity_maps(
                        incremental_semgrep_map,
                        current_semgrep_full_map,
                    )
                    semgrep_delta_map = diff_identity_maps(
                        current_semgrep_full_map,
                        parent_semgrep_full_map,
                    )
                    semgrep_incremental_vs_delta_map = intersect_identity_maps(
                        incremental_semgrep_map,
                        semgrep_delta_map,
                    )

                    incremental_gitleaks_result = run_gitleaks(
                        repo_path=repo_path,
                        targets=existing_changed_files,
                    )
                    current_gitleaks_full_result = run_gitleaks(
                        repo_path=repo_path,
                        targets=["."],
                    )

                    incremental_gitleaks_map = gitleaks_results_to_identity_map(
                        incremental_gitleaks_result["stdout_json"]
                    )
                    current_gitleaks_full_map = gitleaks_results_to_identity_map(
                        current_gitleaks_full_result["stdout_json"]
                    )

                    gitleaks_common_map = intersect_identity_maps(
                        incremental_gitleaks_map,
                        current_gitleaks_full_map,
                    )
                    gitleaks_delta_map = diff_identity_maps(
                        current_gitleaks_full_map,
                        parent_gitleaks_full_map,
                    )
                    gitleaks_incremental_vs_delta_map = intersect_identity_maps(
                        incremental_gitleaks_map,
                        gitleaks_delta_map,
                    )

                    commit_entry["tools"]["semgrep"]["scans"].append({
                        "mode": "incremental",
                        "targets": incremental_semgrep_result["targets"],
                        "returncode": incremental_semgrep_result["returncode"],
                        "duration_seconds": incremental_semgrep_result["duration_seconds"],
                        "findings_count": incremental_semgrep_result["findings_count"],
                        "stderr": incremental_semgrep_result["stderr"],
                    })
                    commit_entry["tools"]["semgrep"]["scans"].append({
                        "mode": "fullscan_compare",
                        "targets": current_semgrep_full_result["targets"],
                        "returncode": current_semgrep_full_result["returncode"],
                        "duration_seconds": current_semgrep_full_result["duration_seconds"],
                        "findings_count": current_semgrep_full_result["findings_count"],
                        "stderr": current_semgrep_full_result["stderr"],
                    })
                    commit_entry["tools"]["semgrep"]["comparisons"]["incremental_full_common"] = (
                        summarize_semgrep_identity_map(semgrep_common_map)
                    )
                    commit_entry["tools"]["semgrep"]["comparisons"]["current_full_minus_parent_full"] = {
                        "parent_commit": parent_commit,
                        "findings": summarize_semgrep_identity_map(semgrep_delta_map),
                    }
                    commit_entry["tools"]["semgrep"]["comparisons"]["incremental_vs_full_delta_common"] = {
                        "parent_commit": parent_commit,
                        "findings": summarize_semgrep_identity_map(semgrep_incremental_vs_delta_map),
                    }

                    commit_entry["tools"]["gitleaks"]["scans"].append({
                        "mode": "incremental",
                        "targets": incremental_gitleaks_result["targets"],
                        "returncode": incremental_gitleaks_result["returncode"],
                        "duration_seconds": incremental_gitleaks_result["duration_seconds"],
                        "findings_count": incremental_gitleaks_result["findings_count"],
                        "stderr": incremental_gitleaks_result["stderr"],
                    })
                    commit_entry["tools"]["gitleaks"]["scans"].append({
                        "mode": "fullscan_compare",
                        "targets": current_gitleaks_full_result["targets"],
                        "returncode": current_gitleaks_full_result["returncode"],
                        "duration_seconds": current_gitleaks_full_result["duration_seconds"],
                        "findings_count": current_gitleaks_full_result["findings_count"],
                        "stderr": current_gitleaks_full_result["stderr"],
                    })
                    commit_entry["tools"]["gitleaks"]["comparisons"]["incremental_full_common"] = (
                        summarize_gitleaks_identity_map(gitleaks_common_map)
                    )
                    commit_entry["tools"]["gitleaks"]["comparisons"]["current_full_minus_parent_full"] = {
                        "parent_commit": parent_commit,
                        "findings": summarize_gitleaks_identity_map(gitleaks_delta_map),
                    }
                    commit_entry["tools"]["gitleaks"]["comparisons"]["incremental_vs_full_delta_common"] = {
                        "parent_commit": parent_commit,
                        "findings": summarize_gitleaks_identity_map(gitleaks_incremental_vs_delta_map),
                    }

                    csv_rows.append(
                        make_csv_row(
                            tool_name="semgrep",
                            commit=commit,
                            parent_commit=parent_commit,
                            mode="incremental",
                            trigger_reason=trigger_reason,
                            changed_files=changed_files,
                            scan_result=incremental_semgrep_result,
                        )
                    )
                    csv_rows.append(
                        make_csv_row(
                            tool_name="semgrep",
                            commit=commit,
                            parent_commit=parent_commit,
                            mode="fullscan_compare",
                            trigger_reason=trigger_reason,
                            changed_files=changed_files,
                            scan_result=current_semgrep_full_result,
                        )
                    )
                    csv_rows.append(
                        make_csv_row(
                            tool_name="gitleaks",
                            commit=commit,
                            parent_commit=parent_commit,
                            mode="incremental",
                            trigger_reason=trigger_reason,
                            changed_files=changed_files,
                            scan_result=incremental_gitleaks_result,
                        )
                    )
                    csv_rows.append(
                        make_csv_row(
                            tool_name="gitleaks",
                            commit=commit,
                            parent_commit=parent_commit,
                            mode="fullscan_compare",
                            trigger_reason=trigger_reason,
                            changed_files=changed_files,
                            scan_result=current_gitleaks_full_result,
                        )
                    )

            json_report.append(commit_entry)

        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(json_report, f, ensure_ascii=False, indent=2)

        fieldnames = [
            "tool",
            "commit",
            "parent_commit",
            "mode",
            "trigger_reason",
            "changed_files_count",
            "scan_targets_count",
            "duration_seconds",
            "findings_count",
            "returncode",
        ]

        with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
            writer.writeheader()
            writer.writerows(csv_rows)

        print("Done.")
        print(f"JSON report: {args.output_json}")
        print(f"CSV report : {args.output_csv}")

    finally:
        restore_ref(repo_path, original_ref)


if __name__ == "__main__":
    main()