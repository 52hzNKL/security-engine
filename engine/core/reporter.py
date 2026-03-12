import csv
import json
from typing import Dict, List


def print_runtime_summary(language: str, mode: str, reason: str, diff_result, scan_result: Dict) -> None:
    print("=== Security Scan Summary ===")
    print(f"language             : {language}")
    print(f"mode                 : {mode}")
    print(f"reason               : {reason}")
    print(f"base_ref             : {diff_result.base_ref}")
    print(f"head_ref             : {diff_result.head_ref}")
    print(f"effective_base_ref   : {diff_result.effective_base_ref}")
    print(f"effective_head_ref   : {diff_result.effective_head_ref}")
    print(f"changed_files_count  : {len(diff_result.all_changed_files)}")
    print(
        f"scanned_files_count  : "
        f"{1 if mode == 'full' else len(diff_result.existing_changed_files)}"
    )
    print(f"returncode           : {scan_result['returncode']}")
    print(f"findings_count       : {scan_result['findings_count']}")
    print(f"duration_seconds     : {scan_result['duration_seconds']}")
    print(f"duration_minutes     : {scan_result['duration_minutes']}")

    if diff_result.all_changed_files:
        print("changed_files:")
        for file_path in diff_result.all_changed_files:
            status = diff_result.status_by_file.get(file_path, "?")
            print(f"  - [{status}] {file_path}")

    if mode == "incremental" and diff_result.existing_changed_files:
        print("incremental_targets:")
        for file_path in diff_result.existing_changed_files:
            print(f"  - {file_path}")

    if scan_result.get("stderr"):
        print("stderr:")
        print(scan_result["stderr"])


def build_benchmark_row(
    repo_name: str,
    language: str,
    commit: str,
    parent_commit: str,
    reason: str,
    diff_result,
    incremental_result: Dict,
    full_result: Dict,
    comparison_metrics: Dict,
) -> Dict:
    return {
        "repo": repo_name,
        "language": language,
        "commit": commit,
        "parent_commit": parent_commit,
        "reason": reason,
        "changed_files_count": len(diff_result.all_changed_files),
        "scanned_files_count": len(diff_result.existing_changed_files),
        "changed_files": diff_result.all_changed_files,
        "scanned_files": diff_result.existing_changed_files,
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
        "time_saved_seconds": comparison_metrics["time_saved_seconds"],
        "time_saved_minutes": comparison_metrics["time_saved_minutes"],
        "speedup_ratio": comparison_metrics["speedup_ratio"],
        "incremental_vs_full_time_ratio": comparison_metrics["incremental_vs_full_time_ratio"],
        "findings_diff": comparison_metrics["findings_diff"],
    }


def write_csv(rows: List[Dict], output_csv: str) -> None:
    fieldnames = [
        "repo",
        "language",
        "commit",
        "parent_commit",
        "reason",
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
        "time_saved_seconds",
        "time_saved_minutes",
        "speedup_ratio",
        "incremental_vs_full_time_ratio",
        "findings_diff",
        "changed_files",
        "scanned_files",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            row_copy = row.copy()
            row_copy["changed_files"] = ";".join(row["changed_files"])
            row_copy["scanned_files"] = ";".join(row["scanned_files"])
            writer.writerow(row_copy)


def write_json(rows: List[Dict], output_json: str) -> None:
    with open(output_json, "w", encoding="utf-8") as file_obj:
        json.dump(rows, file_obj, ensure_ascii=False, indent=2)