import argparse
import json
import sys
from pathlib import Path

from core.diff import build_diff_result
from core.decision import finalize_scan_mode, DEFAULT_MAX_CHANGED_FILES
from core.metrics import build_scan_metrics, scan_metrics_to_dict
from core.reporter import build_scan_report, write_json_report
from python_engine.scanner import run_semgrep, run_gitleaks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Runtime Python security scanning engine"
    )
    parser.add_argument("--repo-path", required=True, help="Path to local git repository")
    parser.add_argument("--parent-commit", required=True, help="Base commit for diff")
    parser.add_argument("--commit", required=True, help="Current commit to scan")
    parser.add_argument("--config", required=True, help="Semgrep config file or rules directory")
    parser.add_argument(
        "--max-changed-files",
        type=int,
        default=DEFAULT_MAX_CHANGED_FILES,
        help="Threshold for switching from incremental scan to fullscan",
    )
    parser.add_argument(
        "--report-output",
        default="python_scan_report.json",
        help="Path to output runtime scan report",
    )
    parser.add_argument(
        "--metrics-output",
        default="python_scan_metrics.json",
        help="Path to output runtime scan metrics",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    repo_path = Path(args.repo_path).resolve()
    config_path = Path(args.config).resolve()

    if not repo_path.exists():
        print(f"Repository path does not exist: {repo_path}", file=sys.stderr)
        sys.exit(1)

    if not config_path.exists():
        print(f"Semgrep config path does not exist: {config_path}", file=sys.stderr)
        sys.exit(1)

    diff_result = build_diff_result(
        repo_path=str(repo_path),
        parent_commit=args.parent_commit,
        commit=args.commit,
    )

    decision = finalize_scan_mode(
        changed_files=diff_result.changed_files,
        existing_changed_files=diff_result.existing_changed_files,
        max_changed_files=args.max_changed_files,
    )

    if decision.mode == "fullscan":
        targets = ["."]
    else:
        targets = diff_result.existing_changed_files

    semgrep_result = run_semgrep(
        repo_path=repo_path,
        targets=targets,
        config_path=config_path,
    )

    gitleaks_result = run_gitleaks(
        repo_path=repo_path,
        targets=targets,
    )

    semgrep_metrics = build_scan_metrics(
        tool_name="semgrep",
        mode=decision.mode,
        trigger_reason=decision.reason,
        scan_result=semgrep_result,
    )
    gitleaks_metrics = build_scan_metrics(
        tool_name="gitleaks",
        mode=decision.mode,
        trigger_reason=decision.reason,
        scan_result=gitleaks_result,
    )

    report = build_scan_report(
        commit=args.commit,
        parent_commit=args.parent_commit,
        mode=decision.mode,
        trigger_reason=decision.reason,
        changed_files=diff_result.changed_files,
        targets=targets,
        tool_reports=[
            {
                "tool": "semgrep",
                "returncode": semgrep_result["returncode"],
                "findings_count": semgrep_result["findings_count"],
                "duration_seconds": semgrep_result["duration_seconds"],
                "stderr": semgrep_result["stderr"],
                "report": semgrep_result["stdout_json"],
            },
            {
                "tool": "gitleaks",
                "returncode": gitleaks_result["returncode"],
                "findings_count": gitleaks_result["findings_count"],
                "duration_seconds": gitleaks_result["duration_seconds"],
                "stderr": gitleaks_result["stderr"],
                "report": gitleaks_result["stdout_json"],
            },
        ],
    )

    write_json_report(report, args.report_output)

    metrics_payload = {
        "commit": args.commit,
        "parent_commit": args.parent_commit,
        "mode": decision.mode,
        "trigger_reason": decision.reason,
        "changed_files_count": len(diff_result.changed_files),
        "targets_count": len(targets),
        "tools": [
            scan_metrics_to_dict(semgrep_metrics),
            scan_metrics_to_dict(gitleaks_metrics),
        ],
    }

    with open(args.metrics_output, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()