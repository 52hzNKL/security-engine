import argparse
import sys
from pathlib import Path

from engine.core.diff import get_changed_files
from engine.core.decision import decide_scan_mode
from engine.core.reporter import print_runtime_summary
from engine.java_engine.scanner import scan_full, scan_incremental


def validate_args(args):
    repo_path = Path(args.repo_path).resolve()
    if not repo_path.exists():
        raise RuntimeError(f"Repository path does not exist: {repo_path}")
    return repo_path


def main():
    parser = argparse.ArgumentParser(description="Java security scan engine")
    parser.add_argument("--repo-path", required=True, help="Path to target repository")
    parser.add_argument("--base-ref", required=True, help="Base git ref/sha")
    parser.add_argument("--head-ref", required=True, help="Head git ref/sha")
    parser.add_argument(
        "--config",
        default="semgrep_rules.yml",
        help="Scanner config path (local rules file or rules directory)",
    )
    parser.add_argument(
        "--use-merge-base",
        action="store_true",
        help="Use git merge-base(base_ref, head_ref) as effective base",
    )
    args = parser.parse_args()

    try:
        repo_path = validate_args(args)

        diff_result = get_changed_files(
            repo_path=str(repo_path),
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            use_merge_base=args.use_merge_base,
        )

        mode, reason = decide_scan_mode(
            language="java",
            changed_files=diff_result.all_changed_files,
        )

        if mode == "full":
            scan_result = scan_full(
                repo_path=str(repo_path),
                config=args.config,
            )
        else:
            if not diff_result.existing_changed_files:
                print("No existing changed files to scan incrementally.")
                print("This usually means all changed files were deleted.")
                sys.exit(0)

            scan_result = scan_incremental(
                repo_path=str(repo_path),
                targets=diff_result.existing_changed_files,
                config=args.config,
            )

        print_runtime_summary(
            language="java",
            mode=mode,
            reason=reason,
            diff_result=diff_result,
            scan_result=scan_result,
        )

        sys.exit(scan_result["returncode"])

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()