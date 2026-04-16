import json
from pathlib import Path
from typing import Any, Dict, List


def build_scan_report(
    commit: str,
    parent_commit: str,
    mode: str,
    trigger_reason: str,
    changed_files: List[str],
    targets: List[str],
    tool_reports: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "commit": commit,
        "parent_commit": parent_commit,
        "decision": {
            "mode": mode,
            "reason": trigger_reason,
        },
        "changed_files": list(changed_files),
        "targets": list(targets),
        "tools": list(tool_reports),
    }


def write_json_report(report: Dict[str, Any], output_path: str | Path) -> None:
    output = Path(output_path)
    with output.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)