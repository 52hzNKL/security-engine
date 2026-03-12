import json
import subprocess
import time
from typing import Dict, List


def run_command(cmd, cwd=None):
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _parse_findings_count(stdout: str) -> int:
    if not stdout.strip():
        return 0

    try:
        payload = json.loads(stdout)
        return len(payload.get("results", []))
    except json.JSONDecodeError:
        return -1


def _run_semgrep(repo_path: str, targets: List[str], config: str) -> Dict:
    cmd = ["semgrep", "scan", "--config", config, "--json", *targets]

    start = time.perf_counter()
    result = run_command(cmd, cwd=repo_path)
    end = time.perf_counter()

    elapsed_seconds = end - start

    return {
        "returncode": result.returncode,
        "duration_seconds": round(elapsed_seconds, 4),
        "duration_minutes": round(elapsed_seconds / 60, 4),
        "findings_count": _parse_findings_count(result.stdout),
        "stderr": result.stderr.strip(),
        "command": " ".join(cmd),
    }


def scan_full(repo_path: str, config: str) -> Dict:
    return _run_semgrep(
        repo_path=repo_path,
        targets=["."],
        config=config,
    )


def scan_incremental(repo_path: str, targets: List[str], config: str) -> Dict:
    if not targets:
        return {
            "returncode": 0,
            "duration_seconds": 0.0,
            "duration_minutes": 0.0,
            "findings_count": 0,
            "stderr": "",
            "command": "",
        }

    return _run_semgrep(
        repo_path=repo_path,
        targets=targets,
        config=config,
    )