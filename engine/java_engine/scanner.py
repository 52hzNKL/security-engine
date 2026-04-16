import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def run_command(cmd: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------
# Semgrep helpers
# ---------------------------

def extract_semgrep_findings_count(stdout_text: str) -> int:
    if not stdout_text.strip():
        return 0

    try:
        payload = json.loads(stdout_text)
        return len(payload.get("results", []))
    except json.JSONDecodeError:
        return -1


def safe_parse_semgrep_results(stdout_text: str) -> List[Dict[str, Any]]:
    if not stdout_text or not stdout_text.strip():
        return []

    try:
        payload = json.loads(stdout_text)
    except json.JSONDecodeError:
        return []

    results = payload.get("results", [])
    return results if isinstance(results, list) else []


def run_semgrep(repo_path: Path, targets: List[str], config_path: Path) -> Dict[str, Any]:
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
        "targets": list(targets),
        "returncode": result.returncode,
        "duration_seconds": duration_seconds,
        "findings_count": findings_count,
        "stderr": result.stderr.strip(),
        "stdout_json": result.stdout.strip(),
    }


# ---------------------------
# Gitleaks helpers
# ---------------------------

def safe_parse_gitleaks_results(stdout_text: str) -> List[Dict[str, Any]]:
    if not stdout_text or not stdout_text.strip():
        return []

    try:
        payload = json.loads(stdout_text)
    except json.JSONDecodeError:
        return []

    return payload if isinstance(payload, list) else []


def run_gitleaks(repo_path: Path, targets: List[str]) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
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

        return {
            "tool": "gitleaks",
            "targets": list(targets),
            "returncode": result.returncode,
            "duration_seconds": duration_seconds,
            "findings_count": len(findings),
            "stderr": result.stderr.strip(),
            "stdout_json": result.stdout.strip(),
        }