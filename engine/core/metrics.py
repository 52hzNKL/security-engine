from dataclasses import dataclass, asdict
from typing import Any, Dict


@dataclass
class ScanMetrics:
    tool: str
    mode: str
    targets_count: int
    duration_seconds: float
    findings_count: int
    returncode: int
    trigger_reason: str


def build_scan_metrics(
    tool_name: str,
    mode: str,
    trigger_reason: str,
    scan_result: Dict[str, Any],
) -> ScanMetrics:
    return ScanMetrics(
        tool=tool_name,
        mode=mode,
        targets_count=len(scan_result.get("targets", [])),
        duration_seconds=float(scan_result.get("duration_seconds", 0.0)),
        findings_count=int(scan_result.get("findings_count", 0)),
        returncode=int(scan_result.get("returncode", 0)),
        trigger_reason=trigger_reason,
    )


def scan_metrics_to_dict(metrics: ScanMetrics, decimal_comma: bool = False) -> Dict[str, Any]:
    payload = asdict(metrics)

    if decimal_comma:
        payload["duration_seconds"] = f"{metrics.duration_seconds:.4f}"
    else:
        payload["duration_seconds"] = round(metrics.duration_seconds, 4)

    return payload