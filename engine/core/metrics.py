from typing import Dict, Optional


def safe_divide(numerator: float, denominator: float) -> Optional[float]:
    if denominator == 0:
        return None
    return numerator / denominator


def compute_comparison_metrics(
    incremental_result: Dict,
    full_result: Dict,
) -> Dict:
    incremental_time_seconds = float(incremental_result.get("duration_seconds", 0.0))
    full_time_seconds = float(full_result.get("duration_seconds", 0.0))

    incremental_findings = int(incremental_result.get("findings_count", 0))
    full_findings = int(full_result.get("findings_count", 0))

    time_saved_seconds = full_time_seconds - incremental_time_seconds
    time_saved_minutes = time_saved_seconds / 60

    speedup_ratio = safe_divide(full_time_seconds, incremental_time_seconds)
    incremental_vs_full_time_ratio = safe_divide(incremental_time_seconds, full_time_seconds)

    findings_diff = full_findings - incremental_findings

    return {
        "incremental_time_seconds": round(incremental_time_seconds, 4),
        "full_time_seconds": round(full_time_seconds, 4),
        "time_saved_seconds": round(time_saved_seconds, 4),
        "time_saved_minutes": round(time_saved_minutes, 4),
        "speedup_ratio": round(speedup_ratio, 4) if speedup_ratio is not None else None,
        "incremental_vs_full_time_ratio": (
            round(incremental_vs_full_time_ratio, 4)
            if incremental_vs_full_time_ratio is not None
            else None
        ),
        "incremental_findings": incremental_findings,
        "full_findings": full_findings,
        "findings_diff": findings_diff,
        "incremental_returncode": int(incremental_result.get("returncode", 1)),
        "full_returncode": int(full_result.get("returncode", 1)),
    }