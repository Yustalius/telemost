#!/usr/bin/env python3

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_jsonl(path: Path):
    records = []
    try:
        with path.open(encoding="utf-8") as source:
            for line in source:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return records


def percentile(values, percentile_value):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile_value * len(ordered)) - 1)
    return round(ordered[index], 3)


def distribution(values, unit="ms"):
    return {
        "count": len(values),
        f"p50_{unit}": percentile(values, 0.50),
        f"p95_{unit}": percentile(values, 0.95),
        f"p99_{unit}": percentile(values, 0.99),
    }


def write_measurements(path: Path, measurements):
    columns = [
        "source",
        "segment",
        "pass",
        "scenario",
        "test_id",
        "concurrency",
        "ok",
        "http_code",
        "dns_ms",
        "connect_ms",
        "tls_ms",
        "first_byte_ms",
        "total_ms",
        "bytes_up",
        "bytes_down",
        "useful_bps",
        "error",
    ]
    with path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(measurements)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()
    result_dir = args.result_dir

    rows = []
    path_records = load_jsonl(result_dir / "path-measurements.jsonl")
    for item in path_records:
        rows.append(
            {
                "source": "curl",
                "segment": item.get("segment"),
                "pass": item.get("pass"),
                "scenario": "http_probe",
                "test_id": item.get("test_id"),
                "concurrency": 1,
                "ok": item.get("ok"),
                "http_code": item.get("http_code"),
                "dns_ms": item.get("time_namelookup_ms"),
                "connect_ms": item.get("time_connect_ms"),
                "tls_ms": item.get("time_appconnect_ms"),
                "first_byte_ms": item.get("time_starttransfer_ms"),
                "total_ms": item.get("time_total_ms"),
                "bytes_up": item.get("size_upload", 0),
                "bytes_down": item.get("size_download", 0),
                "useful_bps": item.get("speed_download", 0),
                "error": item.get("error"),
            }
        )

    vps_job = load_json(result_dir / "vps-run.json", {})
    for item in vps_job.get("measurements", []):
        total_us = item.get("total_us") or 0
        useful_bytes = max(item.get("bytes_up") or 0, item.get("bytes_down") or 0)
        rows.append(
            {
                "source": "reverse",
                "segment": "vps_reverse_mac_target",
                "pass": item.get("pass"),
                "scenario": item.get("scenario"),
                "test_id": item.get("test_id"),
                "concurrency": item.get("concurrency"),
                "ok": item.get("ok"),
                "http_code": None,
                "dns_ms": None,
                "connect_ms": round((item.get("connect_us") or 0) / 1000, 3),
                "tls_ms": None,
                "first_byte_ms": (
                    round(item["first_byte_us"] / 1000, 3)
                    if item.get("first_byte_us") is not None
                    else None
                ),
                "total_ms": round(total_us / 1000, 3),
                "bytes_up": item.get("bytes_up", 0),
                "bytes_down": item.get("bytes_down", 0),
                "useful_bps": (
                    round(useful_bytes * 1_000_000 / total_us, 3)
                    if useful_bytes and total_us
                    else 0
                ),
                "error": item.get("error"),
            }
        )

    write_measurements(result_dir / "measurements.csv", rows)
    client_events = load_jsonl(result_dir / "client-events.jsonl")
    event_counts = Counter(item.get("event", "unknown") for item in client_events)
    status_counts = Counter(
        str(item["status"])
        for item in client_events
        if item.get("status") is not None
    )
    read_sizes = [
        item.get("bytes", 0)
        for item in client_events
        if item.get("event") in {"tcp_read", "tcp_write"}
    ]
    body_sizes = [
        item.get("response_bytes", 0)
        for item in client_events
        if item.get("event") == "v2_recv"
    ]
    ack_wait = [
        item.get("ack_wait_us", 0) / 1000
        for item in client_events
        if item.get("event") == "v2_send" and item.get("ok")
    ]
    resource_rows = []
    try:
        with (result_dir / "mac-resources.csv").open(encoding="utf-8") as source:
            resource_rows = list(csv.DictReader(source))
    except FileNotFoundError:
        pass

    grouped = defaultdict(list)
    for row in rows:
        if row.get("ok") in {True, "true", "True", 1} and row.get("total_ms") is not None:
            grouped[f"{row['segment']}::{row['scenario']}"].append(float(row["total_ms"]))
    latency = {name: distribution(values) for name, values in sorted(grouped.items())}
    failures = [row for row in rows if row.get("ok") not in {True, "true", "True", 1}]
    rss_values = [int(float(row["rss_kib"])) for row in resource_rows if row.get("rss_kib")]
    cpu_values = [float(row["cpu_percent"]) for row in resource_rows if row.get("cpu_percent")]
    vps_samples = vps_job.get("resources", [])
    first_vps = vps_samples[0] if vps_samples else {}
    last_vps = vps_samples[-1] if vps_samples else {}

    def counter_delta(name):
        if first_vps.get(name) is None or last_vps.get(name) is None:
            return None
        return max(0, int(last_vps[name]) - int(first_vps[name]))

    report = {
        "schema": 1,
        "profile": "A-v2-baseline",
        "run_id": vps_job.get("run_id"),
        "status": (
            "complete"
            if not failures and vps_job.get("status") == "complete"
            else "complete_with_findings"
            if vps_job.get("status") == "complete"
            else "incomplete"
        ),
        "completed_checks": len(rows),
        "failed_checks": len(failures),
        "findings": [
            {
                "segment": row.get("segment"),
                "scenario": row.get("scenario"),
                "test_id": row.get("test_id"),
                "error": row.get("error"),
            }
            for row in failures
        ],
        "skipped_checks": vps_job.get("skipped_checks", []),
        "latency": latency,
        "transport": {
            "client_event_counts": dict(sorted(event_counts.items())),
            "http_status_counts": dict(sorted(status_counts.items())),
            "tcp_read_size": distribution(read_sizes, "bytes"),
            "downstream_body_size": distribution(body_sizes, "bytes"),
            "ack_wait": distribution(ack_wait),
            "empty_recv": sum(
                1
                for item in client_events
                if item.get("event") == "v2_recv" and item.get("empty")
            ),
            "retries": event_counts.get("v2_retry", 0),
            "vps_http_gets": counter_delta("http_gets"),
            "vps_http_posts": counter_delta("http_posts"),
            "vps_new_http_connections": counter_delta("http_connections_total"),
        },
        "resources": {
            "mac_client_rss_kib_max": max(rss_values) if rss_values else None,
            "mac_client_cpu_percent_max": max(cpu_values) if cpu_values else None,
            "vps_http_connections_active_max": max(
                (sample.get("http_connections_active", 0) for sample in vps_samples),
                default=None,
            ),
            "vps_sessions_max": max(
                (sample.get("v2_sessions", 0) for sample in vps_samples), default=None
            ),
            "vps_rss_kib_max": max(
                (sample["rss_kib"] for sample in vps_samples if sample.get("rss_kib") is not None),
                default=None,
            ),
            "vps_cpu_ticks": counter_delta("cpu_ticks"),
            "vps_samples": vps_samples,
        },
        "sso_routes": load_jsonl(result_dir / "sso-routes.jsonl"),
    }
    (result_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# Reverse httptun diagnostic summary",
        "",
        f"- Run: `{report['run_id'] or 'unknown'}`",
        f"- Profile: `{report['profile']}`",
        f"- Status: **{report['status']}**",
        f"- Checks: {report['completed_checks']}, failed: {report['failed_checks']}",
        f"- V2 retries: {report['transport']['retries']}; empty recv: {report['transport']['empty_recv']}",
        f"- VPS HTTP GET/POST: {report['transport']['vps_http_gets']}/{report['transport']['vps_http_posts']}; new connections: {report['transport']['vps_new_http_connections']}",
        "",
        "## Latency",
        "",
        "| Segment / scenario | n | p50 ms | p95 ms | p99 ms |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, stats in latency.items():
        lines.append(
            f"| {name} | {stats['count']} | {stats['p50_ms']} | {stats['p95_ms']} | {stats['p99_ms']} |"
        )
    if report["findings"]:
        lines.extend(["", "## Findings", ""])
        for finding in report["findings"]:
            lines.append(
                f"- `{finding['segment']}::{finding['scenario']}`: "
                f"{finding['error'] or 'check failed'}"
            )
    lines.extend(
        [
            "",
            "## Resource peaks",
            "",
            f"- Mac client RSS: {report['resources']['mac_client_rss_kib_max']} KiB",
            f"- Mac client CPU: {report['resources']['mac_client_cpu_percent_max']}%",
            f"- VPS RSS: {report['resources']['vps_rss_kib_max']} KiB",
            f"- VPS active sessions: {report['resources']['vps_sessions_max']}",
            "",
            "## Scope",
            "",
            "This is the A/v2 baseline. No optimization is selected at this stage. "
            "Transport fault injection is covered by the local suite; optional packet capture is separate.",
        ]
    )
    (result_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
