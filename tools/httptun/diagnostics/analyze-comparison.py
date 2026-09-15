#!/usr/bin/env python3

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


PROFILES = ["A-v2-baseline", "B-batch-64", "B-batch-128", "B-batch-256"]
PRIORITY_SCENARIOS = [
    "short_sequential",
    "parallel_short",
    "short_with_background",
    "short_with_slow_receiver",
    "background_download",
]


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_jsonl(path):
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


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(fraction * len(ordered)) - 1)], 3)


def distribution(values, unit="ms"):
    return {
        "count": len(values),
        f"p50_{unit}": percentile(values, 0.50),
        f"p95_{unit}": percentile(values, 0.95),
        f"p99_{unit}": percentile(values, 0.99),
    }


def delta_percent(candidate, baseline):
    if candidate is None or baseline in (None, 0):
        return None
    return round((candidate - baseline) * 100 / baseline, 2)


def counter_delta(samples, name):
    if not samples:
        return None
    first = samples[0].get(name)
    last = samples[-1].get(name)
    if first is None or last is None:
        return None
    return max(0, int(last) - int(first))


def load_resource_rows(path):
    try:
        with path.open(encoding="utf-8") as source:
            return list(csv.DictReader(source))
    except FileNotFoundError:
        return []


def profile_report(root, profile):
    runs = []
    measurements = []
    events = []
    mac_resources = []
    pass_latency = {}
    pass_operations = {}
    profile_root = root / "profiles" / profile
    for comparison_pass in (1, 2, 3):
        run_root = profile_root / f"pass-{comparison_pass}"
        job = load_json(run_root / "vps-run.json", {})
        run_events = load_jsonl(run_root / "client-events.jsonl")
        resource_rows = load_resource_rows(run_root / "mac-resources.csv")
        runs.append(job)
        events.extend(run_events)
        mac_resources.extend(resource_rows)
        grouped = defaultdict(list)
        for item in job.get("measurements", []):
            copy = dict(item)
            copy["comparison_pass"] = comparison_pass
            measurements.append(copy)
            if item.get("ok") and item.get("total_us") is not None:
                grouped[item.get("scenario")].append(item["total_us"] / 1000)
        pass_latency[str(comparison_pass)] = {
            scenario: distribution(values)
            for scenario, values in sorted(grouped.items())
        }
        samples = job.get("resources", [])
        gets = counter_delta(samples, "http_gets")
        posts = counter_delta(samples, "http_posts")
        pass_operations[str(comparison_pass)] = (
            gets + posts if gets is not None and posts is not None else None
        )

    grouped = defaultdict(list)
    for item in measurements:
        if item.get("ok") and item.get("total_us") is not None:
            grouped[item.get("scenario")].append(item["total_us"] / 1000)
    latency = {
        scenario: distribution(values) for scenario, values in sorted(grouped.items())
    }
    failures = [item for item in measurements if not item.get("ok")]
    known = [
        item
        for item in failures
        if item.get("scenario") == "half_close" and item.get("error") == "eof"
    ]
    unexpected = [item for item in failures if item not in known]
    event_counts = Counter(item.get("event", "unknown") for item in events)
    request_sizes = [
        item.get("request_bytes", 0)
        for item in events
        if item.get("event") == "v2_send" and item.get("ok")
    ]
    response_sizes = [
        item.get("response_bytes", 0)
        for item in events
        if item.get("event") == "v2_recv" and item.get("ok")
    ]
    fill_ratios = [
        float(item["fill_ratio"])
        for item in events
        if item.get("event") in {"v2_send", "v2_recv"}
        and item.get("ok")
        and item.get("fill_ratio") is not None
    ]
    ack_wait = [
        item.get("ack_wait_us", 0) / 1000
        for item in events
        if item.get("event") == "v2_send" and item.get("ok")
    ]
    gets = sum(counter_delta(run.get("resources", []), "http_gets") or 0 for run in runs)
    posts = sum(counter_delta(run.get("resources", []), "http_posts") or 0 for run in runs)
    connections = sum(
        counter_delta(run.get("resources", []), "http_connections_total") or 0
        for run in runs
    )
    operations = gets + posts
    rss_values = [
        int(float(row["rss_kib"])) for row in mac_resources if row.get("rss_kib")
    ]
    cpu_values = [
        float(row["cpu_percent"])
        for row in mac_resources
        if row.get("cpu_percent")
    ]
    thread_values = [
        int(row["threads"]) for row in mac_resources if row.get("threads")
    ]
    vps_samples = [sample for run in runs for sample in run.get("resources", [])]
    return {
        "runs": len([run for run in runs if run]),
        "completed_runs": len(
            [run for run in runs if run.get("status") == "complete"]
        ),
        "completed_checks": len(measurements),
        "failed_checks": len(failures),
        "known_findings": known,
        "unexpected_failures": unexpected,
        "latency": latency,
        "pass_latency": pass_latency,
        "transport": {
            "client_event_counts": dict(sorted(event_counts.items())),
            "request_body_size": distribution(request_sizes, "bytes"),
            "response_body_size": distribution(response_sizes, "bytes"),
            "body_fill_ratio": distribution(fill_ratios, "ratio"),
            "ack_wait": distribution(ack_wait),
            "empty_recv": sum(
                1
                for item in events
                if item.get("event") == "v2_recv" and item.get("empty")
            ),
            "retries": event_counts.get("v2_retry", 0),
            "vps_http_gets": gets,
            "vps_http_posts": posts,
            "http_operations": operations,
            "vps_new_http_connections": connections,
            "connection_reuse_percent": (
                round(max(0, operations - connections) * 100 / operations, 2)
                if operations
                else None
            ),
            "pass_http_operations": pass_operations,
        },
        "resources": {
            "mac_client_cpu_percent_max": max(cpu_values) if cpu_values else None,
            "mac_client_rss_kib_max": max(rss_values) if rss_values else None,
            "mac_client_threads_max": max(thread_values) if thread_values else None,
            "vps_rss_kib_max": max(
                (sample.get("rss_kib", 0) for sample in vps_samples), default=None
            ),
            "vps_sessions_max": max(
                (sample.get("v2_sessions", 0) for sample in vps_samples), default=None
            ),
        },
        "measurements": measurements,
    }


def comparison(candidate, baseline):
    scenario_deltas = {}
    repeated_latency_wins = []
    regressions = []
    for scenario, base_distribution in baseline["latency"].items():
        candidate_distribution = candidate["latency"].get(scenario, {})
        base_p95 = base_distribution.get("p95_ms")
        candidate_p95 = candidate_distribution.get("p95_ms")
        change = delta_percent(candidate_p95, base_p95)
        scenario_deltas[scenario] = {
            "baseline_p95_ms": base_p95,
            "candidate_p95_ms": candidate_p95,
            "delta_percent": change,
        }
        per_pass = []
        for comparison_pass in ("1", "2", "3"):
            base_value = (
                baseline["pass_latency"]
                .get(comparison_pass, {})
                .get(scenario, {})
                .get("p95_ms")
            )
            candidate_value = (
                candidate["pass_latency"]
                .get(comparison_pass, {})
                .get(scenario, {})
                .get("p95_ms")
            )
            pass_delta = delta_percent(candidate_value, base_value)
            per_pass.append(pass_delta is not None and pass_delta <= -20)
        if change is not None and change <= -20 and all(per_pass):
            repeated_latency_wins.append(scenario)
        if scenario in PRIORITY_SCENARIOS and change is not None and change > 10:
            regressions.append(scenario)

    base_ops = baseline["transport"]["http_operations"]
    candidate_ops = candidate["transport"]["http_operations"]
    operations_delta = delta_percent(candidate_ops, base_ops)
    operation_passes = []
    for comparison_pass in ("1", "2", "3"):
        base_value = baseline["transport"]["pass_http_operations"].get(comparison_pass)
        candidate_value = candidate["transport"]["pass_http_operations"].get(
            comparison_pass
        )
        pass_delta = delta_percent(candidate_value, base_value)
        operation_passes.append(pass_delta is not None and pass_delta <= -30)
    repeated_operations_win = (
        operations_delta is not None
        and operations_delta <= -30
        and all(operation_passes)
    )
    qualifies = (
        not candidate["unexpected_failures"]
        and not regressions
        and (bool(repeated_latency_wins) or repeated_operations_win)
    )
    return {
        "scenario_p95": scenario_deltas,
        "http_operations_delta_percent": operations_delta,
        "repeated_latency_wins": repeated_latency_wins,
        "repeated_http_operations_win": repeated_operations_win,
        "p95_regressions_over_10_percent": regressions,
        "no_new_correctness_failures": not candidate["unexpected_failures"],
        "qualifies": qualifies,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()
    root = args.result_dir
    profiles = {profile: profile_report(root, profile) for profile in PROFILES}
    baseline = profiles["A-v2-baseline"]
    comparisons = {
        profile: comparison(profiles[profile], baseline) for profile in PROFILES[1:]
    }
    qualifying = [profile for profile, result in comparisons.items() if result["qualifies"]]
    recommendation = (
        min(
            qualifying,
            key=lambda profile: (
                profiles[profile]["latency"]
                .get("short_sequential", {})
                .get("p95_ms")
                or float("inf"),
                profiles[profile]["transport"]["http_operations"],
            ),
        )
        if qualifying
        else None
    )
    route_records = [
        item
        for item in load_jsonl(root / "path-measurements.jsonl")
        if not item.get("warmup")
    ]
    report = {
        "schema": 1,
        "stage": "A-vs-B-batch-sizes",
        "run_id": root.name,
        "status": (
            "complete_with_findings"
            if all(profile["completed_runs"] == 3 for profile in profiles.values())
            else "incomplete"
        ),
        "profiles": profiles,
        "comparisons": comparisons,
        "recommended_profile": recommendation,
        "route_measurements": route_records,
    }
    (root / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    with (root / "measurements.csv").open("w", newline="", encoding="utf-8") as target:
        columns = [
            "profile",
            "comparison_pass",
            "scenario",
            "test_id",
            "concurrency",
            "ok",
            "total_ms",
            "first_byte_ms",
            "bytes_up",
            "bytes_down",
            "error",
        ]
        writer = csv.DictWriter(target, fieldnames=columns)
        writer.writeheader()
        for profile, data in profiles.items():
            for item in data["measurements"]:
                writer.writerow(
                    {
                        "profile": profile,
                        "comparison_pass": item.get("comparison_pass"),
                        "scenario": item.get("scenario"),
                        "test_id": item.get("test_id"),
                        "concurrency": item.get("concurrency"),
                        "ok": item.get("ok"),
                        "total_ms": round((item.get("total_us") or 0) / 1000, 3),
                        "first_byte_ms": (
                            round(item["first_byte_us"] / 1000, 3)
                            if item.get("first_byte_us") is not None
                            else None
                        ),
                        "bytes_up": item.get("bytes_up"),
                        "bytes_down": item.get("bytes_down"),
                        "error": item.get("error"),
                    }
                )

    lines = [
        "# Reverse httptun A/B batch comparison",
        "",
        f"- Run: `{root.name}`",
        f"- Status: **{report['status']}**",
        f"- Recommended profile: `{recommendation or 'none'}`",
        "",
        "| Profile | checks | unexpected failures | short p95 ms | short+bg p95 ms | HTTP ops | reuse |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for profile, data in profiles.items():
        short = data["latency"].get("short_sequential", {}).get("p95_ms")
        short_bg = data["latency"].get("short_with_background", {}).get("p95_ms")
        transport = data["transport"]
        lines.append(
            f"| {profile} | {data['completed_checks']} | {len(data['unexpected_failures'])} | "
            f"{short} | {short_bg} | {transport['http_operations']} | "
            f"{transport['connection_reuse_percent']}% |"
        )
    lines.extend(["", "## Decision gates", ""])
    for profile, result in comparisons.items():
        lines.append(
            f"- `{profile}`: qualifies={str(result['qualifies']).lower()}, "
            f"HTTP ops delta={result['http_operations_delta_percent']}%, "
            f"repeated latency wins={result['repeated_latency_wins'] or 'none'}, "
            f"p95 regressions={result['p95_regressions_over_10_percent'] or 'none'}."
        )
    lines.extend(
        [
            "",
            "The known baseline `half_close: eof` finding is listed separately and is not treated as a new profile B regression.",
        ]
    )
    (root / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
