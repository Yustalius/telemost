#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


def append_jsonl(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as target:
        target.write(json.dumps(record, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--segment", required=True)
    parser.add_argument("--pass", dest="pass_number", required=True, type=int)
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--mode", choices=("direct", "proxy"), required=True)
    parser.add_argument("--proxy")
    parser.add_argument("--noproxy", default="beeline.ru,vimpelcom.ru")
    parser.add_argument("--measurements", required=True, type=Path)
    parser.add_argument("--routes", required=True, type=Path)
    parser.add_argument("--warmup", action="store_true")
    args = parser.parse_args()

    command = [
        "curl",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--location",
        "--max-redirs",
        "10",
        "--max-time",
        "60",
        "--connect-timeout",
        "20",
        "--header",
        "Connection: close",
        "--write-out",
        "%{json}",
    ]
    environment = os.environ.copy()
    if args.mode == "direct":
        for name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ):
            environment.pop(name, None)
        command.extend(["--proxy", "", "--noproxy", args.noproxy])
    else:
        if not args.proxy:
            parser.error("--proxy is required in proxy mode")
        command.extend(["--proxy", args.proxy, "--noproxy", ""])
    command.append(args.url)

    completed = subprocess.run(
        command,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    try:
        metrics = json.loads(completed.stdout)
    except json.JSONDecodeError:
        metrics = {}
    code = int(metrics.get("http_code") or 0)
    ok = completed.returncode == 0 and code not in {0, 407, 502}
    error = None
    if completed.returncode != 0:
        error = f"curl_exit_{completed.returncode}"
    elif code in {0, 407, 502}:
        error = f"http_{code}"
    if not args.warmup:
        record = {
            "segment": args.segment,
            "pass": args.pass_number,
            "test_id": args.test_id,
            "ok": ok,
            "curl_exit": completed.returncode,
            "http_code": code,
            "time_namelookup_ms": round(float(metrics.get("time_namelookup") or 0) * 1000, 3),
            "time_connect_ms": round(float(metrics.get("time_connect") or 0) * 1000, 3),
            "time_appconnect_ms": round(float(metrics.get("time_appconnect") or 0) * 1000, 3),
            "time_starttransfer_ms": round(float(metrics.get("time_starttransfer") or 0) * 1000, 3),
            "time_total_ms": round(float(metrics.get("time_total") or 0) * 1000, 3),
            "size_upload": int(metrics.get("size_upload") or 0),
            "size_download": int(metrics.get("size_download") or 0),
            "speed_download": round(float(metrics.get("speed_download") or 0), 3),
            "num_connects": int(metrics.get("num_connects") or 0),
            "num_redirects": int(metrics.get("num_redirects") or 0),
            "error": error,
        }
        append_jsonl(args.measurements, record)
        effective = urlsplit(metrics.get("url_effective") or args.url)
        append_jsonl(
            args.routes,
            {
                "segment": args.segment,
                "pass": args.pass_number,
                "http_code": code,
                "redirects": record["num_redirects"],
                "final": f"{effective.scheme}://{effective.hostname or ''}{effective.path}",
            },
        )
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
