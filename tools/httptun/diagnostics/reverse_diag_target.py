#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import re
import signal
import time
from pathlib import Path


MAX_BYTES = 8 * 1024 * 1024
MAX_LINE = 4096
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class EventLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("a", encoding="utf-8", buffering=1)
        self._started_ns = time.monotonic_ns()
        self._wall_started_ms = time.time_ns() // 1_000_000

    def write(self, event: str, **fields: object) -> None:
        elapsed_us = (time.monotonic_ns() - self._started_ns) // 1_000
        record = {
            "schema": 1,
            "event": event,
            "role": "target",
            "pid": os.getpid(),
            "monotonic_us": elapsed_us,
            "unix_ms": self._wall_started_ms + elapsed_us // 1_000,
            **fields,
        }
        self._file.write(json.dumps(record, separators=(",", ":")) + "\n")


def pattern(offset: int, count: int) -> bytes:
    return bytes((offset + index) % 251 for index in range(count))


def validate_request(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("request_not_object")
    command = value.get("command")
    test_id = value.get("test_id")
    byte_count = value.get("bytes")
    chunk_bytes = value.get("chunk_bytes")
    delay_ms = value.get("delay_ms")
    first_delay_ms = value.get("first_delay_ms")
    if command not in {"upload", "download", "exchange", "reset"}:
        raise ValueError("invalid_command")
    if not isinstance(test_id, str) or not ID_RE.fullmatch(test_id):
        raise ValueError("invalid_test_id")
    if not isinstance(byte_count, int) or not 0 <= byte_count <= MAX_BYTES:
        raise ValueError("invalid_bytes")
    if not isinstance(chunk_bytes, int) or not 1 <= chunk_bytes <= 256 * 1024:
        raise ValueError("invalid_chunk_bytes")
    if not isinstance(delay_ms, int) or not 0 <= delay_ms <= 1_000:
        raise ValueError("invalid_delay_ms")
    if not isinstance(first_delay_ms, int) or not 0 <= first_delay_ms <= 10_000:
        raise ValueError("invalid_first_delay_ms")
    return value


async def read_and_verify(reader: asyncio.StreamReader, byte_count: int) -> None:
    offset = 0
    while offset < byte_count:
        count = min(32 * 1024, byte_count - offset)
        block = await reader.readexactly(count)
        if block != pattern(offset, count):
            raise ValueError("payload_mismatch")
        offset += count


async def send_pattern(
    writer: asyncio.StreamWriter, byte_count: int, chunk_bytes: int, delay_ms: int
) -> None:
    offset = 0
    while offset < byte_count:
        count = min(chunk_bytes, byte_count - offset)
        writer.write(pattern(offset, count))
        await writer.drain()
        offset += count
        if delay_ms and offset < byte_count:
            await asyncio.sleep(delay_ms / 1_000)


async def handle_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, events: EventLog
) -> None:
    peer = writer.get_extra_info("peername")
    peer_text = f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else "unknown"
    events.write("target_accept", peer=peer_text)
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break
            if len(raw) > MAX_LINE or not raw.endswith(b"\n"):
                raise ValueError("invalid_header")
            request = validate_request(json.loads(raw))
            command = request["command"]
            test_id = request["test_id"]
            byte_count = request["bytes"]
            started_ns = time.monotonic_ns()
            events.write(
                "target_request",
                peer=peer_text,
                test_id=test_id,
                command=command,
                bytes=byte_count,
            )
            if command == "reset":
                writer.transport.abort()
                events.write("target_reset", peer=peer_text, test_id=test_id)
                return
            if command in {"upload", "exchange"}:
                await read_and_verify(reader, byte_count)
            if request["first_delay_ms"]:
                await asyncio.sleep(request["first_delay_ms"] / 1_000)
            writer.write(
                json.dumps(
                    {"ok": True, "bytes": byte_count}, separators=(",", ":")
                ).encode("ascii")
                + b"\n"
            )
            await writer.drain()
            if command in {"download", "exchange"}:
                await send_pattern(
                    writer,
                    byte_count,
                    request["chunk_bytes"],
                    request["delay_ms"],
                )
            events.write(
                "target_complete",
                peer=peer_text,
                test_id=test_id,
                command=command,
                bytes=byte_count,
                duration_us=(time.monotonic_ns() - started_ns) // 1_000,
            )
    except (asyncio.IncompleteReadError, ConnectionError):
        events.write("target_connection_lost", peer=peer_text)
    except (json.JSONDecodeError, ValueError) as error:
        events.write("target_error", peer=peer_text, reason=str(error))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:13131")
    parser.add_argument("--events", required=True, type=Path)
    args = parser.parse_args()
    host, raw_port = args.listen.rsplit(":", 1)
    events = EventLog(args.events)
    server = await asyncio.start_server(
        lambda reader, writer: handle_connection(reader, writer, events),
        host,
        int(raw_port),
        limit=MAX_LINE,
    )
    events.write("target_start", listen=args.listen)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            loop.add_signal_handler(getattr(signal, name), stop.set)
    async with server:
        await stop.wait()


if __name__ == "__main__":
    asyncio.run(main())
