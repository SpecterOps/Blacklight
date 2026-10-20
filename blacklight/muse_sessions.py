"""Read the observed Muse Code 0.2.1 durable event stream.

Schema evidence: session-migrate/formats/muse.py, native build b3170a534f.
Unknown record and payload types are deliberately ignored.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import iter_jsonl


def is_muse_record(record: dict[str, Any]) -> bool:
    stream = record.get("stream")
    return (record.get("schema_version") == 1
            and record.get("record_type") == "event"
            and isinstance(stream, dict) and stream.get("kind") == "session"
            and isinstance(stream.get("id"), str)
            and str(record.get("payload_type", "")).startswith("runtime.")
            and isinstance(record.get("payload"), dict))


def iter_muse_records(path: Path):
    pending: Counter[str] = Counter()
    for line, record, error in iter_jsonl(path):
        if error:
            yield line, record, error
            continue
        if not record or not is_muse_record(record):
            continue
        payload = record["payload"]
        base: dict[str, Any] = {"session_id": record["stream"]["id"]}
        recorded_at = record.get("recorded_at")
        if isinstance(recorded_at, (int, float)) and not isinstance(recorded_at, bool):
            try:
                base["timestamp"] = datetime.fromtimestamp(recorded_at / 1_000_000, timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                pass
        kind = record["payload_type"]
        if kind == "runtime.session.metadata":
            metadata = payload.get("record")
            if isinstance(metadata, dict):
                yield line, {**base, "role": "system", "cwd": metadata.get("workspace_root")}, None
        elif kind == "runtime.user_intent.accepted":
            messages = payload.get("model_messages")
            for message in messages if isinstance(messages, list) else []:
                if not isinstance(message, dict):
                    continue
                content = message.get("content")
                for block in content if isinstance(content, list) else []:
                    if isinstance(block, dict) and block.get("kind") == "text" and isinstance(block.get("text"), str):
                        text = block["text"]
                        pending[text] += 1
                        yield line, {**base, "role": "user", "content": text}, None
        elif kind == "runtime.session" and payload.get("kind") == "run":
            event = payload.get("event")
            if not isinstance(event, dict):
                continue
            event_kind = event.get("kind")
            if event_kind == "started" and isinstance(event.get("prompt"), str):
                prompt = event["prompt"]
                if pending[prompt]:
                    pending[prompt] -= 1
                else:
                    yield line, {**base, "role": "user", "content": prompt}, None
            elif event_kind == "assistant_message_committed" and isinstance(event.get("text"), str):
                yield line, {**base, "role": "assistant", "content": event["text"]}, None
            elif event_kind == "assistant_tool_calls_committed":
                calls = event.get("tool_calls")
                for call in calls if isinstance(calls, list) else []:
                    if isinstance(call, dict):
                        yield line, {**base, "role": "tool", "content": call.get("args", {})}, None
            elif event_kind == "tool_result_batch_committed":
                results = event.get("results")
                for result in results if isinstance(results, list) else []:
                    if isinstance(result, dict) and isinstance(result.get("text"), str):
                        yield line, {**base, "role": "tool", "content": result["text"]}, None
