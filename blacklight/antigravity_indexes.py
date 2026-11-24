"""Offline Antigravity conversation indexes (AGY 1.5.9 observed layout)."""
from __future__ import annotations

import json
from pathlib import Path

INDEX_NAMES = {'conversation_metadata.json', 'jetbox_summaries_proto.pb'}


def _varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError('truncated protobuf varint')
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ValueError('protobuf varint overflow')
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError('protobuf varint overflow')


def fields(data):
    offset = 0
    result = []
    while offset < len(data):
        tag, offset = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not 0 < number < 2**29:
            raise ValueError('invalid protobuf field number')
        if wire == 0:
            value, offset = _varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, offset = _varint(data, offset)
            else:
                length = 8 if wire == 1 else 4
            if length > len(data) - offset:
                raise ValueError('truncated protobuf field')
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError('unsupported protobuf wire type')
        result.append((number, wire, value))
    return result


def _text(value):
    if not isinstance(value, bytes):
        return None
    try:
        text = value.decode('utf-8')
    except UnicodeError:
        return None
    return text if all(c.isprintable() or c in '\n\r\t' for c in text) else None


def _texts(data, prefix='', depth=0):
    if depth > 8:
        return {}
    result = {}
    for number, wire, value in fields(data):
        key = f'{prefix}{number}'
        if wire != 2:
            continue
        text = _text(value)
        if text is not None:
            result.setdefault(key, []).append(text)
        else:
            try:
                nested = _texts(value, key + '.', depth + 1)
            except ValueError:
                continue
            for name, values in nested.items():
                result.setdefault(name, []).extend(values)
    return result


def index_records(path: Path):
    if path.name == 'conversation_metadata.json':
        document = json.loads(path.read_text(encoding='utf-8'))
        conversations = document.get('conversations') if isinstance(document, dict) else None
        if not isinstance(conversations, dict):
            raise ValueError('expected conversations object')
        for identifier, entry in conversations.items():
            if not isinstance(entry, dict) or not isinstance(entry.get('summary'), dict):
                raise ValueError('expected conversation summary object')
            summary = entry['summary']
            for key in ('Title', 'Preview', 'UpdatedAt'):
                if summary.get(key) is not None and not isinstance(summary[key], str):
                    raise ValueError(f'expected string summary {key}')
            if summary.get('WorkspaceURIs') is not None and (not isinstance(summary['WorkspaceURIs'], list) or any(not isinstance(v, str) for v in summary['WorkspaceURIs'])):
                raise ValueError('expected WorkspaceURIs string array')
            yield {'session_id': identifier, 'title': summary.get('Title') or summary.get('Preview'),
                   'updated_at': summary.get('UpdatedAt'), 'workspace_uris': summary.get('WorkspaceURIs'),
                   '_agy_index': {'source': str(path), 'summary': summary}}
        return
    for number, wire, value in fields(path.read_bytes()):
        if number != 1 or wire != 2:
            continue
        entry = fields(value)
        ids = [_text(v) for n, w, v in entry if n == 1 and w == 2]
        if not ids or not ids[0]:
            raise ValueError('summary protobuf entry has no conversation identifier')
        for n, w, summary in entry:
            if n != 2 or w != 2:
                continue
            texts = _texts(summary)
            workspaces = [v for values in texts.values() for v in values if v.startswith('file://')]
            yield {'session_id': ids[0], 'title': next(iter(texts.get('1', [])), None),
                   'workspace_uris': workspaces,
                   '_agy_index': {'source': str(path), 'protobuf_text_fields': texts,
                                  'workspace_uris': sorted(set(workspaces)),
                                  'repository_identifiers': texts.get('9.3.1', []),
                                  'repository_urls': texts.get('9.3.2', []),
                                  'branches': texts.get('9.4', [])}}
