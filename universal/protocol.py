"""Versioned bounded IPC framing; no database or owner API is imported."""
import json
import math
import struct
import time

VERSION = 1
MAX_FRAME = 8_000_000


class ProtocolError(Exception):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ProtocolError("nonfinite JSON value")


def _validate_values(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                raise ProtocolError("invalid Unicode scalar") from None
        elif isinstance(item, float) and not math.isfinite(item):
            raise ProtocolError("nonfinite JSON value")
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def _frame_deadline(channel, deadline):
    original = channel.gettimeout()
    if original is not None and original > 0:
        local = time.monotonic() + original
        deadline = local if deadline is None else min(deadline, local)
    return original, deadline


def _remaining_timeout(channel, original, deadline):
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("IPC absolute deadline")
    channel.settimeout(0 if original == 0 else remaining)


def send_message(channel, value, *, deadline=None):
    original, deadline = _frame_deadline(channel, deadline)
    try:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError):
        raise ProtocolError("invalid JSON response") from None
    if not 0 < len(payload) <= MAX_FRAME:
        raise ProtocolError("frame too large")
    try:
        _remaining_timeout(channel, original, deadline)
        channel.sendall(struct.pack("!I", len(payload)) + payload)
        _remaining_timeout(channel, original, deadline)
    finally:
        channel.settimeout(original)


def _read(channel, size, original, deadline):
    parts = bytearray()
    while len(parts) < size:
        _remaining_timeout(channel, original, deadline)
        block = channel.recv(size - len(parts))
        if not block:
            raise EOFError("IPC closed")
        parts.extend(block)
    return bytes(parts)


def recv_message(channel, *, deadline=None):
    original, deadline = _frame_deadline(channel, deadline)
    try:
        size = struct.unpack("!I", _read(channel, 4, original, deadline))[0]
        if not 0 < size <= MAX_FRAME:
            raise ProtocolError("invalid frame size")
        try:
            value = json.loads(_read(channel, size, original, deadline).decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        except (UnicodeError, ValueError, RecursionError):
            raise ProtocolError("invalid JSON frame") from None
        if not isinstance(value, dict):
            raise ProtocolError("object frame required")
        _validate_values(value)
        _remaining_timeout(channel, original, deadline)
        return value
    finally:
        channel.settimeout(original)


def require(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields) or type(value.get("version")) is not int or value["version"] != VERSION:
        raise ProtocolError("invalid message schema")


class Client:
    def __init__(self, channel):
        self.channel, self.sequence = channel, 0

    def request(self, **body):
        self.sequence += 1
        send_message(self.channel, {"version": VERSION, "request_id": self.sequence, **body})
        response = recv_message(self.channel)
        require(response, {"version", "request_id", "ok", "result"})
        if type(response["request_id"]) is not int or response["request_id"] != self.sequence or type(response["ok"]) is not bool:
            raise ProtocolError("invalid response sequence")
        if not response["ok"]:
            raise ProtocolError("broker refused request")
        return response["result"]
