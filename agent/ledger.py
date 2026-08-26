"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng.

Interface bắt buộc:
    append(entry: dict, path: pathlib.Path) -> dict
    verify(path: pathlib.Path) -> bool
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64


def _compute_hash(entry_dict: dict) -> str:
    """Tính SHA-256 từ nội dung entry (loại bỏ trường 'hash' nếu có)."""
    to_hash = {k: v for k, v in entry_dict.items() if k != "hash"}
    serialized = json.dumps(to_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Ghi nối một dòng kiểm toán vào ledger với chuỗi hash chống sửa đổi."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = GENESIS_HASH
    if path.exists() and path.stat().st_size > 0:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last_entry = json.loads(lines[-1])
            prev_hash = last_entry.get("hash", GENESIS_HASH)

    entry_to_write = dict(entry)
    entry_to_write["prev_hash"] = prev_hash
    entry_hash = _compute_hash(entry_to_write)
    entry_to_write["hash"] = entry_hash

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry_to_write, ensure_ascii=False) + "\n")

    return entry_to_write


def verify(path: Path) -> bool:
    """Xác minh tính toàn vẹn của toàn bộ file ledger."""
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev_hash = GENESIS_HASH
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # 1. Kiểm tra trường reason bắt buộc phải non-empty
        reason = entry.get("reason")
        if not reason or not str(reason).strip():
            return False

        # 2. Kiểm tra chuỗi liên kết prev_hash
        if entry.get("prev_hash") != expected_prev_hash:
            return False

        # 3. Kiểm tra tính toàn vẹn của hash dòng hiện tại
        recorded_hash = entry.get("hash")
        computed_hash = _compute_hash(entry)
        if recorded_hash != computed_hash:
            return False

        expected_prev_hash = recorded_hash

    return True
