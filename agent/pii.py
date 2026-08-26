"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Interface bắt buộc:
    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        type là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
    redact(text: str) -> str
        Thay mọi entity bằng "[REDACTED_<TYPE>]"
"""
from __future__ import annotations

import re

# Email regex chuẩn
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")

# Bank account: 8-16 chữ số sau từ khoá STK / số tài khoản / TK
_BANK_PREFIX_RE = re.compile(r"(?i:\b(?:STK|số tài khoản|tài khoản|TK)\s*)([0-9]{8,16})\b")

# CCCD: 12 chữ số liên tiếp
_CCCD_RE = re.compile(r"\b\d{12}\b")

# Phone: 10 chữ số bắt đầu bằng 0 (có thể có khoảng trắng hoặc gạch ngang)
_PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các entity PII trong `text`.
    
    Returns: list[{"type": str, "start": int, "end": int}]
    """
    entities: list[dict] = []
    occupied: list[tuple[int, int]] = []

    def is_free(start: int, end: int) -> bool:
        return not any(start < occ_end and occ_start < end for occ_start, occ_end in occupied)

    # 1. EMAIL
    for m in _EMAIL_RE.finditer(text):
        start, end = m.span()
        if is_free(start, end):
            entities.append({"type": "EMAIL", "start": start, "end": end})
            occupied.append((start, end))

    # 2. VN_BANK_ACCOUNT (kèm tiền tố STK / số tài khoản)
    for m in _BANK_PREFIX_RE.finditer(text):
        # group(1) chứa chuỗi số tài khoản
        start, end = m.span(1)
        if is_free(start, end):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
            occupied.append((start, end))

    # 3. VN_CCCD (12 số)
    for m in _CCCD_RE.finditer(text):
        start, end = m.span()
        if is_free(start, end):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            occupied.append((start, end))

    # 4. VN_PHONE (10 số bắt đầu bằng 0)
    for m in _PHONE_RE.finditer(text):
        start, end = m.span()
        if is_free(start, end):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            occupied.append((start, end))

    # Sắp xếp các entity theo thứ tự vị trí xuất hiện
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Che mọi entity PII trong `text` bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    # Thay thế từ cuối chuỗi về đầu để tránh lệch index
    entities.sort(key=lambda x: x["start"], reverse=True)
    res = text
    for ent in entities:
        tag = f"[REDACTED_{ent['type']}]"
        res = res[:ent["start"]] + tag + res[ent["end"]:]
    return res
