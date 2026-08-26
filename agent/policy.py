"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute.

Interface bắt buộc:
    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và allow=False.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str  # "public" | "internal" | "restricted"
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật trước khi thực thi tool.
    
    Quy tắc tối thiểu bắt buộc:
        classification == "restricted" and egress_enabled is True -> DENY
    """
    # 1. Rule tối thiểu: Chặn rò rỉ dữ liệu restricted ra kênh egress
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, f"Denied egress for restricted data by agent {context.agent_owner} (purpose: {context.request_purpose})"

    # 2. Kiểm tra delegation depth (ngăn chặn leo thang đặc quyền / lặp vô hạn)
    if context.delegation_depth > 5:
        return False, f"Denied tool execution: delegation depth {context.delegation_depth} exceeds maximum threshold of 5"

    # 3. Cho phép truy cập dữ liệu hợp lệ trong nội bộ
    if context.data_classification in ("public", "internal", "restricted"):
        egress_status = "egress-enabled" if context.egress_enabled else "internal-only"
        return True, f"Allowed access to {context.data_classification} data for agent {context.agent_owner} ({egress_status}, purpose: {context.request_purpose})"

    # Fallback an toàn (mặc định deny nếu không rõ classification)
    return False, f"Denied access: unknown data classification {context.data_classification!r}"
