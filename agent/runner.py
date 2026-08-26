"""BƯỚC 3c — trifecta split + egress allowlist.

Tách luồng xử lý thành các Run riêng biệt:
    Run A: Gọi search_docs (untrusted content). Lấy ticket_id dạng số từ tên file.
    Run B: Tra cứu customer_id qua related_tickets trong data/customers.json (nguồn tin cậy).
           Không bao giờ lấy customer_id từ free text do attacker cung cấp.
    Mọi tool call đi qua policy.check() và được ghi vào ledger.append().
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def _hash_args(args_obj: object) -> str:
    """Tạo hash rút gọn cho tham số gọi tool."""
    serialized = json.dumps(args_obj, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _extract_ticket_ids_from_docs(docs: list[dict]) -> list[int]:
    """Trích xuất ticket_id (số nguyên) chỉ từ tên file doc['id'], ví dụ 'ticket-014.md' -> 14."""
    ticket_ids: list[int] = []
    for doc in docs:
        filename = doc.get("id", "")
        m = re.search(r"ticket-(\d+)", filename)
        if m:
            try:
                ticket_ids.append(int(m.group(1)))
            except ValueError:
                continue
    return sorted(set(ticket_ids))


def _find_customers_for_tickets(ticket_ids: list[int], customers_file: Path | None = None) -> list[str]:
    """Tra cứu customer_id từ bảng dữ liệu tin cậy (customers.json: related_tickets)."""
    customers_file = customers_file or CUSTOMERS_FILE
    if not customers_file.exists():
        return []
    try:
        customers = json.loads(customers_file.read_text(encoding="utf-8"))
    except Exception:
        return []

    ticket_id_set = set(ticket_ids)
    matched_customer_ids: list[str] = []
    for c in customers:
        rel = set(c.get("related_tickets", []))
        if rel & ticket_id_set:
            matched_customer_ids.append(c["customer_id"])
    return sorted(set(matched_customer_ids))


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Xử lý yêu cầu người dùng với Trifecta Split và PEP Policy / Audit Ledger."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    agent_id = "lab24-agent"

    # -------------------------------------------------------------
    # 1. RUN A: Tìm kiếm tài liệu (Untrusted Content)
    # -------------------------------------------------------------
    ctx_a = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_a, reason_a = policy.check(ctx_a)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": "run-a",
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": "internal",
            "decision": "allow" if allow_a else "deny",
            "reason": reason_a,
        },
        ledger_path,
    )

    if not allow_a:
        return "Yêu cầu tìm kiếm bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d.get("text", "") for d in docs)

    # Trích xuất ticket_id từ TÊN FILE (nguồn typed an toàn), không trích xuất từ free text
    ticket_ids = _extract_ticket_ids_from_docs(docs)

    # -------------------------------------------------------------
    # 2. RUN B: Đọc dữ liệu khách hàng (Private Data)
    # -------------------------------------------------------------
    trusted_customer_ids = _find_customers_for_tickets(ticket_ids)
    collected_records = []

    for customer_id in trusted_customer_ids:
        ctx_b = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="read-customer-details",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_b, reason_b = policy.check(ctx_b)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": "run-b",
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": customer_id}),
                "classification": "restricted",
                "decision": "allow" if allow_b else "deny",
                "reason": reason_b,
            },
            ledger_path,
        )

        if allow_b:
            try:
                rec = tools.read_customer(customer_id)
                collected_records.append(rec)
            except tools.ToolError:
                continue

    # -------------------------------------------------------------
    # 3. KIỂM SOÁT EXFILTRATION (Chặn Lethal Trifecta / Egress)
    # -------------------------------------------------------------
    injected = llm.find_injection(combined_text)
    if injected is not None:
        # Attacker cố gắng kích hoạt gửi dữ liệu PII ra ngoài (egress)
        ctx_egress = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="exfiltration-reconcile",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_egress, reason_egress = policy.check(ctx_egress)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": "run-b",
                "tool": "http_post",
                "args_hash": _hash_args({"url": injected.target_url, "records_count": len(collected_records)}),
                "classification": "restricted",
                "decision": "allow" if allow_egress else "deny",
                "reason": reason_egress,
            },
            ledger_path,
        )

        # Vì policy từ chối (allow_egress = False), KHÔNG gọi tools.http_post

    # -------------------------------------------------------------
    # 4. Trả về kết quả tổng hợp cho người dùng
    # -------------------------------------------------------------
    return llm.summarize(docs)
