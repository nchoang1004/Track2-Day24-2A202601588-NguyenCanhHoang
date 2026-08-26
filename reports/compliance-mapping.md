# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo — không phải mô tả chung.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Cơ chế cascade delete cho data subject (chưa implement, xem stretch #3) | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory & đánh giá chuyển dữ liệu LLM API | [`reports/dpia-lite.md`](dpia-lite.md) §2, §3 |
| ASI03 — Privilege Abuse | Phân quyền theo vai trò per-agent/run identity, kiểm tra context tại PEP | [`agent/policy.py:L31-L47`](../agent/policy.py), [`agent/runner.py:L62-L136`](../agent/runner.py) |
| ASI01 — Goal Hijack | Ngăn chặn thực thi lệnh injection qua kiến trúc Trifecta Split & Egress blocking | [`agent/runner.py:L114-L134`](../agent/runner.py), [`reports/attack-after.log`](attack-after.log) |
| ISO 42001 Clause 5-6 | Policy-as-Code & Audit Ledger tamper-evident cho mọi quyết định AI | [`agent/policy.py:L39-L50`](../agent/policy.py), [`agent/ledger.py:L23-L65`](../agent/ledger.py), [`reports/ledger.jsonl`](ledger.jsonl) |
