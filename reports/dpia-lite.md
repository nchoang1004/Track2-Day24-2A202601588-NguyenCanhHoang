# DPIA-lite — Đánh giá tác động bảo vệ dữ liệu cá nhân (1 trang)

## 1. Dữ liệu gì

Hệ thống Agent xử lý các nhóm dữ liệu cá nhân (PII) được thu thập và lưu trữ trong hệ thống:

| Nhóm dữ liệu | Dữ liệu cụ thể | Nguồn / Tool chạm vào | Phân loại dữ liệu |
|---|---|---|---|
| **Dữ liệu ticket hỗ trợ** | Nội dung khiếu nại, mã ticket, tên khách hàng trong văn bản | `tools.search_docs` (đọc từ `corpus/*.md`) | **Internal** (Nội bộ) |
| **Dữ liệu định danh cá nhân** | Họ và tên, Số CCCD (12 chữ số) | `tools.read_customer` (đọc từ `data/customers.json`) | **Restricted** (Nhạy cảm) |
| **Dữ liệu liên hệ** | Số điện thoại di động (10 số), Địa chỉ Email | `tools.read_customer` (đọc từ `data/customers.json`) | **Restricted** (Nhạy cảm) |
| **Dữ liệu tài chính** | Số tài khoản ngân hàng (STK: 8-16 chữ số) | `tools.read_customer` (đọc từ `data/customers.json`) | **Restricted** (Nhạy cảm) |

---

## 2. Mục đích gì

- **Tổng hợp và đối soát ticket hỗ trợ khách hàng:** Agent cần tra cứu các ticket đang mở trong tuần (`search_docs`) và thông tin liên quan trong hồ sơ khách hàng (`read_customer`) để hỗ trợ giải quyết sự cố, tra cứu giao dịch, trả lời khiếu nại và xuất báo cáo nội bộ.
- **Nguyên tắc giảm thiểu dữ liệu (Data Minimization):**
  - Trước khi đưa vào context xử lý hoặc lưu trữ, văn bản thô được quét qua bộ lọc PII Gate (`agent/pii.py`) để phát hiện và che giấu (`redact`) các trường thông tin nhạy cảm.
  - Agent chỉ truy xuất hồ sơ khách hàng khi có liên kết hợp lệ thông qua trường `related_tickets` của hệ thống, không tự ý truy cập dữ liệu ngoài phạm vi nghiệp vụ.

---

## 3. Chảy đi đâu

### Luồng lưu chuyển dữ liệu trong hệ thống:
1. **Lưu trữ nội bộ & Nhật ký kiểm toán:**
   - Dữ liệu truy vấn và phản hồi được ghi nhận có kiểm soát trong hệ thống.
   - Mọi hành vi gọi công cụ đều được ghi vào Audit Ledger dạng hash chain (`reports/ledger.jsonl`) phục vụ giám sát, chống sửa đổi (tamper-evident).
2. **Kênh Egress / Đích nhận bên ngoài (Sink):**
   - Trong môi trường Lab, kênh exfiltration sink trỏ vào `localhost:9999`. 
   - **Cơ chế kiểm soát:** Policy Enforcement Point (PEP trong `agent/policy.py`) và kiến trúc Trifecta Split (`agent/runner.py`) chặn triệt để mọi hành vi chuyển dữ liệu phân loại `restricted` ra kênh egress (`http_post` bị từ chối và ghi log `decision=deny`).
3. **Đánh giá Chuyển dữ liệu xuyên biên giới (NĐ 356/2025/NĐ-CP):**
   - **Khi chạy chế độ `--mock` (Mặc định):** Không có dữ liệu nào được truyền ra ngoài máy chủ nội bộ. Hoàn toàn đáp ứng chủ quyền dữ liệu trong nước.
   - **Khi chạy chế độ `--model` (gọi API nhà cung cấp nước ngoài như Anthropic Claude):** Dữ liệu tóm tắt context được gửi qua API HTTPS sang máy chủ nước ngoài.
   - **Biện pháp giảm thiểu rủi ro:**
     - Áp dụng PII Redaction (`[REDACTED_VN_CCCD]`, `[REDACTED_VN_PHONE]`, ...) trước khi gửi prompt ra mô hình bên thứ ba.
     - Lập Data-Flow Inventory định kỳ 60 ngày theo đúng quy định tại Nghị định 356/2025/NĐ-CP.
     - Áp dụng kiểm soát egress cứng qua PEP Policy để ngăn chặn rò rỉ cơ sở dữ liệu khách hàng nguyên vẹn.
