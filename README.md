# AES & RSA Lab (.NET 8 Console)

Chạy: `dotnet run` (cần .NET 8 SDK). Menu số 1–20 tương ứng các yêu cầu bài 1 và bài 2.

## Bài 1 – AES-256-CBC
Sinh/lưu/import khoá (base64), mã hoá văn bản, mã hoá file bằng stream (buffer 1MB, chạy được file hàng GB), IV ngẫu nhiên 16 byte ghi ở đầu dữ liệu. Menu 8 đo thời gian mã hoá/giải mã và so sánh từng byte file gốc với file giải mã.

**Kết luận (điền số liệu của bạn sau khi chạy):** AES là mã đối xứng nên rất nhanh (thường vài trăm MB/s đến GB/s nhờ AES-NI), thời gian tăng tuyến tính theo kích thước file; file giải mã trùng khớp 100% từng byte với file gốc.

## Bài 2 – RSA-2048
- PEM: public = X.509 SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`), private = PKCS#8 (`BEGIN PRIVATE KEY`). Menu 13 giải nghĩa từng byte TLV (Tag-Length-Value) của DER.
- Mã hoá dùng OAEP-SHA256 nên tối đa 256 − 2·32 − 2 = **190 byte** (vừa đủ khoá AES-256 32 byte). Kết quả lưu base64.
- Tốc độ (menu 18): public key có e nhỏ (65537) nên mã hoá nhanh; private key có d cỡ 2048 bit nên giải mã chậm hơn khoảng vài chục lần.
- SHA-256 (menu 19): đổi 1 ký tự đầu vào thì ~50% số bit băm thay đổi (hiệu ứng thác lũ).

## Bài 9 – Đề xuất: cùng dữ liệu, cùng private key, mỗi lần ký ra chữ ký khác nhau
RSA PKCS#1 v1.5 là **tất định** nên luôn ra cùng chữ ký. Phương pháp đề xuất:

1. **RSA-PSS (khuyến nghị):** trước khi ký, băm dữ liệu rồi trộn với **salt ngẫu nhiên** (`EMSA-PSS`). Mỗi lần ký salt khác nhau ⇒ chữ ký khác nhau, nhưng người nhận vẫn verify đúng vì salt được nhúng trong chữ ký. Trong .NET: `RSASignaturePadding.Pss`.
2. **Thêm nonce/timestamp vào dữ liệu trước khi ký:** ký `H(data ‖ nonce)` rồi gửi kèm nonce. Cách này đổi dữ liệu thực sự được ký nên phải gửi thêm nonce.

Ưu điểm PSS: có chứng minh an toàn, không cần thay đổi dữ liệu, chuẩn hiện đại (RFC 8017). Menu 20 minh hoạ: PKCS#1 → 2 chữ ký giống nhau, PSS → 2 chữ ký khác nhau nhưng cả hai đều verify = true.
