# Hướng dẫn frontend mobile tương tác thẻ

## Tổng quan

Chainora gồm hai applet: **Chainora Wallet** (làm việc với client) và **Chainora Secure** (giữ PIN và dữ liệu nhạy cảm). Wallet truy cập Secure thông qua shareable interface, vì vậy frontend mobile chỉ cần làm việc với Wallet AID và gửi các APDU được hỗ trợ.

## AID và bước SELECT

- Chainora Wallet (client): `F0 56 4E 43 48 57 01`
- Chainora Secure (server): `F0 56 4E 43 48 58 01`

Chuỗi khởi động mặc định:

1. Kết nối NFC (IsoDep) hoặc đầu đọc ISO7816.
2. Gửi SELECT: `00 A4 04 00 07 F0 56 4E 43 48 57 01 00`.
3. Chờ SW = 0x9000. Nếu không, kiểm tra lại AID và quyền truy cập NFC.

## Thông số giao tiếp

- Giao thức: ISO 7816-4, T=CL.
- CLA: 0x00 cho tất cả lệnh hiện có.
- P1/P2: 0x00 nếu không ghi chú rõ khác.
- Kích thước PIN: tối đa 8 byte (OwnerPIN với `PIN_MAX_SIZE = 0x08`).
- Giới hạn PIN: 3 lần (`PIN_TRY_LIMIT = 0x03`).

## Bảng APDU hỗ trợ

| INS    | Lệnh                | Dữ liệu vào                | Phản hồi                                  | SW thành công | SW lỗi chính                                     | Ghi chú                                          |
| ------ | ------------------- | -------------------------- | ----------------------------------------- | ------------- | ------------------------------------------------ | ------------------------------------------------ |
| `0x10` | INIT_PIN            | PIN mới (<= 8 byte)        | -                                         | `0x9000`      | `0x6985` khi đã khởi tạo                         | Chỉ dùng sau RESET_PIN                           |
| `0x11` | VERIFY_PIN          | PIN hiện tại               | -                                         | `0x9000`      | `0x6982` khi sai PIN, `0x6985` khi chưa init     | Bắt buộc trước UPDATE_PIN và GET_VERY_SECRET_KEY |
| `0x12` | UPDATE_PIN          | PIN mới                    | -                                         | `0x9000`      | `0x6985` khi chưa init, `0x6982` khi chưa verify | Chỉ cho phép sau khi PIN đang hợp lệ             |
| `0x13` | RESET_PIN           | (không có)                 | -                                         | `0x9000`      | -                                                | Đưa PIN về trạng thái chưa khởi tạo              |
| `0x14` | IS_PIN_INITIALIZED  | (không có)                 | 1 byte (`0x01` đã init, `0x00` chưa init) | `0x9000`      | -                                                | Hữu ích cho UI hiển thị trạng thái               |
| `0x20` | GEN_KEY_PAIR        | (dự kiến)                  | (chưa dùng)                               | -             | `0x6D00`                                         | Chưa được triển khai                             |
| `0x21` | GET_PUBLIC_KEY      | (dự kiến)                  | (chưa dùng)                               | -             | `0x6D00`                                         | Chưa được triển khai                             |
| `0x22` | SIGN_HASH           | Hash dự kiến (vd: 32 byte) | Chữ ký (dự kiến)                          | `0x9000`      | `0x6D00`                                         | Hiện tại hàm trống, sẽ được cập nhật             |
| `0x30` | GET_VERY_SECRET_KEY | -                          | Chuỗi ASCII "Chainora Secure"             | `0x9000`      | `0x6985` chưa init, `0x6982` chưa verify         | Chỉ phục vụ demo, thay bằng dữ liệu thật khi cần |

## Trạng thái SW thông dụng

- `0x9000`: thao tác thành công.
- `0x6985 (SW_CONDITIONS_NOT_SATISFIED)`: ví dụ PIN chưa khởi tạo nhưng gọi lệnh cần PIN.
- `0x6982 (SW_SECURITY_STATUS_NOT_SATISFIED)`: chưa verify PIN hoặc PIN sai.
- `0x6A82`: không tìm được applet/shareable interface.
- `0x63CX`: báo sai PIN kèm số lần còn lại (`X`).

## Luồng thao tác mẫu

1. **Thiết lập/Reset PIN**
   - Gửi `0x13` để đưa applet về trạng thái chưa init (chỉ dùng cho chức năng admin).
   - Gửi `0x10` kèm PIN mới.
2. **Đăng nhập và lấy dữ liệu**
   - Gửi `0x11` kèm PIN người dùng.
   - Kiểm tra SW = 0x9000, nếu không thì báo số lần còn lại (đọc SW2 nếu nhận 0x63CX).
   - Gửi `0x30` để lấy dữ liệu "Chainora Secure" (có thể thay bằng khóa thực tế sau này).
3. **Cập nhật PIN**
   - Sau khi verify thành công, gửi `0x12` kèm PIN mới.

## Ví dụ mã nguồn (Android/Kotlin)

```kotlin
val isoDep = IsoDep.get(tag) ?: error("IsoDep không sẵn sàng")
isoDep.connect()

fun transmit(apdu: ByteArray): ByteArray {
	val response = isoDep.transceive(apdu)
	val sw = ((response[response.size - 2].toInt() and 0xFF) shl 8) or
		(response[response.size - 1].toInt() and 0xFF)
	check(sw == 0x9000) { "Lệnh thất bại: SW=%04X".format(sw) }
	return response.copyOf(response.size - 2)
}

val selectApdu = byteArrayOf(
	0x00, 0xA4.toByte(), 0x04, 0x00,
	0x07, 0xF0.toByte(), 0x56, 0x4E, 0x43, 0x48, 0x57, 0x01, 0x00
)
transmit(selectApdu)

// Verify PIN "1234"
val verify = byteArrayOf(0x00, 0x11, 0x00, 0x00, 0x04, 0x31, 0x32, 0x33, 0x34)
transmit(verify)

// Lấy Very Secret Key
val key = transmit(byteArrayOf(0x00, 0x30, 0x00, 0x00, 0x00))
Log.d("Chainora", String(key, Charsets.US_ASCII))
```

## Gợi ý kiểm thử từ frontend

- Tích hợp test NFC Instrumented để đảm bảo SELECT và các APDU chính trả về 0x9000.
- Mô phỏng lỗi PIN sai: gửi VERIFY sai 3 lần và đảm bảo UI khóa thao tác.
- Thử nghiệm thực tế trên đầu đọc phù hợp (ACR122U hoặc Android HCE) nếu cần xác nhận chung.
