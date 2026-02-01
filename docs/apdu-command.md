# Tài liệu APDU Commands - ChainoraWallet

## Giới thiệu

Tài liệu này mô tả các APDU commands để tương tác với applet **ChainoraWallet** trên JavaCard. Applet này cung cấp các chức năng quản lý PIN và quản lý cặp khóa EC (Elliptic Curve) để ký giao dịch.

**Applet AID**: `F0564E43485701`

---

## Cấu trúc APDU Command

```
CLA  INS  P1  P2  Lc  Data  Le
```

- **CLA** (Class): `0x80` - Class byte cho applet
- **INS** (Instruction): Mã lệnh cụ thể
- **P1, P2** (Parameters): Tham số bổ sung (thường là `0x00`)
- **Lc** (Length of data): Độ dài dữ liệu gửi đi
- **Data**: Dữ liệu command
- **Le** (Expected length): Độ dài dữ liệu mong đợi nhận về

---

## 1. Quản lý PIN

### 1.1. INIT_PIN - Khởi tạo PIN

**Mô tả**: Khởi tạo PIN lần đầu tiên cho thẻ. Chỉ có thể thực hiện một lần.

**Command**:

```
CLA: 0x80
INS: 0x10
P1:  0x00
P2:  0x00
Lc:  [độ dài PIN]
Data: [PIN bytes]
```

**Tham số**:

- `Lc`: Độ dài của PIN (tối đa 8 bytes theo Configuration.PIN_MAX_SIZE)
- `Data`: Mã PIN dạng byte array

**Ví dụ**:

```
// Khởi tạo PIN = "123456" (6 bytes)
Command: 80 10 00 00 06 31 32 33 34 35 36
```

**Response codes**:

- `0x9000` (SW_NO_ERROR): Khởi tạo PIN thành công
- `0x6985` (SW_CONDITIONS_NOT_SATISFIED): PIN đã được khởi tạo trước đó

---

### 1.2. VERIFY_PIN - Xác thực PIN

**Mô tả**: Xác thực PIN để mở khóa các chức năng bảo mật.

**Command**:

```
CLA: 0x80
INS: 0x11
P1:  0x00
P2:  0x00
Lc:  [độ dài PIN]
Data: [PIN bytes]
```

**Tham số**:

- `Lc`: Độ dài của PIN
- `Data`: Mã PIN cần xác thực

**Ví dụ**:

```
// Xác thực PIN = "123456"
Command: 80 11 00 00 06 31 32 33 34 35 36
```

**Response codes**:

- `0x9000` (SW_NO_ERROR): Xác thực thành công
- `0x6985` (SW_CONDITIONS_NOT_SATISFIED): PIN chưa được khởi tạo
- `0x6982` (SW_SECURITY_STATUS_NOT_SATISFIED): PIN không đúng
- `0x6983` (SW_AUTHENTICATION_METHOD_BLOCKED): PIN bị khóa do nhập sai quá số lần cho phép (3 lần)

---

### 1.3. UPDATE_PIN - Cập nhật PIN

**Mô tả**: Thay đổi mã PIN hiện tại. Yêu cầu đã xác thực PIN trước đó.

**Command**:

```
CLA: 0x80
INS: 0x12
P1:  0x00
P2:  0x00
Lc:  [1 + độ dài PIN cũ + độ dài PIN mới]
Data: [curPinLen:1][curPin][newPin]
```

**Tham số**:

- `Lc`: Tổng độ dài = 1 (cho curPinLen) + độ dài PIN cũ + độ dài PIN mới
- `Data[0]`: Độ dài PIN hiện tại (1 byte)
- `Data[1..curPinLen]`: PIN hiện tại
- `Data[curPinLen+1..]`: PIN mới

**Ví dụ**:

```
// Đổi PIN từ "123456" sang "654321"
// curPinLen=6, curPin="123456", newPin="654321"
Command: 80 12 00 00 0E 06 31 32 33 34 35 36 36 35 34 33 32 31
```

**Response codes**:

- `0x9000` (SW_NO_ERROR): Cập nhật PIN thành công
- `0x6985` (SW_CONDITIONS_NOT_SATISFIED): PIN chưa được khởi tạo
- `0x6982` (SW_SECURITY_STATUS_NOT_SATISFIED): PIN hiện tại không đúng hoặc chưa xác thực

---

### 1.4. RESET_PIN - Reset PIN

**Mô tả**: Xóa PIN và reset trạng thái khởi tạo. Sau khi reset, cần phải khởi tạo PIN lại. Yêu cầu đã xác thực PIN trước đó.

**Command**:

```
CLA: 0x80
INS: 0x13
P1:  0x00
P2:  0x00
Lc:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```
Command: 80 13 00 00 00
```

**Response codes**:

- `0x9000` (SW_NO_ERROR): Reset PIN thành công
- `0x6982` (SW_SECURITY_STATUS_NOT_SATISFIED): Chưa xác thực PIN

---

### 1.5. IS_PIN_INITIALIZED - Kiểm tra trạng thái PIN

**Mô tả**: Kiểm tra xem PIN đã được khởi tạo chưa.

**Command**:

```
CLA: 0x80
INS: 0x14
P1:  0x00
P2:  0x00
Le:  0x01
```

**Tham số**: Không có

**Ví dụ**:

```
Command: 80 14 00 00 00 01
```

**Response**:

- Data: `0x01` nếu PIN đã khởi tạo, `0x00` nếu chưa
- Status: `0x9000`

**Response codes**:

- `0x9000` (SW_NO_ERROR): Thành công, kiểm tra byte dữ liệu trả về

---

## 2. Quản lý KeyPair (Cặp khóa EC)

### 2.1. GEN_KEY_PAIR - Sinh cặp khóa

**Mô tả**: Sinh một cặp khóa EC (secp256k1) mới. Yêu cầu đã xác thực PIN.

**Command**:

```
CLA: 0x80
INS: 0x20
P1:  0x00
P2:  0x00
Lc:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```
Command: 80 20 00 00 00
```

**Response codes**:

- `0x9000` (SW_NO_ERROR): Sinh khóa thành công
- `0x6985` (SW_CONDITIONS_NOT_SATISFIED): PIN chưa được khởi tạo
- `0x6982` (SW_SECURITY_STATUS_NOT_SATISFIED): Chưa xác thực PIN

---

### 2.2. GET_PUBLIC_KEY - Lấy Public Key

**Mô tả**: Lấy public key đã được sinh. Yêu cầu đã xác thực PIN.

**Command**:

```
CLA: 0x80
INS: 0x21
P1:  0x00
P2:  0x00
Le:  0x00 (hoặc 0x41 để nhận 65 bytes)
```

**Tham số**: Không có

**Ví dụ**:

```
Command: 80 21 00 00 00 00
```

**Response**:

- Data: 65 bytes public key (uncompressed format: 0x04 + X coordinate 32 bytes + Y coordinate 32 bytes)
- Status: `0x9000`

**Response codes**:

- `0x9000` (SW_NO_ERROR): Lấy public key thành công
- `0x6985` (SW_CONDITIONS_NOT_SATISFIED): PIN chưa được khởi tạo hoặc chưa sinh khóa
- `0x6982` (SW_SECURITY_STATUS_NOT_SATISFIED): Chưa xác thực PIN

---

### 2.3. SIGN_HASH - Ký hash

**Mô tả**: Ký một hash data bằng private key. Signature được Low-S normalized để ngăn chặn transaction malleability.

**Command**:

```
CLA: 0x80
INS: 0x22
P1:  0x00
P2:  0x00
Lc:  0x20 (32 bytes)
Data: [32-byte hash]
Le:  0x00
```

**Tham số**:

- `Data`: Hash 32 bytes cần ký (thường là Keccak-256 hash của transaction, đã được tính toán sẵn)

**Ví dụ**:

```
// Ký hash (32 bytes)
Command: 80 22 00 00 20 [32 bytes hash] 00
```

**Response**:

- Data: DER-encoded ECDSA signature (Low-S normalized)
  - Format: 0x30 [totalLen] 0x02 [rLen] [r...] 0x02 [sLen] [s...]
  - s <= n/2 để ngăn chặn transaction malleability
- Status: `0x9000`

**Response codes**:

- `0x9000` (SW_NO_ERROR): Ký thành công
- `0x6985` (SW_CONDITIONS_NOT_SATISFIED): PIN chưa được khởi tạo hoặc chưa sinh khóa
- `0x6982` (SW_SECURITY_STATUS_NOT_SATISFIED): Chưa xác thực PIN

---

## 3. Mã Response phổ biến

| Status Code | Constant                         | Ý nghĩa                                          |
| ----------- | -------------------------------- | ------------------------------------------------ |
| `0x9000`    | SW_NO_ERROR                      | Thành công                                       |
| `0x6982`    | SW_SECURITY_STATUS_NOT_SATISFIED | Chưa xác thực PIN hoặc PIN sai                   |
| `0x6983`    | SW_AUTHENTICATION_METHOD_BLOCKED | PIN bị khóa                                      |
| `0x6985`    | SW_CONDITIONS_NOT_SATISFIED      | Điều kiện không thỏa mãn (VD: PIN chưa khởi tạo) |
| `0x6A86`    | SW_INCORRECT_P1P2                | Tham số P1/P2 không hợp lệ                       |
| `0x6D00`    | SW_INS_NOT_SUPPORTED             | Lệnh không được hỗ trợ                           |
| `0x6E00`    | SW_CLA_NOT_SUPPORTED             | Class byte không được hỗ trợ                     |

---

## 4. Workflow sử dụng điển hình

### 4.1. Thiết lập thẻ lần đầu

```
1. IS_PIN_INITIALIZED    -> Kiểm tra PIN đã khởi tạo chưa
2. INIT_PIN              -> Khởi tạo PIN (nếu chưa)
3. VERIFY_PIN            -> Xác thực PIN
4. GEN_KEY_PAIR          -> Sinh cặp khóa
5. GET_PUBLIC_KEY        -> Lấy public key để lưu trữ/sử dụng
```

### 4.2. Ký giao dịch

```
1. VERIFY_PIN            -> Xác thực PIN
2. SIGN_HASH             -> Ký hash của transaction
```

### 4.3. Đổi PIN

```
1. VERIFY_PIN            -> Xác thực PIN cũ
2. UPDATE_PIN            -> Cập nhật PIN mới
```

### 4.4. Reset thẻ

```
1. RESET_PIN             -> Xóa PIN
2. INIT_PIN              -> Khởi tạo PIN mới
3. VERIFY_PIN            -> Xác thực PIN
4. GEN_KEY_PAIR          -> Sinh cặp khóa mới
```

---

## 5. Lưu ý bảo mật

1. **PIN Security**:
   - PIN chỉ có thể nhập sai tối đa 3 lần (Configuration.PIN_TRY_LIMIT)
   - Sau 3 lần sai, thẻ sẽ bị khóa (SW_AUTHENTICATION_METHOD_BLOCKED)
   - Cần RESET_PIN để mở khóa
   - UPDATE_PIN yêu cầu xác thực PIN hiện tại trước khi đổi
   - RESET_PIN yêu cầu đã xác thực PIN trước đó

2. **Key Protection**:
   - Private key không bao giờ được xuất ra ngoài thẻ
   - Mọi thao tác với private key đều yêu cầu xác thực PIN
   - Public key chỉ có thể đọc sau khi xác thực PIN

3. **Session Management**:
   - Xác thực PIN có hiệu lực trong phiên làm việc hiện tại
   - Sau khi ngắt kết nối hoặc select applet khác, cần xác thực lại PIN

4. **Transaction Malleability Protection**:
   - Signature được Low-S normalized (s <= n/2) trước khi trả về
   - Ngăn chặn việc tạo nhiều signature hợp lệ từ cùng một transaction

---

## 6. Hỗ trợ

Nếu có vấn đề khi tích hợp, vui lòng liên hệ team applet hoặc tạo issue trên repository.

**Repository**: https://github.com/Chainora/chainora-applet
