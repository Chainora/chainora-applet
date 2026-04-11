# Tài liệu APDU Commands - ChainoraWallet

## Giới thiệu

Tài liệu này mô tả các APDU command để tương tác với applet **ChainoraWallet** trên JavaCard. Applet hỗ trợ:

- quản lý PIN
- quản lý wallet keypair secp256k1
- device identity / certificate provisioning
- backend card attestation
- backup wallet bằng mutual authentication + ECDH

**Applet AID**: `F0564E43485701`

---

## Cấu trúc APDU Command

```text
CLA  INS  P1  P2  Lc  Data  Le
```

- **CLA**: `0x80`
- **INS**: mã lệnh
- **P1, P2**: tham số bổ sung
- **Lc**: độ dài data gửi lên card
- **Data**: payload của command
- **Le**: độ dài dữ liệu mong đợi trả về

---

## 1. Quản lý PIN

### 1.1. INIT_PIN - Khởi tạo PIN

**Mô tả**: Khởi tạo PIN lần đầu tiên cho thẻ. Chỉ thực hiện được một lần cho đến khi `RESET_PIN`.

**Command**:

```text
CLA: 0x80
INS: 0x10
P1:  0x00
P2:  0x00
Lc:  [độ dài PIN]
Data: [PIN bytes]
```

**Tham số**:

- `Lc`: độ dài PIN, tối đa 8 byte
- `Data`: PIN dạng byte array

**Ví dụ**:

```text
// PIN = "123456"
Command: 80 10 00 00 06 31 32 33 34 35 36
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: PIN đã được khởi tạo trước đó

---

### 1.2. VERIFY_PIN - Xác thực PIN

**Mô tả**: Xác thực PIN để mở khóa các chức năng yêu cầu bảo mật.

**Command**:

```text
CLA: 0x80
INS: 0x11
P1:  0x00
P2:  0x00
Lc:  [độ dài PIN]
Data: [PIN bytes]
```

**Tham số**:

- `Lc`: độ dài PIN
- `Data`: PIN cần xác thực

**Ví dụ**:

```text
Command: 80 11 00 00 06 31 32 33 34 35 36
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: PIN chưa được khởi tạo
- `0x6982`: PIN không đúng
- `0x6983`: PIN bị khóa do nhập sai quá số lần cho phép

---

### 1.3. UPDATE_PIN - Cập nhật PIN

**Mô tả**: Đổi PIN hiện tại. Yêu cầu cung cấp đúng PIN hiện tại.

**Command**:

```text
CLA: 0x80
INS: 0x12
P1:  0x00
P2:  0x00
Lc:  [1 + độ dài PIN cũ + độ dài PIN mới]
Data: [curPinLen:1][curPin][newPin]
```

**Tham số**:

- `Data[0]`: độ dài PIN hiện tại
- `Data[1..]`: PIN hiện tại nối tiếp PIN mới

**Ví dụ**:

```text
// đổi từ "123456" sang "654321"
Command: 80 12 00 00 0D 06 31 32 33 34 35 36 36 35 34 33 32 31
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: PIN chưa được khởi tạo
- `0x6982`: PIN hiện tại không đúng hoặc chưa xác thực được yêu cầu nội bộ

---

### 1.4. RESET_PIN - Reset PIN

**Mô tả**: Xóa PIN và đưa card về trạng thái chưa khởi tạo PIN. Yêu cầu đã verify PIN trong session hiện tại.

**Command**:

```text
CLA: 0x80
INS: 0x13
P1:  0x00
P2:  0x00
Lc:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 13 00 00 00
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6982`: chưa xác thực PIN

---

### 1.5. IS_PIN_INITIALIZED - Kiểm tra trạng thái PIN

**Mô tả**: Kiểm tra xem PIN đã được khởi tạo hay chưa.

**Command**:

```text
CLA: 0x80
INS: 0x14
P1:  0x00
P2:  0x00
Le:  0x01
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 14 00 00 00 01
```

**Response**:

- Data: `0x01` nếu đã khởi tạo, `0x00` nếu chưa
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công

---

## 2. Quản lý Wallet KeyPair

### 2.1. GEN_KEY_PAIR - Sinh cặp khóa

**Mô tả**: Sinh wallet keypair secp256k1 mới. Yêu cầu đã verify PIN.

**Command**:

```text
CLA: 0x80
INS: 0x20
P1:  0x00
P2:  0x00
Lc:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 20 00 00 00
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: PIN chưa được khởi tạo
- `0x6982`: chưa xác thực PIN

---

### 2.2. GET_PUBLIC_KEY - Lấy public key

**Mô tả**: Đọc wallet public key đã sinh. Yêu cầu đã verify PIN.

**Command**:

```text
CLA: 0x80
INS: 0x21
P1:  0x00
P2:  0x00
Le:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 21 00 00 00 00
```

**Response**:

- Data: 65 byte public key secp256k1 uncompressed (`0x04 || X || Y`)
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: PIN chưa được khởi tạo hoặc chưa có keypair
- `0x6982`: chưa xác thực PIN

---

### 2.3. SIGN_HASH - Ký hash

**Mô tả**: Ký hash 32 byte bằng wallet private key. Signature trả về ở dạng DER ECDSA và được low-S normalize.

**Command**:

```text
CLA: 0x80
INS: 0x22
P1:  0x00
P2:  0x00
Lc:  0x20
Data: [32-byte hash]
Le:  0x00
```

**Tham số**:

- `Data`: hash 32 byte đã được tính sẵn ở phía host

**Ví dụ**:

```text
Command: 80 22 00 00 20 [32 bytes hash] 00
```

**Response**:

- Data: DER-encoded ECDSA signature
- Format: `30 [len] 02 [rLen] [r] 02 [sLen] [s]`
- `s <= n/2` để tránh malleability
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: PIN chưa được khởi tạo hoặc chưa có keypair
- `0x6982`: chưa xác thực PIN

---

## 3. Device Identity Và Backend Attestation

### 3.1. GET_DEVICE_CERT - Lấy device certificate

**Mô tả**: Đọc device certificate đã được factory provision trên thẻ.

**Command**:

```text
CLA: 0x80
INS: 0x23
P1:  0x00
P2:  0x00
Lc:  0x00
Le:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 23 00 00 00 00
```

**Response**:

- Data format:

```text
[version:1][deviceId:16][deviceAuthPublicKey:65][capabilities:1][sigLen:1][sigDer:sigLen]
```

- `version`: hiện tại = `0x01`
- `deviceId`: định danh 16 byte của thẻ
- `deviceAuthPublicKey`: public key secp256k1 uncompressed
- `capabilities`: bitmap capability, hiện tại phải có bit backup `0x01`
- `sigLen`: độ dài chữ ký DER
- `sigDer`: chữ ký ECDSA SHA-256 của factory trên phần body certificate
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6A83`: chưa có device certificate
- `0x6A86`: P1/P2 không hợp lệ

---

### 3.2. GET_FACTORY_CSR - Lấy factory CSR

**Mô tả**: Đọc CSR blob từ thẻ để factory/dev tooling ký thành device certificate.

**Command**:

```text
CLA: 0x80
INS: 0x23
P1:  0x10
P2:  0x00
Lc:  0x00
Le:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 23 10 00 00 00
```

**Response**:

- Data format:

```text
[version:1][deviceId:16][deviceAuthPublicKey:65]
```

- `version`: hiện tại = `0x01`
- `deviceId`: định danh 16 byte của thẻ
- `deviceAuthPublicKey`: public key secp256k1 uncompressed
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6A86`: P1/P2 không hợp lệ

---

### 3.3. SET_DEVICE_CERT - Ghi device certificate

**Mô tả**: Ghi device certificate đã được factory ký vào thẻ. Chỉ được ghi một lần.

**Command**:

```text
CLA: 0x80
INS: 0x23
P1:  0x11
P2:  0x00
Lc:  [độ dài certificate]
Data: [device certificate]
```

**Tham số**:

- `Data` có format:

```text
[version:1][deviceId:16][deviceAuthPublicKey:65][capabilities:1][sigLen:1][sigDer:sigLen]
```

**Ví dụ**:

```text
Command: 80 23 11 00 [Lc] [certificate bytes]
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: certificate đã được ghi trước đó
- `0x6984`: certificate sai format, sai binding với thẻ, hoặc capability không hợp lệ
- `0x6982`: chữ ký certificate không verify được bằng factory root key
- `0x6A86`: P1/P2 không hợp lệ

---

### 3.4. CARD_ATTEST - Ký backend challenge

**Mô tả**: Thẻ ký challenge 32 byte do backend sinh bằng `deviceAuthPrivateKey`.

**Command**:

```text
CLA: 0x80
INS: 0x24
P1:  0x00
P2:  0x00
Lc:  0x20
Data: [32-byte challenge]
Le:  0x00
```

**Tham số**:

- `Data`: challenge 32 byte từ backend

**Ví dụ**:

```text
Command: 80 24 00 00 20 [32 bytes challenge] 00
```

**Response**:

- Data format:

```text
[version:1][deviceId:16][challenge:32][sigLen:1][sigDer:sigLen]
```

- `version`: hiện tại = `0x01`
- `deviceId`: định danh 16 byte của thẻ
- `challenge`: echo lại đúng challenge đã gửi vào
- `sigLen`: độ dài chữ ký DER
- `sigDer`: chữ ký ECDSA SHA-256 trên `[version][deviceId][challenge]`
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6700`: challenge không đúng 32 byte
- `0x6A83`: chưa có device certificate
- `0x6984`: lỗi dữ liệu nội bộ hoặc signature không hợp lệ
- `0x6A86`: P1/P2 không hợp lệ

---

## 4. Backup Key Bằng Mutual Authentication + ECDH

### 4.1. START_LINK_PROOF - Tạo link proof

**Mô tả**: Tạo ephemeral link keypair + nonce cho session backup, sau đó ký link proof bằng `deviceAuthPrivateKey`.

**Command**:

```text
CLA: 0x80
INS: 0x30
P1:  0x01
P2:  0x00
Lc:  0x00
Le:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 30 01 00 00 00
```

**Response**:

- Data format:

```text
[version:1][sessionId:2][counter:2][deviceId:16][linkPublicKey:65][nonce:16][sigLen:1][sigDer:sigLen]
```

- `version`: hiện tại = `0x02`
- `sessionId`: định danh 2 byte của session backup
- `counter`: hiện tại = `0x0001`
- `deviceId`: định danh 16 byte của thẻ
- `linkPublicKey`: public key ephemeral secp256k1 uncompressed
- `nonce`: nonce 16 byte của session
- `sigDer`: chữ ký trên toàn bộ body link proof
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: chưa có device certificate
- `0x6984`: public key hoặc signature nội bộ không hợp lệ
- `0x6A86`: P1/P2 không hợp lệ

---

### 4.2. LOAD_PEER_CERT - Nạp certificate của peer

**Mô tả**: Nạp device certificate của card đối tác để chuẩn bị mutual authentication.

**Command**:

```text
CLA: 0x80
INS: 0x30
P1:  0x02
P2:  0x00
Lc:  [độ dài peer certificate]
Data: [peer certificate]
```

**Tham số**:

- `Data`: raw certificate lấy từ `GET_DEVICE_CERT`

**Ví dụ**:

```text
Command: 80 30 02 00 [Lc] [peer certificate bytes]
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6984`: certificate sai format hoặc capability không hợp lệ
- `0x6982`: chữ ký certificate không hợp lệ
- `0x6A86`: P1/P2 không hợp lệ

---

### 4.3. LOAD_PEER_LINK_PROOF - Nạp link proof của peer

**Mô tả**: Nạp link proof của peer, verify `deviceId`, `counter`, public key ephemeral và chữ ký.

**Command**:

```text
CLA: 0x80
INS: 0x30
P1:  0x03
P2:  0x00
Lc:  [độ dài peer link proof]
Data: [peer link proof]
```

**Tham số**:

- `Data`: payload lấy từ `START_LINK_PROOF`
- Chỉ chấp nhận `version = 0x02` và `counter = 0x0001`
- Sau 3 lần lỗi `length/data/security` trong cùng session, command sẽ bị lock cho đến khi reset state

**Ví dụ**:

```text
Command: 80 30 03 00 [Lc] [peer link proof bytes]
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: thiếu local link proof, thiếu peer cert, proof đã load rồi, hoặc command bị lock
- `0x6982`: `deviceId`, counter, hoặc chữ ký peer proof không hợp lệ
- `0x6984`: version, `sigLen`, hoặc nội dung proof không hợp lệ
- `0x6700`: độ dài peer proof không hợp lệ
- `0x6A86`: P1/P2 không hợp lệ

---

### 4.4. CLEAR_LINK_STATE - Xóa backup session state

**Mô tả**: Xóa local/peer backup state để bắt đầu lại flow backup.

**Command**:

```text
CLA: 0x80
INS: 0x30
P1:  0x04
P2:  0x00
Lc:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 30 04 00 00
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6A86`: P1/P2 không hợp lệ

---

### 4.5. BACKUP_EXPORT - Xuất backup envelope

**Mô tả**: Card nguồn mã hóa wallet key material bằng session key từ ECDH và trả về backup envelope đã ký.

**Command**:

```text
CLA: 0x80
INS: 0x31
P1:  0x00
P2:  0x00
Lc:  0x00
Le:  0x00
```

**Tham số**: Không có

**Ví dụ**:

```text
Command: 80 31 00 00 00 00
```

**Response**:

- Data format:

```text
[version:1][sessionId:2][counter:2][sourceDeviceId:16][destDeviceId:16][iv:16][cipherLen:1][cipher:cipherLen][sigLen:1][sigDer:sigLen]
```

- `version`: hiện tại = `0x02`
- `counter`: hiện tại = `0x0002`
- `iv`: AES-CBC IV 16 byte
- `cipher`: payload backup đã pad và mã hóa
- `sigDer`: chữ ký của source device auth key trên phần body envelope
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: chưa đủ precondition, chưa verify PIN, chưa có wallet key, hoặc chưa hoàn tất mutual auth
- `0x6982`: chưa xác thực PIN hoặc security check của session backup không đạt
- `0x6984`: dữ liệu mã hóa hoặc signature nội bộ không hợp lệ
- `0x6A86`: P1/P2 không hợp lệ

---

### 4.6. BACKUP_IMPORT - Nhập backup envelope

**Mô tả**: Card đích verify envelope, giải mã payload bằng session key tương ứng và import wallet key material.

**Command**:

```text
CLA: 0x80
INS: 0x32
P1:  0x00
P2:  0x00
Lc:  [độ dài backup envelope]
Data: [backup envelope]
```

**Tham số**:

- `Data`: envelope lấy từ `BACKUP_EXPORT`
- Chỉ chấp nhận `version = 0x02`, `counter = 0x0002`, và `sessionId` khớp session hiện tại
- Sau 3 lần lỗi `length/data/security` trong cùng session, command sẽ bị lock cho đến khi reset state

**Ví dụ**:

```text
Command: 80 32 00 00 [Lc] [backup envelope bytes]
```

**Response**:

- Không có data
- Status: `0x9000`

**Response codes**:

- `0x9000`: thành công
- `0x6985`: chưa đủ precondition, command bị lock, hoặc card đích đang có wallet key khác
- `0x6982`: chưa xác thực PIN, hoặc `sessionId`, `deviceId`, counter, chữ ký envelope không hợp lệ
- `0x6984`: envelope, payload, padding, hoặc dữ liệu key không hợp lệ
- `0x6700`: độ dài envelope / ciphertext không hợp lệ
- `0x6A86`: P1/P2 không hợp lệ

---

## 5. Mã Response Phổ Biến

| Status Code | Constant                         | Ý nghĩa |
| ----------- | -------------------------------- | ------- |
| `0x9000`    | SW_NO_ERROR                      | Thành công |
| `0x6700`    | SW_WRONG_LENGTH                  | Độ dài input không đúng |
| `0x6982`    | SW_SECURITY_STATUS_NOT_SATISFIED | Chưa xác thực PIN hoặc security check không đạt |
| `0x6983`    | SW_AUTHENTICATION_METHOD_BLOCKED | PIN bị khóa |
| `0x6984`    | SW_DATA_INVALID                  | Dữ liệu input không hợp lệ |
| `0x6985`    | SW_CONDITIONS_NOT_SATISFIED      | Điều kiện tiên quyết chưa đạt |
| `0x6A83`    | SW_RECORD_NOT_FOUND              | Chưa có device certificate |
| `0x6A86`    | SW_INCORRECT_P1P2                | P1/P2 không hợp lệ |
| `0x6D00`    | SW_INS_NOT_SUPPORTED             | INS không được hỗ trợ |
| `0x6E00`    | SW_CLA_NOT_SUPPORTED             | CLA không được hỗ trợ |

---

## 6. Workflow Sử Dụng Điển Hình

### 6.1. Thiết lập thẻ lần đầu

```text
1. IS_PIN_INITIALIZED
2. INIT_PIN
3. VERIFY_PIN
4. GEN_KEY_PAIR
5. GET_PUBLIC_KEY
```

### 6.2. Provision device certificate

```text
1. GET_FACTORY_CSR
2. Factory ký CSR off-card
3. SET_DEVICE_CERT
4. GET_DEVICE_CERT
```

### 6.3. Backend verify card

```text
1. GET_DEVICE_CERT
2. Backend verify certificate bằng factory root public key
3. Backend sinh challenge 32 byte
4. CARD_ATTEST
5. Backend verify proof bằng deviceAuthPublicKey trong certificate
```

### 6.4. Ký giao dịch

```text
1. VERIFY_PIN
2. SIGN_HASH
```

### 6.5. Đổi PIN

```text
1. VERIFY_PIN
2. UPDATE_PIN
```

### 6.6. Reset thẻ

```text
1. RESET_PIN
2. INIT_PIN
3. VERIFY_PIN
4. GEN_KEY_PAIR
```

### 6.7. Backup source -> destination

```text
1. (Destination) GET_DEVICE_CERT
2. (Destination) START_LINK_PROOF
3. (Source) GET_DEVICE_CERT
4. (Source) START_LINK_PROOF
5. (Source) LOAD_PEER_CERT(dest cert)
6. (Source) LOAD_PEER_LINK_PROOF(dest proof)
7. (Source) VERIFY_PIN
8. (Source) BACKUP_EXPORT
9. (Destination) LOAD_PEER_CERT(source cert)
10. (Destination) LOAD_PEER_LINK_PROOF(source proof)
11. (Destination) VERIFY_PIN
12. (Destination) BACKUP_IMPORT
```

---

## 7. Lưu Ý Bảo Mật

1. **PIN Security**
   - PIN chỉ có thể nhập sai tối đa 3 lần.
   - Sau khi bị khóa, cần reset / reprovision theo flow phù hợp.

2. **Wallet Key Protection**
   - Wallet private key không bao giờ được export thô qua APDU.
   - `SIGN_HASH` yêu cầu verify PIN trước.

3. **Device Identity**
   - `deviceAuthPrivateKey` tách riêng khỏi wallet private key.
   - `CARD_ATTEST` chỉ chứng minh genuine card + possession của `deviceAuthPrivateKey`.
   - `CARD_ATTEST` không chứng minh user đã nhập PIN.

4. **Certificate Trust Model**
   - Device certificate phải được ký bởi Chainora factory root key hardcoded trong applet.
   - Host đã bỏ hoàn toàn path cũ qua `INS 0x30` cho cert/factory. Các lệnh `GET_DEVICE_CERT`, `GET_FACTORY_CSR`, `SET_DEVICE_CERT` chỉ còn ở `INS 0x23`.

5. **Backup Security**
   - Backup chỉ hoàn tất sau khi verify peer cert và peer link proof.
   - Backup payload được AES-CBC encrypt bằng session key dẫn xuất từ ECDH.
   - Envelope được ký để đảm bảo integrity.

6. **Replay / Abuse Guard**
   - `CARD_ATTEST` nên dùng challenge one-time, TTL ngắn, do backend quản lý.
   - `LOAD_PEER_LINK_PROOF` và `BACKUP_IMPORT` có cơ chế lock sau 3 lần sai trong cùng session.

---

## 8. Hỗ Trợ

Nếu có vấn đề khi tích hợp, vui lòng liên hệ team applet hoặc tạo issue trên repository.

**Repository**: https://github.com/Chainora/chainora-applet
