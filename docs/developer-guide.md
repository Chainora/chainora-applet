# Tài liệu Phát triển Applet ChainoraWallet

## 1. Giới thiệu dự án

### 1.1. Tổng quan

**ChainoraWallet** là một ứng dụng JavaCard (applet) chạy trên thẻ thông minh (smart card), cung cấp chức năng ví tiền điện tử Ethereum. Applet lưu trữ cặp khóa EC (secp256k1) và ký giao dịch trực tiếp trên thẻ - private key không bao giờ rời khỏi thẻ.

**Kiến trúc hệ thống:**

```
┌─────────────────────────────────────────────────────────────────┐
│                        Desktop Client (Java)                    │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐   │
│  │ PinManager  │ │ KeyManager  │ │     WalletManager       │   │
│  └──────┬──────┘ └──────┬──────┘ └───────────┬─────────────┘   │
│         │               │                     │                 │
│         └───────────────┴─────────────────────┘                 │
│                          │                                      │
│              cz.muni.fi.crocs.rcard.client                      │
│                          │                                      │
└──────────────────────────┼──────────────────────────────────────┘
                           │ APDU Commands
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   JavaCard Applet (On-Card)                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  ChainoraWallet                         │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │   │
│  │  │PinValidator │ │CommandDisp. │ │Secp256k1 Params │   │   │
│  │  └──────┬──────┘ └──────┬──────┘ └────────┬────────┘   │   │
│  │         │               │                 │             │   │
│  │  ┌──────┴───────┐ ┌─────┴─────┐ ┌────────┴────────┐   │   │
│  │  │PinCommand    │ │KeyCommand  │ │SignCommand      │   │   │
│  │  │Handler       │ │Handler     │ │Handler          │   │   │
│  │  └──────────────┘ └────────────┘ └─────────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**Hai thành phần chính:**

| Module | Mô tả | Công nghệ |
|--------|-------|-----------|
| `applet` | JavaCard applet chạy trên thẻ | JavaCard 3.0.5u3 |
| `client` | Ứng dụng desktop giao tiếp với thẻ | Java 8, Gradle |

### 1.2. Tính năng chính

- **Quản lý PIN**: Khởi tạo, xác thực, cập nhật, reset PIN
- **Quản lý khóa**: Sinh cặp khóa EC secp256k1, lấy public key
- **Ký giao dịch**: Ký hash giao dịch với Low-S normalization
- **Backup key bảo mật**: Mutual authentication bằng certificate chain + ECDH encrypted transfer
- **Bảo mật**: Private key không rời khỏi thẻ, PIN-based authentication

---

## 2. Cấu trúc dự án

### 2.1. Thư mục gốc

```
chainora-applet/
├── applet/                    # JavaCard applet module
│   ├── src/main/java/         # Source code
│   │   └── com/chainora/wallet/
│   │       ├── ChainoraWallet.java      # Main applet
│   │       ├── CommandHandler.java      # Interface
│   │       ├── CommandDispatcher.java   # Router
│   │       ├── PinCommandHandler.java   # PIN operations
│   │       ├── KeyCommandHandler.java   # Key operations
│   │       ├── SignCommandHandler.java  # Signing
│   │       ├── BackupCommandHandler.java # Provisioning + backup flow
│   │       ├── PinValidator.java        # PIN validation
│   │       ├── ApduUtils.java           # APDU utilities
│   │       ├── Secp256k1.java           # Curve params
│   │       └── Configuration.java       # Constants
│   ├── src/test/java/         # Unit tests
│   │   └── tests/
│   └── build.gradle           # Applet build config
├── client/                    # Desktop client module
│   └── src/main/java/
├── docs/                      # Documentation
│   ├── apdu-command.md        # APDU protocol reference
│   └── developer-guide.md     # This file
└── build.gradle               # Root build config
```

### 2.2. Applet Source Code

**Core Classes (Điều phối chính)**

| File | Mô tả |
|------|-------|
| `ChainoraWallet.java` | Entry point chính, xử lý vòng đời applet và dispatch commands |

**Abstractions (Dependency Inversion)**

| File | Mô tả |
|------|-------|
| `CommandHandler.java` | Interface định nghĩa method `process(APDU, byte)` cho handlers |

**Command Dispatcher (Open-Closed Principle)**

| File | Mô tả |
|------|-------|
| `CommandDispatcher.java` | Định tuyến APDU commands đến handlers qua registry pattern |

**Command Handlers (Single Responsibility Principle)**

| File | INS | Mô tả |
|------|-----|-------|
| `PinCommandHandler.java` | 0x10-0x14 | Tất cả thao tác PIN |
| `KeyCommandHandler.java` | 0x20-0x21 | Sinh khóa và lấy public key |
| `SignCommandHandler.java` | 0x22 | Ký hash |
| `BackupCommandHandler.java` | 0x30-0x32 | Provisioning cert, mutual auth, ECDH backup |

**Utilities (DRY Principle)**

| File | Mô tả |
|------|-------|
| `PinValidator.java` | Logic xác thực và validate PIN tập trung |
| `ApduUtils.java` | Các method tiện ích cho APDU |
| `Configuration.java` | Hằng số cấu hình (PIN max size, retry limit) |
| `Secp256k1.java` | Tham số đường cong secp256k1 |

---

## 3. Chi tiết các thành phần

### 3.1. ChainoraWallet.java - Entry Point

```java
public class ChainoraWallet extends Applet {
    private final CommandDispatcher dispatcher;
    private final PinValidator pinValidator;

    private ChainoraWallet(byte[] bArray, short bOffset, byte bLength) {
        // Đăng ký các command handlers
        pinValidator = new PinValidator();
        dispatcher = new CommandDispatcher();
        dispatcher.register((byte) 0x10, new PinCommandHandler(pinValidator));
        dispatcher.register((byte) 0x11, new PinCommandHandler(pinValidator));
        dispatcher.register((byte) 0x12, new PinCommandHandler(pinValidator));
        dispatcher.register((byte) 0x13, new PinCommandHandler(pinValidator));
        dispatcher.register((byte) 0x14, new PinCommandHandler(pinValidator));
        dispatcher.register((byte) 0x20, new KeyCommandHandler(pinValidator));
        dispatcher.register((byte) 0x21, new KeyCommandHandler(pinValidator));
        dispatcher.register((byte) 0x22, new SignCommandHandler(pinValidator, privateKey, signature));
        register();
    }

    @Override
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            return;
        }
        byte ins = buffer[ISO7816.OFFSET_INS];
        dispatcher.dispatch(apdu, ins);
    }
}
```

**Điểm quan trọng:**
- `selectingApplet()` kiểm tra nếu đây là lệnh SELECT (chọn applet)
- `dispatch()` gọi handler phù hợp dựa trên INS byte
- Các handlers được đăng ký với instruction code tương ứng

### 3.2. CommandHandler Interface

```java
public interface CommandHandler {
    /**
     * Xử lý APDU command.
     * @param apdu APDU buffer
     * @param ins Instruction byte
     * @return Status word (thường là SW_NO_ERROR)
     */
    short process(APDU apdu, byte ins);
}
```

**Pattern:**
- Mỗi command handler implement interface này
- `process()` xử lý logic và throw ISOException nếu lỗi
- Trả về SW_NO_ERROR (0x9000) khi thành công

### 3.3. CommandDispatcher - Registry Pattern

```java
public class CommandDispatcher {
    private static final byte MAP_SIZE = 20;
    private final byte[] keys = new byte[MAP_SIZE];
    private final CommandHandler[] handlers = new CommandHandler[MAP_SIZE];
    private short count = 0;

    public void register(byte ins, CommandHandler handler) {
        keys[count] = ins;
        handlers[count] = handler;
        count++;
    }

    public void dispatch(APDU apdu, byte ins) {
        for (short i = 0; i < count; i++) {
            if (keys[i] == ins) {
                handlers[i].process(apdu, ins);
                return;
            }
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}
```

**Lợi ích:**
- **Open-Closed**: Thêm command mới không cần sửa dispatcher
- **Single Responsibility**: Mỗi handler chỉ lo về logic của mình
- **Extensibility**: Dễ dàng thêm handlers mới

### 3.4. PinValidator - DRY Principle

Tập trung logic PIN validation để tránh duplicate code:

```java
public class PinValidator {
    private byte[] pin = new byte[Configuration.PIN_MAX_SIZE];
    private byte pinLen = 0;
    private boolean initialized = false;
    private byte tryCount = 0;

    // Các method chính:
    public void ensureInitialized();       // Ném ngoại lệ nếu chưa init
    public void ensureValidated();         // Ném ngoại lệ nếu chưa validate
    public void validatePinLength(short len); // Validate độ dài PIN
    public void updatePin(byte[] data, short offset, byte len); // Cập nhật PIN
    public boolean checkPin(byte[] data, short offset, byte len); // Kiểm tra PIN
    public boolean isInitialized();        // Trạng thái init
    public void markInitialized();         // Đánh dấu đã init
    public void reset();                   // Reset về trạng thái ban đầu
}
```

**Bảo mật:**
- Tối đa 3 lần thử sai PIN
- Sau 3 lần sai: `SW_AUTHENTICATION_METHOD_BLOCKED`
- RESET_PIN yêu cầu đã xác thực PIN trước đó

### 3.5. Secp256k1 - Đường cong Elliptic

Tham số đường cong secp256k1 (dùng trong Ethereum):

```java
public class Secp256k1 {
    // P: Prime field modulus (256-bit prime)
    public static final byte[] P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        // ... 32 bytes total
    };

    // N: Order of the group (private key range)
    public static final byte[] N = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        // ... 32 bytes total
    };

    // G: Generator point (base point)
    public static final byte[] G = {...};  // 65 bytes uncompressed

    // N/2: Threshold for Low-S normalization
    public static final byte[] N_DIV_2 = {...};
}
```

---

## 4. APDU Protocol

### 4.1. Cấu trúc APDU Command

```
┌─────┬─────┬─────┬─────┬────────┬───────────┬────────┐
│ CLA │ INS │ P1  │ P2  │  Lc    │ Data      │  Le    │
│ 1B  │ 1B  │ 1B  │ 1B  │  1B    │ Lc bytes  │  0-1B  │
└─────┴─────┴─────┴─────┴────────┴───────────┴────────┘
```

| Byte | Ý nghĩa | Giá trị |
|------|---------|---------|
| CLA | Class | 0x80 (applet class) |
| INS | Instruction Code | Mã lệnh cụ thể |
| P1, P2 | Parameters | Thường là 0x00 |
| Lc | Data Length | Số bytes data gửi đi |
| Data | Command Data | Dữ liệu lệnh |
| Le | Expected Length | Số bytes mong đợi nhận về (0x00 = variable) |

### 4.2. Bảng các lệnh

| INS | Tên | Yêu cầu PIN | Data Input | Response |
|-----|-----|-------------|------------|----------|
| 0x10 | INIT_PIN | Không | [PIN bytes] | SW only |
| 0x11 | VERIFY_PIN | Không | [PIN bytes] | SW only |
| 0x12 | UPDATE_PIN | Đã validate | [curLen:1][curPIN][newPIN] | SW only |
| 0x13 | RESET_PIN | Đã validate | - | SW only |
| 0x14 | IS_PIN_INIT | Không | - | 1 byte + SW |
| 0x20 | GEN_KEY_PAIR | Đã validate | - | SW only |
| 0x21 | GET_PUBLIC_KEY | Đã validate | - | 65 bytes + SW |
| 0x22 | SIGN_HASH | Đã validate | [32-byte hash] | DER sig + SW |
| 0x30 | BACKUP_SESSION | Tuỳ subcommand | Subcommand payload | Data/SW |
| 0x31 | BACKUP_EXPORT | Đã validate | - | Backup envelope + SW |
| 0x32 | BACKUP_IMPORT | Đã validate | Backup envelope | SW only |

### 4.3. Mã Response phổ biến

| Status Code | Constant | Ý nghĩa |
|-------------|----------|---------|
| 0x9000 | SW_NO_ERROR | Thành công |
| 0x6982 | SW_SECURITY_STATUS_NOT_SATISFIED | Chưa xác thực/PIN sai |
| 0x6983 | SW_AUTHENTICATION_METHOD_BLOCKED | PIN bị khóa |
| 0x6985 | SW_CONDITIONS_NOT_SATISFIED | Điều kiện không thỏa mãn |
| 0x6984 | SW_DATA_INVALID | Payload backup/cert không hợp lệ |
| 0x6A86 | SW_INCORRECT_P1P2 | Tham số P1/P2 lỗi |
| 0x6A83 | SW_RECORD_NOT_FOUND | Device cert chưa tồn tại |
| 0x6D00 | SW_INS_NOT_SUPPORTED | Lệnh không hỗ trợ |
| 0x6E00 | SW_CLA_NOT_SUPPORTED | CLA không hỗ trợ |

---

## 5. Các nguyên tắc thiết kế

### 5.1. SOLID Principles

**Single Responsibility Principle (SRP)**
- Mỗi handler chỉ xử lý một loại thao tác
- `PinCommandHandler` chỉ xử lý PIN, không biết về key generation

**Open-Closed Principle (OCP)**
- Thêm command mới = tạo handler mới, không sửa dispatcher
- `CommandDispatcher.dispatch()` không thay đổi khi thêm handlers

**Dependency Inversion Principle (DIP)**
- `ChainoraWallet` phụ thuộc vào `CommandHandler` interface
- Các concrete handlers implement interface này

**DRY Principle**
- Logic PIN validation tập trung trong `PinValidator`
- APDU utilities trong `ApduUtils`

### 5.2. Bảo mật

**Low-S Normalization**
- Canonicalization now compares full 32-byte big-int `S` against `N/2` before normalization.
- Signature được normalize để `s <= n/2`
- Ngăn chặn transaction malleability (tạo nhiều sig hợp lệ từ 1 transaction)

**Certificate Chain + ECDH Backup**
- Backup protocol v2 binds `sessionId/counter` into KDF and signed envelope/link-proof payload.
- Per-session DoS guard: `LOAD_PEER_LINK_PROOF` and `BACKUP_IMPORT` lock after 3 invalid attempts until link-state reset.
- Mỗi card có `deviceAuth` keypair riêng, cert được ký bởi root key của Chainora
- Card chỉ tin peer sau khi verify: root -> peer cert -> peer link proof
- Session key backup được dẫn xuất bằng ECDH từ link key ephemeral (per-session)
- Private key transfer luôn ở dạng encrypted envelope; app host không thấy plaintext key

**PIN Protection**
- Private key không thể access nếu chưa validate PIN
- RESET_PIN yêu cầu đã validate
- UPDATE_PIN yêu cầu xác thực PIN hiện tại

---

## 6. Hướng dẫn phát triển

### 6.1. Thiết lập môi trường

```bash
# Yêu cầu
# - Java 8 (8-u271+)
# - Gradle 7+
# - JavaCard SDK 3.0.5u3
# - Thẻ JavaCard hỗ trợ ECC secp256k1

# Clone và build
git clone https://github.com/Chainora/chainora-applet.git
cd chainora-applet

# Build CAP file
./gradlew :applet:buildJavaCard --info --rerun-tasks

# Install lên thẻ (yêu cầu thẻ kết nối qua card reader)
./gradlew :applet:installJavaCard --info --rerun-tasks

# Lưu ý: task install sẽ tự động provision device certificate ngay sau khi cài applet
```

### 6.2. Chạy tests

**Quan trọng:**
- Tests PHẢI chạy trên thẻ vật lý (simulator không hỗ trợ ECC secp256k1)
- Trạng thái trên thẻ KHÔNG reset giữa các tests
- Luôn reinstall applet trước khi test

```bash
# Install và chạy tests
./gradlew :applet:installJavaCard --info --rerun-tasks && \
./gradlew :applet:test --info --rerun-tasks
```

### 6.3. Thêm command mới

**Bước 1:** Tạo Handler mới

```java
public class NewCommandHandler implements CommandHandler {
    private static final byte INS_NEW_CMD = (byte) 0x25;
    private final PinValidator pinValidator;

    public NewCommandHandler(PinValidator pinValidator) {
        this.pinValidator = pinValidator;
    }

    @Override
    public short process(APDU apdu, byte ins) {
        if (ins == INS_NEW_CMD) {
            // Xử lý command
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        return ISO7816.SW_NO_ERROR;
    }
}
```

**Bước 2:** Đăng ký trong ChainoraWallet

```java
// Trong constructor của ChainoraWallet
dispatcher.register(INS_NEW_CMD, new NewCommandHandler(pinValidator));
```

**Bước 3:** Thêm test trong AppletTest.java

### 6.4. Debugging

```java
// Sử dụng ISOException với SW phù hợp
ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

// Log bằng cách ghi vào APDU buffer (chỉ khi debugging)
apdu.getBuffer()[0] = (byte) 0x01;
```

---

## 7. Lưu ý quan trọng

### 7.1. JavaCard Limitations

- **Không có floating point**: Tất cả tính toán số học phải là integer/short
- **Array bounds checking**: JavaCard runtime kiểm tra array bounds
- **Memory limited**: Heap rất hạn chế (KB thay vì MB)
- **No reflection**: Không thể sử dụng reflection API
- **Signed bytes**: Java bytes là signed (-128 đến 127)

### 7.2. Các lỗi thường gặp

| Lỗi | Nguyên nhân | Giải pháp |
|-----|-------------|-----------|
| `SW_CONDITIONS_NOT_SATISFIED` (0x6985) | PIN đã init | Reset PIN trước khi init |
| `SW_SECURITY_STATUS_NOT_SATISFIED` (0x6982) | Chưa validate PIN | Gọi VERIFY_PIN trước |
| `SW_INS_NOT_SUPPORTED` (0x6D00) | INS không đúng | Kiểm tra INS byte |
| `ArrayIndexOutOfBounds` | Offset/length sai | Validate trước khi access |

### 7.3. Resources

- [JavaCard SDK Documentation](https://docs.oracle.com/javacard/)
- [secp256k1 Bitcoin Wiki](https://en.bitcoin.it/wiki/Secp256k1)
- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
- [APDU Command Reference](docs/apdu-command.md)

---

## 8. Quy trình phát triển

```
1. Thiết kế
   └── Xác định command mới (INS, data format, response)
   └── Thêm vào bảng APDU protocol

2. Implement
   └── Tạo CommandHandler mới
   └── Đăng ký trong ChainoraWallet
   └── Thêm unit tests

3. Test
   └── Build và install lên thẻ
   └── Chạy tests trên thẻ vật lý
   └── Verify tất cả edge cases

4. Document
   └── Cập nhật apdu-command.md
   └── Cập nhật developer-guide.md (nếu cần)

5. Review & Commit
   └── Code review
   └── Commit với message rõ ràng
   └── Push lên remote
```

---

## 9. Câu hỏi thường gặp

**Q: Tại sao cần Low-S normalization?**
A: Để ngăn chặn transaction malleability - kẻ tấn công có thể thay đổi signature mà vẫn hợp lệ, dẫn đến transaction ID thay đổi.

**Q: Simulator có thể test được không?**
A: Không. Simulator jCardSim không hỗ trợ ECC với đường cong secp256k1. Phải test trên thẻ vật lý.

**Q: Private key có thể trích xuất từ thẻ không?**
A: Không. Private key được lưu trong secure storage của JavaCard và không bao giờ được export.

**Q: PIN bị khóa sau 3 lần sai, làm sao mở khóa?**
A: Gọi RESET_PIN (yêu cầu đã validate PIN trước đó) hoặc reinstall applet.

**Q: Làm sao thêm support cho cryptocurrency khác?**
A: Thay đổi Secp256k1.java nếu dùng đường cong khác, thêm handler mới nếu cần workflow khác.

---

*Tài liệu này được tạo để hỗ trợ các developer mới tham gia dự án ChainoraWallet. Nếu có câu hỏi, vui lòng tạo issue trên repository hoặc liên hệ team.*
