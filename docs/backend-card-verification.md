# Backend Verify The Chainora Card

Tài liệu này mô tả luồng backend xác thực thẻ Chainora bằng:

1. `device certificate` được factory ký
2. `card attestation proof` ký challenge do backend sinh

Luồng này tách riêng khỏi backup. Với tích hợp mới, backend nên dùng `INS_DEVICE_CERT (0x23)` và `INS_CARD_ATTEST (0x24)`, không dùng `START_LINK_PROOF` của backup flow cho mục đích login/xác thực.

## 1. Trust model

- Mỗi thẻ có một `deviceAuth` keypair riêng.
- Factory của Chainora ký `device certificate` bằng `CHAINORA_FACTORY_ROOT_PUBLIC_KEY`.
- Backend trust duy nhất root public key đó.
- Khi backend verify được:
  - `certificate` hợp lệ theo root key
  - `proof` hợp lệ theo `deviceAuthPublicKey` nằm trong certificate

thì backend biết:

- đây là một thẻ Chainora đã được factory provision
- thẻ đang thật sự sở hữu `deviceAuth private key`

## 2. APDU dùng cho backend verify

### 2.1. Đọc device certificate

`INS_DEVICE_CERT = 0x23`

- `P1 = 0x00` `GET_DEVICE_CERT`
- `P2 = 0x00`

Response:

```text
[version:1][deviceId:16][deviceAuthPublicKey:65][capabilities:1][sigLen:1][sigDer:sigLen]
```

### 2.2. Đọc factory CSR

`INS_DEVICE_CERT = 0x23`

- `P1 = 0x10` `GET_FACTORY_CSR`
- `P2 = 0x00`

Response:

```text
[version:1][deviceId:16][deviceAuthPublicKey:65]
```

Lệnh này chủ yếu dành cho factory/dev tooling. Backend runtime thường không cần gọi trực tiếp.

### 2.3. Card attest challenge

`INS_CARD_ATTEST = 0x24`

- `P1 = 0x00`
- `P2 = 0x00`
- `Data = challenge[32]`

Response:

```text
[version:1][deviceId:16][challenge:32][sigLen:1][sigDer:sigLen]
```

Thẻ ký toàn bộ phần body:

```text
[version][deviceId][challenge]
```

bằng `deviceAuthPrivateKey` với thuật toán `ECDSA with SHA-256` trên `secp256k1`.

## 3. Luồng khuyến nghị

### 3.1. Bind device

1. App đọc `deviceCertificate` từ thẻ bằng `GET_DEVICE_CERT`.
2. App gửi certificate lên backend.
3. Backend parse certificate, verify root signature.
4. Backend lưu:
   - `deviceId`
   - `deviceAuthPublicKey`
   - certificate gốc hoặc fingerprint certificate

### 3.2. Verify card trong phiên

1. Backend sinh `challenge` ngẫu nhiên 32 byte.
2. Backend lưu challenge ở trạng thái `pending`, gắn với user/session/device và TTL ngắn.
3. App gửi challenge xuống thẻ bằng `INS_CARD_ATTEST`.
4. Thẻ trả `attestationProof`.
5. App gửi `attestationProof` và `deviceId` hoặc `deviceCertificate` lên backend.
6. Backend:
   - kiểm tra challenge còn hạn và chưa dùng
   - lấy `deviceAuthPublicKey` đã bind
   - verify proof signature
   - mark challenge là `used`

## 4. Verify phía backend

### 4.1. Parse certificate

Các bước tối thiểu:

- `version == 0x01`
- public key bắt đầu bằng byte `0x04` (uncompressed secp256k1)
- `capabilities & 0x01 != 0`
- `sigLen > 0`
- tổng độ dài đúng bằng `83 + 1 + sigLen`

`certificateBody` là 83 byte đầu:

```text
[version:1][deviceId:16][deviceAuthPublicKey:65][capabilities:1]
```

Backend verify:

```text
verifyECDSASha256(factoryRootPublicKey, certificateBody, sigDer)
```

Nếu hợp lệ, lấy:

- `deviceId = certificate[1..16]`
- `deviceAuthPublicKey = certificate[17..81]`

### 4.2. Parse attestation proof

Các bước tối thiểu:

- `version == 0x01`
- `deviceId` trong proof phải khớp với device đã bind
- `challenge` trong proof phải khớp tuyệt đối challenge backend đã sinh
- `sigLen > 0`
- tổng độ dài đúng bằng `49 + 1 + sigLen`

`proofBody` là 49 byte đầu:

```text
[version:1][deviceId:16][challenge:32]
```

Backend verify:

```text
verifyECDSASha256(deviceAuthPublicKey, proofBody, sigDer)
```

## 5. Pseudo-code

```text
function bindDevice(deviceCertificate):
  cert = parseCertificate(deviceCertificate)
  assert cert.version == 0x01
  assert verifyECDSASha256(factoryRootPublicKey, cert.body, cert.signature)

  saveDevice({
    deviceId: cert.deviceId,
    deviceAuthPublicKey: cert.deviceAuthPublicKey,
    certificate: deviceCertificate
  })
```

```text
function issueChallenge(deviceId, sessionId):
  challenge = randomBytes(32)
  storePendingChallenge({
    deviceId: deviceId,
    sessionId: sessionId,
    challenge: challenge,
    expiresAt: now + 60s,
    used: false
  })
  return challenge
```

```text
function verifyCardProof(deviceId, proofBytes):
  proof = parseProof(proofBytes)
  pending = loadPendingChallenge(deviceId)

  assert pending exists
  assert pending.used == false
  assert pending.expiresAt > now
  assert proof.deviceId == deviceId
  assert proof.challenge == pending.challenge

  device = loadBoundDevice(deviceId)
  assert verifyECDSASha256(device.deviceAuthPublicKey, proof.body, proof.signature)

  markChallengeUsed(pending)
  return success
```

## 6. Lưu ý bảo mật

- Challenge phải là random 32 byte, one-time use, TTL ngắn.
- Backend phải mark challenge là `used` ngay sau verify thành công.
- Flow này không yêu cầu PIN. Nó chứng minh `genuine card + possession of deviceAuth private key`, không chứng minh user đã unlock wallet.
- Nếu cần gắn thêm điều kiện “user đã nhập PIN”, cần một flow khác có PIN gate riêng; không nên suy diễn điều đó từ attestation proof này.
- `START_LINK_PROOF` của backup không nên dùng cho backend auth mới vì payload do thẻ tự sinh, không phải server challenge.

## 7. Host Update Required

Kể từ bản này, host không được gọi cert/factory qua `BACKUP_SESSION (0x30)` nữa.

Các thay đổi bắt buộc:

- `GET_DEVICE_CERT`
  - cũ: `INS 0x30 / P1=0x00`
  - mới: `INS 0x23 / P1=0x00`
- `GET_FACTORY_CSR`
  - cũ: `INS 0x30 / P1=0x10`
  - mới: `INS 0x23 / P1=0x10`
- `SET_DEVICE_CERT`
  - cũ: `INS 0x30 / P1=0x11`
  - mới: `INS 0x23 / P1=0x11`

Các phần backup giữ nguyên wire format và logic:

- `START_LINK_PROOF`: `0x30 / P1=0x01`
- `LOAD_PEER_CERT`: `0x30 / P1=0x02`
- `LOAD_PEER_LINK_PROOF`: `0x30 / P1=0x03`
- `CLEAR_LINK_STATE`: `0x30 / P1=0x04`
- `BACKUP_EXPORT`: `0x31`
- `BACKUP_IMPORT`: `0x32`

Nếu host muốn giữ logic backup như cũ thì chỉ cần đổi chỗ đọc/cài certificate sang `INS_DEVICE_CERT (0x23)`. Phần trao đổi peer certificate trong backup vẫn giữ nguyên: host đọc cert bằng `0x23`, sau đó truyền raw certificate đó vào `LOAD_PEER_CERT (0x30 / P1=0x02)`.
