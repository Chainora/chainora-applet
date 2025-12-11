package tests;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TestUtils {
    private static final SecP256K1Curve CURVE = new SecP256K1Curve();
    private static final BigInteger GX = new BigInteger(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger GY = new BigInteger(
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static final ECPoint G = CURVE.createPoint(GX, GY);
    private static final ECDomainParameters DOMAIN = new ECDomainParameters(CURVE, G, CURVE.getOrder(),
            CURVE.getCofactor());
    private static final long DEFAULT_CHAIN_ID = 1L;

    public static byte[][] decodeDerSignature(byte[] derSignature, int coordinateSizeBytes) {
        if (derSignature == null || derSignature.length < 8) {
            throw new IllegalArgumentException("Signature is too short");
        }

        int offset = 0;
        if (derSignature[offset++] != 0x30) {
            throw new IllegalArgumentException("Signature must start with DER SEQUENCE");
        }

        int lengthByte = derSignature[offset++] & 0xFF;
        if ((lengthByte & 0x80) != 0) {
            int lengthBytes = lengthByte & 0x7F;
            int totalLength = 0;
            for (int i = 0; i < lengthBytes; i++) {
                totalLength = (totalLength << 8) | (derSignature[offset++] & 0xFF);
            }
            if (totalLength != derSignature.length - offset) {
                throw new IllegalArgumentException("Invalid DER length encoding");
            }
        }

        if (derSignature[offset++] != 0x02) {
            throw new IllegalArgumentException("Missing R component marker");
        }
        int rLength = derSignature[offset++] & 0xFF;
        byte[] rRaw = Arrays.copyOfRange(derSignature, offset, offset + rLength);
        offset += rLength;

        if (derSignature[offset++] != 0x02) {
            throw new IllegalArgumentException("Missing S component marker");
        }
        int sLength = derSignature[offset++] & 0xFF;
        byte[] sRaw = Arrays.copyOfRange(derSignature, offset, offset + sLength);

        return new byte[][] {
                normalizeComponent(rRaw, coordinateSizeBytes),
                normalizeComponent(sRaw, coordinateSizeBytes)
        };
    }

    public static byte[] normalizeComponent(byte[] component, int coordinateSize) {
        int firstNonZero = 0;
        while (firstNonZero < component.length - 1 && component[firstNonZero] == 0x00) {
            firstNonZero++;
        }

        int valueLength = component.length - firstNonZero;
        if (valueLength > coordinateSize) {
            throw new IllegalArgumentException("Component longer than expected");
        }

        byte[] normalized = new byte[coordinateSize];
        System.arraycopy(component, firstNonZero, normalized, coordinateSize - valueLength, valueLength);
        return normalized;
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            sb.append(String.format("%02X", aByte));
        }
        return sb.toString();
    }

    public static boolean isAllZero(byte[] input) {
        for (byte b : input) {
            if (b != 0x00) {
                return false;
            }
        }
        return true;
    }

    public static byte[] prepareEvmRawTransaction() {
        byte[] nonce = encodeInteger(1);
        byte[] gasPrice = hexStringToBytes("09184E72A000");
        byte[] gasLimit = hexStringToBytes("2710");
        byte[] to = hexStringToBytes("B94F5374FCE5EDBC8E2A8697C15331677E6EBF0B");
        byte[] value = new byte[0];
        byte[] data = new byte[0];
        byte[] chainId = encodeInteger(DEFAULT_CHAIN_ID);
        byte[] empty = new byte[0];

        return rlpEncodeList(nonce, gasPrice, gasLimit, to, value, data, chainId, empty, empty);
    }

    public static byte[] keccak256Hash(byte[] input) {
        KeccakDigest digest = new KeccakDigest(256);
        if (input != null && input.length > 0) {
            digest.update(input, 0, input.length);
        }
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    public static byte[] constructSignedEvmTransaction(byte[] evmTx, byte[] rComponent, byte[] sComponent,
            int recoveryId) {
        if (evmTx == null) {
            throw new IllegalArgumentException("Unsigned transaction cannot be null");
        }
        byte[][] fields = decodeTopLevelList(evmTx);
        if (fields.length != 9) {
            throw new IllegalArgumentException("Unexpected RLP structure for unsigned transaction");
        }

        long chainId = bytesToLong(fields[6], DEFAULT_CHAIN_ID);
        if (recoveryId < 0 || recoveryId > 3) {
            throw new IllegalArgumentException("Invalid recovery id");
        }
        byte[] v = encodeInteger(chainId * 2 + 35 + recoveryId);
        byte[] r = trimLeadingZeros(rComponent);
        byte[] s = trimLeadingZeros(sComponent);

        return rlpEncodeList(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], v, r, s);
    }

    public static int determineRecoveryId(byte[] hash, byte[] rComponent, byte[] sComponent, byte[] expectedPubKey) {
        if (hash == null) {
            throw new IllegalArgumentException("Hash cannot be null");
        }
        if (expectedPubKey == null || expectedPubKey.length == 0) {
            throw new IllegalArgumentException("Expected public key is required");
        }
        BigInteger r = new BigInteger(1, ensureNonEmpty(rComponent));
        BigInteger s = new BigInteger(1, ensureNonEmpty(sComponent));
        ECPoint expected = CURVE.decodePoint(expectedPubKey).normalize();

        for (int recId = 0; recId < 4; recId++) {
            ECPoint candidate = recoverFromSignature(recId, r, s, hash);
            if (candidate != null && candidate.normalize().equals(expected)) {
                return recId;
            }
        }
        throw new IllegalStateException("Unable to determine recovery id for provided signature");
    }

    public static byte[] recoverEvmPublicKeyFromSignedTransaction(byte[] signedTx, byte[] txHash) {
        if (signedTx == null) {
            throw new IllegalArgumentException("Signed transaction cannot be null");
        }
        if (txHash == null) {
            throw new IllegalArgumentException("Transaction hash is required for recovery");
        }

        byte[][] fields = decodeTopLevelList(signedTx);
        if (fields.length != 9) {
            throw new IllegalArgumentException("Signed transaction must have 9 RLP fields");
        }

        BigInteger v = new BigInteger(1, ensureNonEmpty(fields[6]));
        BigInteger r = new BigInteger(1, ensureNonEmpty(fields[7]));
        BigInteger s = new BigInteger(1, ensureNonEmpty(fields[8]));

        int recId = deriveRecoveryId(v);
        ECPoint q = recoverFromSignature(recId, r, s, txHash);
        if (q == null) {
            throw new IllegalStateException("Unable to recover public key from signature");
        }
        return q.getEncoded(false);
    }

    private static byte[] ensureNonEmpty(byte[] input) {
        if (input == null || input.length == 0) {
            return new byte[] { 0x00 };
        }
        return input;
    }

    private static ECPoint recoverFromSignature(int recId, BigInteger r, BigInteger s, byte[] hash) {
        BigInteger n = DOMAIN.getN();
        BigInteger i = BigInteger.valueOf(recId / 2);
        BigInteger x = r.add(i.multiply(n));
        BigInteger prime = CURVE.getField().getCharacteristic();
        if (x.compareTo(prime) >= 0) {
            return null;
        }

        byte[] compressedPoint = new byte[33];
        compressedPoint[0] = (byte) ((recId & 1) == 1 ? 0x03 : 0x02);
        byte[] xBytes = toFixedLength(x, 32);
        System.arraycopy(xBytes, 0, compressedPoint, 1, 32);

        ECPoint R = CURVE.decodePoint(compressedPoint);
        if (!R.multiply(n).isInfinity()) {
            return null;
        }

        BigInteger e = new BigInteger(1, hash);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = s.multiply(rInv).mod(n);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger eInvrInv = eInv.multiply(rInv).mod(n);

        return ECAlgorithms.sumOfTwoMultiplies(G, eInvrInv, R, srInv).normalize();
    }

    private static byte[] rlpEncodeList(byte[]... elements) {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        for (byte[] element : elements) {
            byte[] encoded = encodeElement(element);
            payload.write(encoded, 0, encoded.length);
        }
        byte[] encodedPayload = payload.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] header = encodeLength(encodedPayload.length, 0xC0);
        result.write(header, 0, header.length);
        result.write(encodedPayload, 0, encodedPayload.length);
        return result.toByteArray();
    }

    private static byte[] encodeElement(byte[] value) {
        if (value == null || value.length == 0) {
            return new byte[] { (byte) 0x80 };
        }
        if (value.length == 1 && (value[0] & 0xFF) < 0x80) {
            return new byte[] { value[0] };
        }
        byte[] lengthBytes = encodeLength(value.length, 0x80);
        return concatenate(lengthBytes, value);
    }

    private static byte[] encodeLength(int length, int offset) {
        if (length < 56) {
            return new byte[] { (byte) (length + offset) };
        }
        byte[] lengthBytes = trimLeadingZeros(BigInteger.valueOf(length).toByteArray());
        byte prefix = (byte) (offset + 55 + lengthBytes.length);
        return concatenate(new byte[] { prefix }, lengthBytes);
    }

    private static byte[][] decodeTopLevelList(byte[] data) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Empty RLP input");
        }
        int prefix = data[0] & 0xFF;
        if (prefix < 0xC0) {
            throw new IllegalArgumentException("RLP does not start with a list");
        }

        int length;
        int offset;
        if (prefix <= 0xF7) {
            length = prefix - 0xC0;
            offset = 1;
        } else {
            int lenOfLen = prefix - 0xF7;
            length = readInt(data, 1, lenOfLen);
            offset = 1 + lenOfLen;
        }

        int end = offset + length;
        if (end > data.length) {
            throw new IllegalArgumentException("Invalid RLP length");
        }

        List<byte[]> elements = new ArrayList<>();
        int index = offset;
        while (index < end) {
            DecodedValue decoded = decodeValue(data, index);
            elements.add(decoded.value);
            index = decoded.nextIndex;
        }

        if (index != end) {
            throw new IllegalArgumentException("RLP list length mismatch");
        }

        return elements.toArray(new byte[0][]);
    }

    private static DecodedValue decodeValue(byte[] data, int index) {
        int prefix = data[index] & 0xFF;
        if (prefix <= 0x7F) {
            return new DecodedValue(new byte[] { data[index] }, index + 1);
        } else if (prefix <= 0xB7) {
            int len = prefix - 0x80;
            if (len == 0) {
                return new DecodedValue(new byte[0], index + 1);
            }
            int start = index + 1;
            return new DecodedValue(Arrays.copyOfRange(data, start, start + len), start + len);
        } else if (prefix <= 0xBF) {
            int lenOfLen = prefix - 0xB7;
            int len = readInt(data, index + 1, lenOfLen);
            int start = index + 1 + lenOfLen;
            return new DecodedValue(Arrays.copyOfRange(data, start, start + len), start + len);
        } else {
            throw new IllegalArgumentException("Nested lists are not supported in this helper");
        }
    }

    private static int readInt(byte[] data, int offset, int length) {
        int value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (data[offset + i] & 0xFF);
        }
        return value;
    }

    private static byte[] concatenate(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static byte[] trimLeadingZeros(byte[] value) {
        if (value == null || value.length == 0) {
            return new byte[0];
        }
        int firstNonZero = 0;
        while (firstNonZero < value.length - 1 && value[firstNonZero] == 0x00) {
            firstNonZero++;
        }
        int len = value.length - firstNonZero;
        byte[] trimmed = Arrays.copyOfRange(value, firstNonZero, value.length);
        return len == 0 ? new byte[] { 0x00 } : trimmed;
    }

    private static byte[] encodeInteger(long value) {
        if (value == 0) {
            return new byte[0];
        }
        return trimLeadingZeros(BigInteger.valueOf(value).toByteArray());
    }

    private static int deriveRecoveryId(BigInteger v) {
        long vLong = v.longValue();
        if (vLong == 27 || vLong == 28) {
            return (int) (vLong - 27);
        }
        if (vLong < 35) {
            throw new IllegalArgumentException("Unsupported v value: " + vLong);
        }
        long chainId = (vLong - 35) / 2;
        int recId = (int) (vLong - (chainId * 2 + 35));
        if (recId < 0 || recId > 3) {
            throw new IllegalArgumentException("Invalid recovery id derived from v");
        }
        return recId;
    }

    private static long bytesToLong(byte[] value, long defaultValue) {
        if (value == null || value.length == 0) {
            return defaultValue;
        }
        BigInteger bigInteger = new BigInteger(1, value);
        return bigInteger.longValue();
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[length];
        int copyStart = Math.max(0, raw.length - length);
        int copyLength = Math.min(raw.length, length);
        System.arraycopy(raw, copyStart, result, length - copyLength, copyLength);
        return result;
    }

    private static byte[] hexStringToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        String normalized = hex.length() % 2 == 0 ? hex : "0" + hex;
        int len = normalized.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) Integer.parseInt(normalized.substring(i, i + 2), 16);
        }
        return data;
    }

    private static class DecodedValue {
        private final byte[] value;
        private final int nextIndex;

        private DecodedValue(byte[] value, int nextIndex) {
            this.value = value;
            this.nextIndex = nextIndex;
        }
    }
}
