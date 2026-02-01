package com.chainora.client.wallet.crypto;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

/**
 * Builds Web3j SignatureData from DER signatures produced by the card.
 */
public class SignatureBuilder {
    private static final ECDomainParameters SECP256K1 = createSecp256k1Domain();
    private static final BigInteger HALF_CURVE_ORDER = SECP256K1.getN().shiftRight(1);

    /**
     * Builds a SignatureData from a DER signature.
     *
     * @param derSignature the DER-encoded signature from the card
     * @param messageHash the hash that was signed
     * @param publicKey the public key bytes
     * @param chainId the chain ID for EIP-155 replay protection
     * @return the SignatureData ready for transaction encoding
     */
    public Sign.SignatureData build(byte[] derSignature, byte[] messageHash,
            byte[] publicKey, long chainId) {
        DerComponents components = parseDerSignature(derSignature);
        byte[] expectedKey = getPublicKeyXY(publicKey);

        int recId = findRecoveryId(components, messageHash, expectedKey);

        BigInteger canonicalS = components.s;
        int canonicalRecId = recId;
        if (canonicalS.compareTo(HALF_CURVE_ORDER) > 0) {
            canonicalS = SECP256K1.getN().subtract(canonicalS);
            canonicalRecId ^= 1;
        }

        // Verify the canonical signature produces the correct key
        byte[] recoveredKey = recoverPublicKey(canonicalRecId, components.r, canonicalS, messageHash);
        if (recoveredKey == null || !Arrays.equals(recoveredKey, expectedKey)) {
            throw new IllegalStateException("Signature normalization failed integrity check.");
        }

        int parityBit = canonicalRecId & 1;
        BigInteger v = chainId > 0
                ? BigInteger.valueOf(chainId * 2L + 35L + parityBit)
                : BigInteger.valueOf(parityBit + 27L);

        byte[] rBytes = Numeric.toBytesPadded(components.r, 32);
        byte[] sBytes = Numeric.toBytesPadded(canonicalS, 32);
        byte[] vBytes = toMinimalBytes(v);

        return new Sign.SignatureData(vBytes, rBytes, sBytes);
    }

    private int findRecoveryId(DerComponents components, byte[] messageHash, byte[] expectedKey) {
        for (int i = 0; i < 4; i++) {
            byte[] recovered = recoverPublicKey(i, components.r, components.s, messageHash);
            if (recovered != null && Arrays.equals(recovered, expectedKey)) {
                return i;
            }
        }
        throw new IllegalStateException("Unable to derive recovery identifier for signature.");
    }

    private byte[] recoverPublicKey(int recId, BigInteger r, BigInteger s, byte[] messageHash) {
        if (recId < 0 || recId > 3) {
            return null;
        }
        ECDomainParameters params = SECP256K1;
        BigInteger n = params.getN();
        BigInteger i = BigInteger.valueOf(recId / 2);
        BigInteger x = r.add(i.multiply(n));
        BigInteger prime = params.getCurve().getField().getCharacteristic();
        if (x.compareTo(prime) >= 0) {
            return null;
        }
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        BigInteger e = new BigInteger(1, messageHash);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = s.multiply(rInv).mod(n);
        BigInteger eNeg = n.subtract(e.mod(n)).mod(n);
        BigInteger eInvrInv = eNeg.multiply(rInv).mod(n);
        ECPoint q = params.getG().multiply(eInvrInv).add(R.multiply(srInv)).normalize();
        if (q.isInfinity()) {
            return null;
        }
        byte[] xBytes = bigIntegerToBytes(q.getAffineXCoord().toBigInteger(), 32);
        byte[] yBytes = bigIntegerToBytes(q.getAffineYCoord().toBigInteger(), 32);
        byte[] out = new byte[64];
        System.arraycopy(xBytes, 0, out, 0, 32);
        System.arraycopy(yBytes, 0, out, 32, 32);
        return out;
    }

    private ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        byte[] compEnc = new byte[33];
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        byte[] xBytes = bigIntegerToBytes(xBN, 32);
        System.arraycopy(xBytes, 0, compEnc, 1, 32);
        return SECP256K1.getCurve().decodePoint(compEnc);
    }

    private DerComponents parseDerSignature(byte[] derSignature) {
        if (derSignature == null || derSignature.length < 8 || derSignature[0] != 0x30) {
            throw new IllegalArgumentException("Invalid DER signature format.");
        }
        int offset = 2;
        if (offset >= derSignature.length || derSignature[offset] != 0x02) {
            throw new IllegalArgumentException("Invalid DER signature: missing R marker.");
        }
        int rLength = derSignature[offset + 1] & 0xFF;
        int rStart = offset + 2;
        if (rStart + rLength > derSignature.length) {
            throw new IllegalArgumentException("Invalid DER signature length for R component.");
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(derSignature, rStart, rStart + rLength));

        int sMarker = rStart + rLength;
        if (sMarker >= derSignature.length || derSignature[sMarker] != 0x02) {
            throw new IllegalArgumentException("Invalid DER signature: missing S marker.");
        }
        int sLength = derSignature[sMarker + 1] & 0xFF;
        int sStart = sMarker + 2;
        if (sStart + sLength > derSignature.length) {
            throw new IllegalArgumentException("Invalid DER signature length for S component.");
        }
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(derSignature, sStart, sStart + sLength));

        return new DerComponents(r, s);
    }

    private byte[] getPublicKeyXY(byte[] publicKey) {
        if (publicKey == null || publicKey.length < 64) {
            throw new IllegalArgumentException("Invalid public key length.");
        }
        if (publicKey.length == 65 && (publicKey[0] == 0x04 || publicKey[0] == 4)) {
            return Arrays.copyOfRange(publicKey, 1, 65);
        }
        return Arrays.copyOf(publicKey, 64);
    }

    private byte[] toMinimalBytes(BigInteger value) {
        if (value == null) {
            return new byte[] { 0x00 };
        }
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0x00) {
            raw = Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw.length == 0 ? new byte[] { 0x00 } : raw;
    }

    private byte[] bigIntegerToBytes(BigInteger value, int length) {
        byte[] src = value.toByteArray();
        if (src.length == length) {
            return src;
        }
        byte[] dst = new byte[length];
        int copyStart = Math.max(0, src.length - length);
        int copyLength = Math.min(length, src.length);
        System.arraycopy(src, copyStart, dst, length - copyLength, copyLength);
        return dst;
    }

    private static ECDomainParameters createSecp256k1Domain() {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        return new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    private static class DerComponents {
        final BigInteger r;
        final BigInteger s;

        DerComponents(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }
    }
}
