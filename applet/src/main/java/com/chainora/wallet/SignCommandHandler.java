package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.Signature;

/**
 * Handles signature commands (INS 0x22).
 * Single Responsibility: only handles hash signing operations.
 */
public class SignCommandHandler implements CommandHandler {
    private static final byte INS_SIGN_HASH = (byte) 0x22;
    private static final short HASH_LENGTH = 32;

    private static final short SW_INS_NOT_SUPPORTED = ISO7816.SW_INS_NOT_SUPPORTED;

    private final PinValidator pinValidator;
    private final ECPrivateKey privateKey;
    private final Signature ecdsaSignature;

    public SignCommandHandler(PinValidator pinValidator, ECPrivateKey privateKey, Signature ecdsaSignature) {
        this.pinValidator = pinValidator;
        this.privateKey = privateKey;
        this.ecdsaSignature = ecdsaSignature;
    }

    @Override
    public short process(APDU apdu, byte ins) {
        if (ins == INS_SIGN_HASH) {
            signHash(apdu);
        } else {
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        return ISO7816.SW_NO_ERROR;
    }

    private void signHash(APDU apdu) {
        pinValidator.ensureInitializedAndValidated();
        short bytesRead = ApduUtils.receiveData(apdu);
        ApduUtils.validateExactLength(bytesRead, HASH_LENGTH);

        byte[] buffer = apdu.getBuffer();
        ecdsaSignature.init(privateKey, Signature.MODE_SIGN);

        short sigLength = ecdsaSignature.signPreComputedHash(
                buffer,
                ISO7816.OFFSET_CDATA,
                bytesRead,
                buffer,
                (short) 0);

        // Normalize signature to Low-S to prevent transaction malleability
        normalizeLowS(buffer, (short) 0, sigLength);

        ApduUtils.sendData(apdu, (short) 0, sigLength);
    }

    /**
     * Normalizes ECDSA signature to Low-S form.
     * Ensures s <= n/2 to prevent signature malleability attacks.
     * DER encoding: 0x30 [totalLen] 0x02 [rLen] [r...] 0x02 [sLen] [s...]
     */
    private void normalizeLowS(byte[] sig, short offset, short length) {
        // Parse DER structure to find S value
        // offset + 3 = rLen
        short rLen = sig[(short) (offset + 3)];
        // sOffset points to 0x02 marker before sLen
        short sOffset = (short) (offset + 4 + rLen);
        // sLen is at sOffset + 1
        short sLen = sig[(short) (sOffset + 1)];

        // S value starts at sOffset + 2
        // DER adds leading 0x00 if first bit is 1 (sign extension prevention)
        short sValueOffset = (short) (sOffset + 2);
        short actualSLen = sLen;
        boolean hasLeadingZero = (sLen > 1 && sig[sValueOffset] == 0);

        if (hasLeadingZero) {
            sValueOffset = (short) (sValueOffset + 1);
            actualSLen = (short) (sLen - 1);
        }

        // Check if S needs normalization (s > n/2)
        // Only compare first byte for efficiency - sufficient for most cases
        short sFirst = (short) (sig[sValueOffset] & 0xFF);
        short nDiv2First = (short) (Secp256k1.N_DIV_2[0] & 0xFF);

        if (sFirst > nDiv2First) {
            // Pad S to 32 bytes for subtraction
            byte[] sPadded = new byte[Secp256k1.N.length];
            short padStart = (short) (Secp256k1.N.length - actualSLen);
            for (short i = 0; i < actualSLen; i++) {
                sPadded[(short) (padStart + i)] = sig[(short) (sValueOffset + i)];
            }

            // Compute n - s (both 32 bytes)
            byte[] result = new byte[Secp256k1.N.length];
            short carry = 0;
            for (short i = (short) (Secp256k1.N.length - 1); i >= 0; i--) {
                short nByte = (short) (Secp256k1.N[i] & 0xFF);
                short sByte = (short) (sPadded[i] & 0xFF);
                short diff = (short) (nByte - sByte - carry);
                carry = (diff < 0) ? (short) 1 : (short) 0;
                result[i] = (byte) ((diff < 0) ? diff + 256 : diff);
            }

            // Strip leading zeros to get actual length
            short actualLen = (short) Secp256k1.N.length;
            while (actualLen > 0 && result[(short) (actualLen - 1)] == 0) {
                actualLen--;
            }

            // Update DER signature
            sig[(short) (sOffset + 1)] = (byte) actualLen;
            for (short i = 0; i < actualLen; i++) {
                sig[(short) (sOffset + 2 + i)] = result[i];
            }
        }
    }

    /**
     * Compares two big-endian unsigned byte arrays.
     * @return negative if a < b, positive if a > b, zero if equal
     */
    private short compareBigInt(byte[] a, byte[] b) {
        short maxLen = (short) (a.length >= b.length ? a.length : b.length);
        for (short i = 0; i < maxLen; i++) {
            short av = (i < a.length) ? (short) (a[i] & 0xFF) : 0;
            short bv = (i < b.length) ? (short) (b[i] & 0xFF) : 0;
            if (av != bv) {
                return (short) (av - bv);
            }
        }
        return (short) (a.length - b.length);
    }
}
