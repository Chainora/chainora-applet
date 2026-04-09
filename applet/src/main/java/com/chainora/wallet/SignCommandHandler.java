package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
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
    private static final short SW_DATA_INVALID = ISO7816.SW_DATA_INVALID;
    private static final short SW_WRONG_LENGTH = ISO7816.SW_WRONG_LENGTH;

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
        if (sigLength <= 0 || sigLength > Configuration.MAX_DER_SIGNATURE_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        // Normalize signature to Low-S to prevent transaction malleability
        sigLength = normalizeLowS(buffer, (short) 0, sigLength);

        ApduUtils.sendData(apdu, (short) 0, sigLength);
    }

    /**
     * Normalizes ECDSA signature to Low-S form.
     * Ensures s <= n/2 to prevent signature malleability attacks.
     * DER encoding: 0x30 [totalLen] 0x02 [rLen] [r...] 0x02 [sLen] [s...]
     */
    private short normalizeLowS(byte[] sig, short offset, short length) {
        if (length < 8) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        if (sig[offset] != 0x30) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        short seqLen = (short) (sig[(short) (offset + 1)] & 0xFF);
        if (seqLen != (short) (length - 2)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        short rMarkerOffset = (short) (offset + 2);
        if (sig[rMarkerOffset] != 0x02) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        short rLen = (short) (sig[(short) (rMarkerOffset + 1)] & 0xFF);
        if (rLen <= 0) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        short sMarkerOffset = (short) (rMarkerOffset + 2 + rLen);
        if (sMarkerOffset >= (short) (offset + length) || sig[sMarkerOffset] != 0x02) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        short sLenOffset = (short) (sMarkerOffset + 1);
        short sLen = (short) (sig[sLenOffset] & 0xFF);
        if (sLen <= 0) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        short sValueOffset = (short) (sLenOffset + 1);
        short sEnd = (short) (sValueOffset + sLen);
        if (sEnd != (short) (offset + length)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        short normalizedSourceOffset = sValueOffset;
        short normalizedSourceLength = sLen;
        if (normalizedSourceLength > 1 && sig[normalizedSourceOffset] == 0x00) {
            normalizedSourceOffset++;
            normalizedSourceLength--;
        }
        if (normalizedSourceLength <= 0 || normalizedSourceLength > (short) Secp256k1.N.length) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        if (!isHighS(sig, normalizedSourceOffset, normalizedSourceLength)) {
            return length;
        }

        if (normalizedSourceLength != (short) Secp256k1.N.length) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        short borrow = 0;
        for (short i = (short) (Secp256k1.N.length - 1); i >= 0; i--) {
            short nByte = (short) (Secp256k1.N[i] & 0xFF);
            short sByte = (short) (sig[(short) (normalizedSourceOffset + i)] & 0xFF);
            short diff = (short) (nByte - sByte - borrow);
            if (diff < 0) {
                diff = (short) (diff + 256);
                borrow = 1;
            } else {
                borrow = 0;
            }
            sig[(short) (normalizedSourceOffset + i)] = (byte) diff;
        }

        short firstNonZero = 0;
        while (firstNonZero < (short) (Secp256k1.N.length - 1)
                && sig[(short) (normalizedSourceOffset + firstNonZero)] == 0x00) {
            firstNonZero++;
        }

        short newSRawLength = (short) (Secp256k1.N.length - firstNonZero);
        if (newSRawLength <= 0 || newSRawLength > sLen) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        Util.arrayCopyNonAtomic(sig, (short) (normalizedSourceOffset + firstNonZero), sig, sValueOffset, newSRawLength);
        sig[sLenOffset] = (byte) newSRawLength;
        short removedBytes = (short) (sLen - newSRawLength);
        sig[(short) (offset + 1)] = (byte) (seqLen - removedBytes);
        return (short) (length - removedBytes);
    }

    private boolean isHighS(byte[] sig, short sOffset, short sLength) {
        if (sLength < (short) Secp256k1.N.length) {
            return false;
        }
        for (short i = 0; i < (short) Secp256k1.N.length; i++) {
            short sv = (short) (sig[(short) (sOffset + i)] & 0xFF);
            short hv = (short) (Secp256k1.N_DIV_2[i] & 0xFF);
            if (sv > hv) {
                return true;
            }
            if (sv < hv) {
                return false;
            }
        }
        return false;
    }
}
