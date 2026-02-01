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

        ApduUtils.sendData(apdu, (short) 0, sigLength);
    }
}
