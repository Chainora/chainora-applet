package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

/**
 * Handles all key-related commands (INS 0x20-0x21).
 * Single Responsibility: only handles key pair and public key operations.
 */
public class KeyCommandHandler implements CommandHandler {
    private static final byte INS_GEN_KEY_PAIR = (byte) 0x20;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x21;

    private static final short SW_INS_NOT_SUPPORTED = ISO7816.SW_INS_NOT_SUPPORTED;

    private final PinValidator pinValidator;
    private final KeyPair keyPair;
    private final ECPublicKey publicKey;

    public KeyCommandHandler(PinValidator pinValidator, KeyPair keyPair, ECPublicKey publicKey) {
        this.pinValidator = pinValidator;
        this.keyPair = keyPair;
        this.publicKey = publicKey;
    }

    @Override
    public short process(APDU apdu, byte ins) {
        switch (ins) {
            case INS_GEN_KEY_PAIR:
                generateKeyPair();
                break;
            case INS_GET_PUBLIC_KEY:
                sendPublicKey(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        return ISO7816.SW_NO_ERROR;
    }

    private void generateKeyPair() {
        pinValidator.ensureInitialized();
        pinValidator.ensureValidated();
        keyPair.genKeyPair();
    }

    private void sendPublicKey(APDU apdu) {
        pinValidator.ensureInitializedAndValidated();
        byte[] buffer = apdu.getBuffer();
        short length = publicKey.getW(buffer, (short) 0);
        ApduUtils.sendData(apdu, (short) 0, length);
    }
}
