package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Handles all PIN-related commands (INS 0x10-0x14).
 * Single Responsibility: only handles PIN operations.
 */
public class PinCommandHandler implements CommandHandler {
    private static final byte INS_INIT_PIN = (byte) 0x10;
    private static final byte INS_VERIFY_PIN = (byte) 0x11;
    private static final byte INS_UPDATE_PIN = (byte) 0x12;
    private static final byte INS_RESET_PIN = (byte) 0x13;
    private static final byte INS_IS_PIN_INITIALIZED = (byte) 0x14;

    private static final short SW_CONDITIONS_NOT_SATISFIED = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
    private static final short SW_SECURITY_STATUS_NOT_SATISFIED = ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
    private static final short SW_INS_NOT_SUPPORTED = ISO7816.SW_INS_NOT_SUPPORTED;

    private final PinValidator pinValidator;

    public PinCommandHandler(PinValidator pinValidator) {
        this.pinValidator = pinValidator;
    }

    @Override
    public short process(APDU apdu, byte ins) {
        switch (ins) {
            case INS_INIT_PIN:
                initPin(apdu);
                break;
            case INS_VERIFY_PIN:
                verifyPin(apdu);
                break;
            case INS_UPDATE_PIN:
                updatePin(apdu);
                break;
            case INS_RESET_PIN:
                resetPin();
                break;
            case INS_IS_PIN_INITIALIZED:
                sendPinState(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        return ISO7816.SW_NO_ERROR;
    }

    private void initPin(APDU apdu) {
        if (pinValidator.isInitialized()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        short bytesRead = ApduUtils.receiveData(apdu);
        pinValidator.validatePinLength(bytesRead);
        byte[] buffer = apdu.getBuffer();
        pinValidator.updatePin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
        pinValidator.markInitialized();
    }

    private void verifyPin(APDU apdu) {
        pinValidator.ensureInitialized();
        short bytesRead = ApduUtils.receiveData(apdu);
        pinValidator.validatePinLength(bytesRead);
        byte[] buffer = apdu.getBuffer();
        if (!pinValidator.checkPin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead)) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void updatePin(APDU apdu) {
        pinValidator.ensureValidated();
        short bytesRead = ApduUtils.receiveData(apdu);
        pinValidator.validatePinLength(bytesRead);
        byte[] buffer = apdu.getBuffer();
        pinValidator.updatePin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
    }

    private void resetPin() {
        pinValidator.reset();
    }

    private void sendPinState(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = (byte) (pinValidator.isInitialized() ? 1 : 0);
        ApduUtils.sendData(apdu, (short) 0, (short) 1);
    }
}
