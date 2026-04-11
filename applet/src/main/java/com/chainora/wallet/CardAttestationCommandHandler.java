package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Signs backend challenges with the device authentication key.
 */
final class CardAttestationCommandHandler implements CommandHandler {
    private static final short SW_INS_NOT_SUPPORTED = ISO7816.SW_INS_NOT_SUPPORTED;
    private static final short SW_WRONG_P1P2 = ISO7816.SW_INCORRECT_P1P2;
    private static final short SW_DATA_INVALID = ISO7816.SW_DATA_INVALID;

    private final DeviceIdentityManager deviceIdentityManager;
    private final byte[] challengeScratch;

    CardAttestationCommandHandler(DeviceIdentityManager deviceIdentityManager) {
        this.deviceIdentityManager = deviceIdentityManager;
        this.challengeScratch = JCSystem.makeTransientByteArray(
                Configuration.CARD_CHALLENGE_LENGTH,
                JCSystem.CLEAR_ON_DESELECT);
    }

    @Override
    public short process(APDU apdu, byte ins) {
        if (ins != Configuration.INS_CARD_ATTEST) {
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_P1] != 0x00 || buffer[ISO7816.OFFSET_P2] != 0x00) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }

        deviceIdentityManager.ensureCertificateInstalledForRead();

        short bytesRead = ApduUtils.receiveData(apdu);
        ApduUtils.validateExactLength(bytesRead, Configuration.CARD_CHALLENGE_LENGTH);

        short challengeOffset = ISO7816.OFFSET_CDATA;
        Util.arrayCopyNonAtomic(buffer, challengeOffset, challengeScratch, (short) 0, Configuration.CARD_CHALLENGE_LENGTH);

        short responseOffset = 0;
        buffer[responseOffset++] = Configuration.CARD_ATTEST_FORMAT_VERSION;
        deviceIdentityManager.copyDeviceId(buffer, responseOffset);
        responseOffset += Configuration.DEVICE_ID_LENGTH;
        Util.arrayCopyNonAtomic(challengeScratch, (short) 0, buffer, responseOffset, Configuration.CARD_CHALLENGE_LENGTH);
        responseOffset += Configuration.CARD_CHALLENGE_LENGTH;

        short bodyLength = responseOffset;
        short signatureLength = deviceIdentityManager.signWithDeviceKey(
                buffer,
                (short) 0,
                bodyLength,
                buffer,
                (short) (bodyLength + 1));
        if (signatureLength <= 0 || signatureLength > Configuration.MAX_DER_SIGNATURE_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        buffer[bodyLength] = (byte) signatureLength;
        ApduUtils.sendData(apdu, (short) 0, (short) (bodyLength + 1 + signatureLength));
        return ISO7816.SW_NO_ERROR;
    }
}
