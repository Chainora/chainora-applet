package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Handles dedicated factory provisioning and device certificate commands.
 */
final class DeviceCertificateCommandHandler implements CommandHandler {
    private static final short SW_INS_NOT_SUPPORTED = ISO7816.SW_INS_NOT_SUPPORTED;
    private static final short SW_WRONG_P1P2 = ISO7816.SW_INCORRECT_P1P2;

    private final DeviceIdentityManager deviceIdentityManager;

    DeviceCertificateCommandHandler(DeviceIdentityManager deviceIdentityManager) {
        this.deviceIdentityManager = deviceIdentityManager;
    }

    @Override
    public short process(APDU apdu, byte ins) {
        if (ins != Configuration.INS_DEVICE_CERT) {
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_P2] != 0x00) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }

        switch (buffer[ISO7816.OFFSET_P1]) {
            case Configuration.P1_GET_DEVICE_CERT:
                deviceIdentityManager.sendDeviceCertificate(apdu);
                break;
            case Configuration.P1_GET_FACTORY_CSR:
                deviceIdentityManager.sendFactoryCsr(apdu);
                break;
            case Configuration.P1_SET_DEVICE_CERT:
                deviceIdentityManager.setDeviceCertificate(apdu);
                break;
            default:
                ISOException.throwIt(SW_WRONG_P1P2);
        }
        return ISO7816.SW_NO_ERROR;
    }
}
