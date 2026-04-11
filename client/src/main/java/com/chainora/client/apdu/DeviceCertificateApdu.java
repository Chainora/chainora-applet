package com.chainora.client.apdu;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import cz.muni.fi.crocs.rcard.client.CardManager;

import com.chainora.client.ApduConstants;

/**
 * Handles device certificate and factory provisioning commands.
 */
public class DeviceCertificateApdu extends BaseApdu {

    public DeviceCertificateApdu(CardManager cardManager) {
        super(cardManager);
    }

    public byte[] getDeviceCertificate() throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_DEVICE_CERT,
                ApduConstants.P1_GET_DEVICE_CERT,
                (byte) 0x00,
                null);
        return requireData(response, "Failed to get device certificate");
    }

    public byte[] getFactoryCsr() throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_DEVICE_CERT,
                ApduConstants.P1_GET_FACTORY_CSR,
                (byte) 0x00,
                null);
        return requireData(response, "Failed to get factory CSR");
    }

    public void setDeviceCertificate(byte[] certificate) throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_DEVICE_CERT,
                ApduConstants.P1_SET_DEVICE_CERT,
                (byte) 0x00,
                certificate);
        ensureSuccess(response, "Failed to set device certificate");
    }
}
