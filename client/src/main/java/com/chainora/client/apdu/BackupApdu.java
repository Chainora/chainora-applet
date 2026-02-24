package com.chainora.client.apdu;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import cz.muni.fi.crocs.rcard.client.CardManager;

import com.chainora.client.ApduConstants;

/**
 * Handles backup APDU commands (INS 0x30-0x32).
 */
public class BackupApdu extends BaseApdu {

    public BackupApdu(CardManager cardManager) {
        super(cardManager);
    }

    public byte[] getDeviceCertificate() throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_BACKUP_SESSION,
                ApduConstants.P1_GET_DEVICE_CERT,
                (byte) 0x00,
                null);
        return requireData(response, "Failed to get device certificate");
    }

    public byte[] startLinkProof() throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_BACKUP_SESSION,
                ApduConstants.P1_START_LINK_PROOF,
                (byte) 0x00,
                null);
        return requireData(response, "Failed to start link proof");
    }

    public void loadPeerCertificate(byte[] peerCertificate) throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_BACKUP_SESSION,
                ApduConstants.P1_LOAD_PEER_CERT,
                (byte) 0x00,
                peerCertificate);
        ensureSuccess(response, "Failed to load peer certificate");
    }

    public void loadPeerLinkProof(byte[] peerLinkProof) throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_BACKUP_SESSION,
                ApduConstants.P1_LOAD_PEER_LINK_PROOF,
                (byte) 0x00,
                peerLinkProof);
        ensureSuccess(response, "Failed to load peer link proof");
    }

    public void clearLinkState() throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_BACKUP_SESSION,
                ApduConstants.P1_CLEAR_LINK_STATE,
                (byte) 0x00,
                null);
        ensureSuccess(response, "Failed to clear link state");
    }

    public byte[] exportBackupEnvelope() throws CardException {
        ResponseAPDU response = transmit(ApduConstants.INS_BACKUP_EXPORT, null);
        return requireData(response, "Failed to export backup envelope");
    }

    public void importBackupEnvelope(byte[] backupEnvelope) throws CardException {
        ResponseAPDU response = transmit(ApduConstants.INS_BACKUP_IMPORT, backupEnvelope);
        ensureSuccess(response, "Failed to import backup envelope");
    }

    private void ensureSuccess(ResponseAPDU response, String message) throws CardOperationException {
        if (!isSuccess(response)) {
            throw new CardOperationException(message, response.getSW());
        }
    }

    private byte[] requireData(ResponseAPDU response, String message) throws CardOperationException {
        if (!isSuccess(response) || !hasData(response)) {
            throw new CardOperationException(message, response.getSW());
        }
        return response.getData();
    }
}
