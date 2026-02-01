package com.chainora.client.apdu;

import com.chainora.client.ApduConstants;
import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

/**
 * Handles all PIN-related APDU commands (INS 0x10-0x14).
 */
public class PinApdu extends BaseApdu {

    public PinApdu(CardManager cardManager) {
        super(cardManager);
    }

    /**
     * Checks if the PIN has been initialized on the card.
     *
     * @return true if PIN is initialized, false otherwise
     * @throws CardException if communication with the card fails
     */
    public boolean isInitialized() throws CardException {
        ResponseAPDU response = transmit(ApduConstants.INS_IS_PIN_INITIALIZED, null);
        if (isSuccess(response) && hasData(response)) {
            return response.getData()[0] == 1;
        }
        return false;
    }

    /**
     * Initializes the PIN on the card.
     *
     * @param pin the PIN bytes (max 16 bytes)
     * @throws CardException if communication with the card fails
     */
    public void init(byte[] pin) throws CardException {
        ResponseAPDU response = transmit(ApduConstants.INS_INIT_PIN, pin);
        if (!isSuccess(response)) {
            throw new CardOperationException("Failed to initialize PIN", response.getSW());
        }
    }

    /**
     * Verifies the PIN on the card.
     *
     * @param pin the PIN bytes to verify
     * @return true if PIN is correct
     * @throws CardException if communication with the card fails
     */
    public boolean verify(byte[] pin) throws CardException {
        ResponseAPDU response = transmit(ApduConstants.INS_VERIFY_PIN, pin);
        return isSuccess(response);
    }

    /**
     * Updates the PIN on the card.
     *
     * @param currentPin the current PIN bytes
     * @param newPin the new PIN bytes
     * @throws CardException if communication with the card fails
     */
    public void update(byte[] currentPin, byte[] newPin) throws CardException {
        // Format: [curLen:1][curPIN][newPIN]
        byte[] data = new byte[1 + currentPin.length + newPin.length];
        data[0] = (byte) currentPin.length;
        System.arraycopy(currentPin, 0, data, 1, currentPin.length);
        System.arraycopy(newPin, 0, data, 1 + currentPin.length, newPin.length);

        ResponseAPDU response = transmit(ApduConstants.INS_UPDATE_PIN, data);
        if (!isSuccess(response)) {
            throw new CardOperationException("Failed to update PIN", response.getSW());
        }
    }

    /**
     * Resets the PIN on the card (requires PIN validation first).
     *
     * @throws CardException if communication with the card fails
     */
    public void reset() throws CardException {
        ResponseAPDU response = transmit(ApduConstants.INS_RESET_PIN, null);
        if (!isSuccess(response)) {
            throw new CardOperationException("Failed to reset PIN", response.getSW());
        }
    }
}
