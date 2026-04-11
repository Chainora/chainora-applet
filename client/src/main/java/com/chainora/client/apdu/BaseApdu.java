package com.chainora.client.apdu;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import cz.muni.fi.crocs.rcard.client.CardManager;

import com.chainora.client.ApduConstants;

/**
 * Base class for APDU operations. Provides common functionality for
 * transmitting commands to the card and handling responses.
 */
public abstract class BaseApdu {
    protected final CardManager cardManager;

    protected BaseApdu(CardManager cardManager) {
        this.cardManager = cardManager;
    }

    /**
     * Transmits an APDU command to the card.
     *
     * @param ins the instruction byte
     * @param data the command data, or null if no data
     * @return the response from the card
     * @throws CardException if communication with the card fails
     */
    protected ResponseAPDU transmit(byte ins, byte[] data) throws CardException {
        return transmit(ins, (byte) 0x00, (byte) 0x00, data);
    }

    /**
     * Transmits an APDU command to the card with explicit P1/P2.
     *
     * @param ins the instruction byte
     * @param p1 the P1 parameter byte
     * @param p2 the P2 parameter byte
     * @param data the command data, or null if no data
     * @return the response from the card
     * @throws CardException if communication with the card fails
     */
    protected ResponseAPDU transmit(byte ins, byte p1, byte p2, byte[] data) throws CardException {
        CommandAPDU command = data == null
                ? new CommandAPDU(ApduConstants.CLA, ins & 0xFF, p1 & 0xFF, p2 & 0xFF)
                : new CommandAPDU(ApduConstants.CLA, ins & 0xFF, p1 & 0xFF, p2 & 0xFF, data);
        return cardManager.transmit(command);
    }

    /**
     * Checks if the response indicates success.
     *
     * @param response the card response
     * @return true if SW = 0x9000
     */
    protected boolean isSuccess(ResponseAPDU response) {
        return response.getSW() == ApduConstants.SW_SUCCESS;
    }

    /**
     * Checks if the response contains data.
     *
     * @param response the card response
     * @return true if response has non-empty data
     */
    protected boolean hasData(ResponseAPDU response) {
        byte[] data = response.getData();
        return data != null && data.length > 0;
    }

    protected void ensureSuccess(ResponseAPDU response, String message) throws CardOperationException {
        if (!isSuccess(response)) {
            throw new CardOperationException(message, response.getSW());
        }
    }

    protected byte[] requireData(ResponseAPDU response, String message) throws CardOperationException {
        if (!isSuccess(response) || !hasData(response)) {
            throw new CardOperationException(message, response.getSW());
        }
        return response.getData();
    }

}
