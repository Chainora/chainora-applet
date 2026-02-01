package com.chainora.client.apdu;

import com.chainora.client.ApduConstants;
import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

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
        CommandAPDU command = data == null
                ? new CommandAPDU(ApduConstants.CLA, ins & 0xFF, 0x00, 0x00)
                : new CommandAPDU(ApduConstants.CLA, ins & 0xFF, 0x00, 0x00, data);
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

    /**
     * Helper method to convert byte array to hex string.
     *
     * @param data the bytes to convert
     * @return hex string representation
     */
    protected static String toHex(byte[] data) {
        if (data == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
