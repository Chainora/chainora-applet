package com.chainora.client.apdu;

import com.chainora.client.ApduConstants;
import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

/**
 * Handles key-related APDU commands (INS 0x20-0x21).
 */
public class KeyApdu extends BaseApdu {

    public KeyApdu(CardManager cardManager) {
        super(cardManager);
    }

    /**
     * Generates a new secp256k1 key pair on the card.
     *
     * @throws CardException if communication with the card fails
     */
    public void generateKeyPair() throws CardException {
        ResponseAPDU response = transmit(ApduConstants.INS_GEN_KEY_PAIR, null);
        if (!isSuccess(response)) {
            throw new CardOperationException("Failed to generate key pair", response.getSW());
        }
    }

    /**
     * Retrieves the public key from the card.
     *
     * @return the public key bytes (65 bytes for uncompressed)
     * @throws CardException if communication with the card fails
     */
    public byte[] getPublicKey() throws CardException {
        ResponseAPDU response = transmit(ApduConstants.INS_GET_PUBLIC_KEY, null);
        if (!isSuccess(response) || !hasData(response)) {
            throw new CardOperationException("Failed to get public key", response.getSW());
        }
        return response.getData();
    }
}
