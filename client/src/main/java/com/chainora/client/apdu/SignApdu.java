package com.chainora.client.apdu;

import com.chainora.client.ApduConstants;
import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

/**
 * Handles signing APDU commands (INS 0x22).
 */
public class SignApdu extends BaseApdu {

    public SignApdu(CardManager cardManager) {
        super(cardManager);
    }

    /**
     * Signs a pre-computed hash using the card's private key.
     * The hash should already be Keccak256 hashed by the client.
     *
     * @param hash the 32-byte hash to sign
     * @return the DER-encoded signature bytes
     * @throws CardException if communication with the card fails
     */
    public byte[] signHash(byte[] hash) throws CardException {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }
        ResponseAPDU response = transmit(ApduConstants.INS_SIGN_HASH, hash);
        if (!isSuccess(response) || !hasData(response)) {
            throw new CardOperationException("Failed to sign hash", response.getSW());
        }
        return response.getData();
    }
}
