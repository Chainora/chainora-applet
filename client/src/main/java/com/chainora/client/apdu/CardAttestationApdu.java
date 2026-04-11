package com.chainora.client.apdu;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import cz.muni.fi.crocs.rcard.client.CardManager;

import com.chainora.client.ApduConstants;

/**
 * Handles backend card attestation commands.
 */
public class CardAttestationApdu extends BaseApdu {

    public CardAttestationApdu(CardManager cardManager) {
        super(cardManager);
    }

    public byte[] signChallenge(byte[] challenge) throws CardException {
        ResponseAPDU response = transmit(
                ApduConstants.INS_CARD_ATTEST,
                (byte) 0x00,
                (byte) 0x00,
                challenge);
        return requireData(response, "Failed to sign backend challenge");
    }
}
