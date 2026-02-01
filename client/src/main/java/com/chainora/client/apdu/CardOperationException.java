package com.chainora.client.apdu;

import javax.smartcardio.CardException;

/**
 * Exception thrown when a card operation fails.
 */
public class CardOperationException extends CardException {
    private final int sw;

    public CardOperationException(String message, int sw) {
        super(message);
        this.sw = sw;
    }

    public CardOperationException(String message, int sw, Throwable cause) {
        super(message, cause);
        this.sw = sw;
    }

    /**
     * Returns the status word from the card response.
     *
     * @return the SW code
     */
    public int getSw() {
        return sw;
    }
}
