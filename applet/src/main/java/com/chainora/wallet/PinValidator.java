package com.chainora.wallet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

/**
 * Centralized PIN validation utility.
 * Eliminates duplication of PIN validation logic across handlers.
 */
public final class PinValidator {
    private static final short SW_PIN_NOT_INITIALIZED = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
    private static final short SW_PIN_NOT_VALIDATED = ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
    private static final short SW_INVALID_PIN_LENGTH = ISO7816.SW_WRONG_LENGTH;

    private boolean pinInitialized;
    private final OwnerPIN pin;

    public PinValidator(OwnerPIN pin) {
        this.pinInitialized = false;
        this.pin = pin;
    }

    /**
     * Ensures the PIN has been initialized.
     * @throws ISOException if PIN not initialized
     */
    public void ensureInitialized() {
        if (!pinInitialized) {
            ISOException.throwIt(SW_PIN_NOT_INITIALIZED);
        }
    }

    /**
     * Ensures the PIN has been validated for the current session.
     * @throws ISOException if PIN not validated
     */
    public void ensureValidated() {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_NOT_VALIDATED);
        }
    }

    /**
     * Ensures both initialization and validation.
     */
    public void ensureInitializedAndValidated() {
        ensureInitialized();
        ensureValidated();
    }

    /**
     * Validates that the PIN data length is within acceptable bounds.
     * @param bytesRead The number of bytes read
     * @throws ISOException if length is invalid
     */
    public void validatePinLength(short bytesRead) {
        if (bytesRead <= 0 || bytesRead > Configuration.PIN_MAX_SIZE) {
            ISOException.throwIt(SW_INVALID_PIN_LENGTH);
        }
    }

    /**
     * Checks if the provided PIN matches the stored PIN.
     * @param buffer APDU buffer containing PIN data
     * @param offset Offset to PIN data in buffer
     * @param length Length of PIN data
     * @return true if PIN matches, false otherwise
     */
    public boolean checkPin(byte[] buffer, short offset, byte length) {
        return pin.check(buffer, offset, length);
    }

    /**
     * Updates the stored PIN.
     * @param buffer APDU buffer containing new PIN
     * @param offset Offset to PIN data in buffer
     * @param length Length of PIN data
     */
    public void updatePin(byte[] buffer, short offset, byte length) {
        pin.update(buffer, offset, length);
    }

    /**
     * Resets the PIN validation state.
     */
    public void reset() {
        pin.reset();
        pinInitialized = false;
    }

    /**
     * Marks the PIN as initialized (called after INIT_PIN).
     */
    public void markInitialized() {
        pinInitialized = true;
    }

    /**
     * Checks if the PIN has been initialized.
     * @return true if initialized, false otherwise
     */
    public boolean isInitialized() {
        return pinInitialized;
    }
}
