package com.chainora.wallet;

import javacard.framework.APDU;

/**
 * Interface for command handlers in the Chainora wallet applet.
 * Follows the Command pattern for extensibility.
 */
public interface CommandHandler {
    /**
     * Process a command with the given instruction byte.
     * @param apdu The APDU containing the command data
     * @param ins The instruction byte
     * @return Status word (typically 0x9000 on success)
     */
    short process(APDU apdu, byte ins);
}
