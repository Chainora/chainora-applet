package com.chainora.wallet;

/**
 * Common configuration constants for the Chainora Wallet applet.
 * Static array initializations are avoided to stay JavaCard compliant.
 */
public final class Configuration {
    public static final byte PIN_TRY_LIMIT = (byte) 0x03;
    public static final byte PIN_MAX_SIZE = (byte) 0x08;
    public static final short KEY_LENGTH_BITS = 256;
}
