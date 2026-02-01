package com.chainora.client;

/**
 * APDU instruction codes for the Chainora wallet applet.
 * Single source of truth for all INS byte values.
 */
public final class ApduConstants {
    private ApduConstants() {
        // Utility class - prevent instantiation
    }

    // PIN Management Instructions (0x10-0x14)
    public static final byte INS_INIT_PIN = 0x10;
    public static final byte INS_VERIFY_PIN = 0x11;
    public static final byte INS_UPDATE_PIN = 0x12;
    public static final byte INS_RESET_PIN = 0x13;
    public static final byte INS_IS_PIN_INITIALIZED = 0x14;

    // Key Management Instructions (0x20-0x21)
    public static final byte INS_GEN_KEY_PAIR = 0x20;
    public static final byte INS_GET_PUBLIC_KEY = 0x21;

    // Signing Instruction (0x22)
    public static final byte INS_SIGN_HASH = 0x22;

    // APDU Constants
    public static final byte CLA = 0x00;
    public static final int SW_SUCCESS = 0x9000;
}
