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

    // Device identity instructions (0x23-0x24)
    public static final byte INS_DEVICE_CERT = 0x23;
    public static final byte INS_CARD_ATTEST = 0x24;

    // Backup instructions (0x30-0x32)
    public static final byte INS_BACKUP_SESSION = 0x30;
    public static final byte INS_BACKUP_EXPORT = 0x31;
    public static final byte INS_BACKUP_IMPORT = 0x32;

    // Shared certificate/factory P1 values used by INS_DEVICE_CERT.
    public static final byte P1_GET_DEVICE_CERT = 0x00;
    public static final byte P1_START_LINK_PROOF = 0x01;
    public static final byte P1_LOAD_PEER_CERT = 0x02;
    public static final byte P1_LOAD_PEER_LINK_PROOF = 0x03;
    public static final byte P1_CLEAR_LINK_STATE = 0x04;
    public static final byte P1_GET_FACTORY_CSR = 0x10;
    public static final byte P1_SET_DEVICE_CERT = 0x11;

    // APDU Constants
    public static final byte CLA = (byte) 0x80;
    public static final int SW_SUCCESS = 0x9000;
}
