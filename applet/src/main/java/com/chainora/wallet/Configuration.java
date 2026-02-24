package com.chainora.wallet;

public final class Configuration {
    private Configuration() {
        // Utility class
    }

    public static final byte PIN_TRY_LIMIT = (byte) 0x03;
    public static final byte PIN_MAX_SIZE = (byte) 0x08;
    public static final short KEY_LENGTH_BITS = 256;

    public static final byte INS_BACKUP_SESSION = (byte) 0x30;
    public static final byte INS_BACKUP_EXPORT = (byte) 0x31;
    public static final byte INS_BACKUP_IMPORT = (byte) 0x32;

    public static final byte P1_GET_DEVICE_CERT = (byte) 0x00;
    public static final byte P1_START_LINK_PROOF = (byte) 0x01;
    public static final byte P1_LOAD_PEER_CERT = (byte) 0x02;
    public static final byte P1_LOAD_PEER_LINK_PROOF = (byte) 0x03;
    public static final byte P1_CLEAR_LINK_STATE = (byte) 0x04;
    public static final byte P1_GET_FACTORY_CSR = (byte) 0x10;
    public static final byte P1_SET_DEVICE_CERT = (byte) 0x11;

    public static final byte BACKUP_FORMAT_VERSION = (byte) 0x01;
    public static final byte DEVICE_CERT_CAPABILITY_BACKUP = (byte) 0x01;

    public static final short DEVICE_ID_LENGTH = 16;
    public static final short SESSION_ID_LENGTH = 2;
    public static final short NONCE_LENGTH = 16;
    public static final short PUBLIC_KEY_UNCOMPRESSED_LENGTH = 65;
    public static final short PRIVATE_KEY_LENGTH = 32;

    public static final short DEVICE_CSR_LENGTH =
            (short) (1 + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH);

    public static final short DEVICE_CERT_BODY_LENGTH =
            (short) (1 + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH + 1);

    public static final short MAX_DER_SIGNATURE_LENGTH = 72;
    public static final short MAX_DEVICE_CERT_LENGTH =
            (short) (DEVICE_CERT_BODY_LENGTH + 1 + MAX_DER_SIGNATURE_LENGTH);

    public static final short LINK_PROOF_BODY_LENGTH =
            (short) (SESSION_ID_LENGTH + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH + NONCE_LENGTH);

    public static final short MAX_LINK_PROOF_LENGTH =
            (short) (LINK_PROOF_BODY_LENGTH + 1 + MAX_DER_SIGNATURE_LENGTH);

    public static final short BACKUP_PAYLOAD_LENGTH =
            (short) (1 + PRIVATE_KEY_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH);

    public static final short AES_BLOCK_SIZE = 16;
    public static final short MAX_BACKUP_CIPHERTEXT_LENGTH =
            (short) (((BACKUP_PAYLOAD_LENGTH / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE);

    public static final short MAX_BACKUP_ENVELOPE_LENGTH =
            (short) (1 + DEVICE_ID_LENGTH + DEVICE_ID_LENGTH + NONCE_LENGTH + 1
                    + MAX_BACKUP_CIPHERTEXT_LENGTH + 1 + MAX_DER_SIGNATURE_LENGTH);

    public static final byte[] BACKUP_KDF_LABEL = {
            (byte) 'C', (byte) 'h', (byte) 'a', (byte) 'i', (byte) 'n', (byte) 'o', (byte) 'r', (byte) 'a',
            (byte) '-', (byte) 'B', (byte) 'a', (byte) 'c', (byte) 'k', (byte) 'u', (byte) 'p', (byte) '-',
            (byte) 'v', (byte) '1'
    };

    // Temporary development root public key for factory provisioning.
    // Replace with production root key before release.
    public static final byte[] CHAINORA_DEV_ROOT_PUBLIC_KEY = {
            (byte) 0x04,
            (byte) 0xB5, (byte) 0x95, (byte) 0x8D, (byte) 0x33, (byte) 0x99, (byte) 0xBD, (byte) 0xD2,
            (byte) 0xD2, (byte) 0x1D, (byte) 0x3B, (byte) 0xB8, (byte) 0x5B, (byte) 0x28, (byte) 0x1E,
            (byte) 0x85, (byte) 0x1A, (byte) 0xBE, (byte) 0xF9, (byte) 0x50, (byte) 0x63, (byte) 0xCF,
            (byte) 0xC0, (byte) 0xC8, (byte) 0x87, (byte) 0xE8, (byte) 0x9C, (byte) 0x02, (byte) 0xC4,
            (byte) 0x37, (byte) 0x9E, (byte) 0x1D, (byte) 0x8E, (byte) 0x92, (byte) 0x1A, (byte) 0x0A,
            (byte) 0x7E, (byte) 0x9C, (byte) 0xFE, (byte) 0x61, (byte) 0x40, (byte) 0x61, (byte) 0xBB,
            (byte) 0x60, (byte) 0xB7, (byte) 0x69, (byte) 0xA7, (byte) 0x98, (byte) 0xCB, (byte) 0x6D,
            (byte) 0x1B, (byte) 0x6D, (byte) 0x34, (byte) 0x2B, (byte) 0x61, (byte) 0xE0, (byte) 0xBE,
            (byte) 0x77, (byte) 0x42, (byte) 0xAA, (byte) 0x35, (byte) 0x15, (byte) 0x2A, (byte) 0x9B,
            (byte) 0x81
    };
}
