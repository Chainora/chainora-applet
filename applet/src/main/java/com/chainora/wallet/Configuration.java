package com.chainora.wallet;

public final class Configuration {
    private Configuration() {
        // Utility class
    }

    public static final byte PIN_TRY_LIMIT = (byte) 0x03;
    public static final byte PIN_MAX_SIZE = (byte) 0x08;
    public static final short KEY_LENGTH_BITS = 256;

    public static final byte INS_DEVICE_CERT = (byte) 0x23;
    public static final byte INS_CARD_ATTEST = (byte) 0x24;

    public static final byte INS_BACKUP_SESSION = (byte) 0x30;
    public static final byte INS_BACKUP_EXPORT = (byte) 0x31;
    public static final byte INS_BACKUP_IMPORT = (byte) 0x32;

    // Shared certificate/factory P1 values used by INS_DEVICE_CERT.
    public static final byte P1_GET_DEVICE_CERT = (byte) 0x00;
    public static final byte P1_START_LINK_PROOF = (byte) 0x01;
    public static final byte P1_LOAD_PEER_CERT = (byte) 0x02;
    public static final byte P1_LOAD_PEER_LINK_PROOF = (byte) 0x03;
    public static final byte P1_CLEAR_LINK_STATE = (byte) 0x04;
    public static final byte P1_GET_FACTORY_CSR = (byte) 0x10;
    public static final byte P1_SET_DEVICE_CERT = (byte) 0x11;

    public static final byte DEVICE_CERT_FORMAT_VERSION = (byte) 0x01;
    public static final byte CARD_ATTEST_FORMAT_VERSION = (byte) 0x01;
    public static final byte BACKUP_PROTOCOL_VERSION = (byte) 0x02;
    public static final short LINK_PROOF_COUNTER = (short) 0x0001;
    public static final short BACKUP_ENVELOPE_COUNTER = (short) 0x0002;
    public static final byte BACKUP_FAILURE_THRESHOLD = (byte) 0x03;
    public static final byte DEVICE_CERT_CAPABILITY_BACKUP = (byte) 0x01;

    public static final short DEVICE_ID_LENGTH = 16;
    public static final short SESSION_ID_LENGTH = 2;
    public static final short COUNTER_LENGTH = 2;
    public static final short NONCE_LENGTH = 16;
    public static final short CARD_CHALLENGE_LENGTH = 32;
    public static final short PUBLIC_KEY_UNCOMPRESSED_LENGTH = 65;
    public static final short PRIVATE_KEY_LENGTH = 32;

    public static final short DEVICE_CSR_LENGTH =
            (short) (1 + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH);

    public static final short DEVICE_CERT_BODY_LENGTH =
            (short) (1 + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH + 1);

    public static final short MAX_DER_SIGNATURE_LENGTH = 72;
    public static final short MAX_DEVICE_CERT_LENGTH =
            (short) (DEVICE_CERT_BODY_LENGTH + 1 + MAX_DER_SIGNATURE_LENGTH);

    public static final short CARD_ATTEST_BODY_LENGTH =
            (short) (1 + DEVICE_ID_LENGTH + CARD_CHALLENGE_LENGTH);

    public static final short MAX_CARD_ATTEST_LENGTH =
            (short) (CARD_ATTEST_BODY_LENGTH + 1 + MAX_DER_SIGNATURE_LENGTH);

    public static final short LINK_PROOF_BODY_LENGTH =
            (short) (1 + SESSION_ID_LENGTH + COUNTER_LENGTH + DEVICE_ID_LENGTH
                    + PUBLIC_KEY_UNCOMPRESSED_LENGTH + NONCE_LENGTH);

    public static final short MAX_LINK_PROOF_LENGTH =
            (short) (LINK_PROOF_BODY_LENGTH + 1 + MAX_DER_SIGNATURE_LENGTH);

    public static final short BACKUP_PAYLOAD_LENGTH =
            (short) (1 + PRIVATE_KEY_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH);

    public static final short AES_BLOCK_SIZE = 16;
    public static final short MAX_BACKUP_CIPHERTEXT_LENGTH =
            (short) (((BACKUP_PAYLOAD_LENGTH / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE);

    public static final short MAX_BACKUP_ENVELOPE_LENGTH =
            (short) (1 + SESSION_ID_LENGTH + COUNTER_LENGTH + DEVICE_ID_LENGTH + DEVICE_ID_LENGTH + NONCE_LENGTH + 1
                    + MAX_BACKUP_CIPHERTEXT_LENGTH + 1 + MAX_DER_SIGNATURE_LENGTH);

    public static final byte[] BACKUP_KDF_LABEL = {
            (byte) 'C', (byte) 'h', (byte) 'a', (byte) 'i', (byte) 'n', (byte) 'o', (byte) 'r', (byte) 'a',
            (byte) '-', (byte) 'B', (byte) 'a', (byte) 'c', (byte) 'k', (byte) 'u', (byte) 'p', (byte) '-',
            (byte) 'v', (byte) '2'
    };

    // Factory root public key used to verify device certificates on card.
    public static final byte[] CHAINORA_FACTORY_ROOT_PUBLIC_KEY = {
            (byte) 0x04,
            (byte) 0x3E, (byte) 0x56, (byte) 0x62, (byte) 0x94, (byte) 0x9A, (byte) 0xF3, (byte) 0xD3,
            (byte) 0xBD, (byte) 0xF8, (byte) 0xC2, (byte) 0x26, (byte) 0xBD, (byte) 0xD8, (byte) 0x44,
            (byte) 0x40, (byte) 0x98, (byte) 0xA1, (byte) 0x4F, (byte) 0x89, (byte) 0x60, (byte) 0x87,
            (byte) 0x0C, (byte) 0xCB, (byte) 0x5B, (byte) 0xE5, (byte) 0x5B, (byte) 0xBE, (byte) 0x09,
            (byte) 0x8B, (byte) 0x36, (byte) 0x3A, (byte) 0xAD, (byte) 0xD0, (byte) 0x61, (byte) 0x09,
            (byte) 0xC1, (byte) 0xC5, (byte) 0x0C, (byte) 0xFC, (byte) 0xFB, (byte) 0x44, (byte) 0xF8,
            (byte) 0x0E, (byte) 0xCD, (byte) 0x08, (byte) 0x2F, (byte) 0xD1, (byte) 0xD0, (byte) 0x0F,
            (byte) 0xC8, (byte) 0xDE, (byte) 0x8C, (byte) 0x73, (byte) 0xED, (byte) 0x52, (byte) 0x1A,
            (byte) 0xD0, (byte) 0xBA, (byte) 0xB9, (byte) 0x62, (byte) 0x42, (byte) 0x2F, (byte) 0x72,
            (byte) 0x1A
    };
}
