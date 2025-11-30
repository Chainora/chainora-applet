package com.chainora.shareable;

/**
 * Configuration constants for Chainora Applets
 * Note: In JavaCard, static array initialization is not allowed in library
 * packages.
 * Use primitives directly instead.
 */
public class Configuration {
        // PIN Configuration
        public static final byte PIN_TRY_LIMIT = (byte) 0x03;
        public static final byte PIN_MAX_SIZE = (byte) 0x08;
}
