package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * APDU utilities for common data reception patterns.
 * Eliminates duplication of APDU handling code.
 */
public final class ApduUtils {
    private static final short SW_NO_DATA = ISO7816.SW_WRONG_LENGTH;

    private ApduUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Receives incoming data from the APDU.
     * @param apdu The APDU to receive data from
     * @return The number of bytes received
     * @throws ISOException if no data received
     */
    public static short receiveData(APDU apdu) {
        short bytesRead = apdu.setIncomingAndReceive();
        short totalLength = bytesRead;
        short incomingLength = apdu.getIncomingLength();
        short offset = (short) (ISO7816.OFFSET_CDATA + bytesRead);

        while (totalLength < incomingLength) {
            bytesRead = apdu.receiveBytes(offset);
            if (bytesRead <= 0) {
                break;
            }
            totalLength += bytesRead;
            offset += bytesRead;
        }

        if (totalLength <= 0) {
            ISOException.throwIt(SW_NO_DATA);
        }
        return totalLength;
    }

    /**
     * Validates that exactly the expected number of bytes was received.
     * @param bytesRead The number of bytes received
     * @param expected The expected number of bytes
     * @throws ISOException if length doesn't match
     */
    public static void validateExactLength(short bytesRead, short expected) {
        if (bytesRead != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    /**
     * Sends data back to the client.
     * @param apdu The APDU to send data through
     * @param offset The offset in the buffer
     * @param length The number of bytes to send
     */
    public static void sendData(APDU apdu, short offset, short length) {
        apdu.setOutgoingAndSend(offset, length);
    }
}
