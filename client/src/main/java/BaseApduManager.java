import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

abstract class BaseApduManager {
    private static final byte CLA = (byte) 0x00;

    private final CardManager cardManager;

    protected BaseApduManager(CardManager cardManager) {
        this.cardManager = cardManager;
    }

    protected ResponseAPDU transmit(byte ins, byte[] data) throws CardException {
        final CommandAPDU command = data == null
                ? new CommandAPDU(CLA & 0xFF, ins & 0xFF, 0x00, 0x00)
                : new CommandAPDU(CLA & 0xFF, ins & 0xFF, 0x00, 0x00, data);
        return cardManager.transmit(command);
    }

    protected boolean isSuccess(ResponseAPDU response) {
        return response.getSW() == 0x9000;
    }

    protected boolean hasData(ResponseAPDU response) {
        final byte[] data = response.getData();
        return data != null && data.length > 0;
    }

    protected void printResponse(ResponseAPDU response) {
        System.out.printf("SW: %04X%n", response.getSW());
        final byte[] data = response.getData();
        if (data != null && data.length > 0) {
            System.out.println("DATA: " + toHex(data));
        }
    }

    protected static String toHex(byte[] data) {
        final StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
