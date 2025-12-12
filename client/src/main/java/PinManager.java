import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

public class PinManager extends BaseApduManager {
    private static final byte INS_INIT_PIN = (byte) 0x10;
    private static final byte INS_VERIFY_PIN = (byte) 0x11;
    private static final byte INS_UPDATE_PIN = (byte) 0x12;
    private static final byte INS_RESET_PIN = (byte) 0x13;
    private static final byte INS_IS_PIN_INITIALIZED = (byte) 0x14;

    public PinManager(CardManager cardManager) {
        super(cardManager);
    }

    public void printPinState() throws CardException {
        final ResponseAPDU response = transmit(INS_IS_PIN_INITIALIZED, null);
        if (isSuccess(response) && hasData(response)) {
            final boolean initialized = response.getData()[0] == 1;
            System.out.println(initialized ? "PIN already initialized." : "PIN not initialized.");
        }
        printResponse(response);
    }

    public void initPin(byte[] pin) throws CardException {
        printResponse(transmit(INS_INIT_PIN, pin));
    }

    public void verifyPin(byte[] pin) throws CardException {
        printResponse(transmit(INS_VERIFY_PIN, pin));
    }

    public void updatePin(byte[] pin) throws CardException {
        printResponse(transmit(INS_UPDATE_PIN, pin));
    }

    public void resetPin() throws CardException {
        printResponse(transmit(INS_RESET_PIN, null));
    }
}
