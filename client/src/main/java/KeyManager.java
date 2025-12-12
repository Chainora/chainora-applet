import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

public class KeyManager extends BaseApduManager {
    private static final byte INS_GEN_KEY_PAIR = (byte) 0x20;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x21;
    private static final byte INS_SIGN_HASH = (byte) 0x22;

    public KeyManager(CardManager cardManager) {
        super(cardManager);
    }

    public void generateKeyPair() throws CardException {
        printResponse(transmit(INS_GEN_KEY_PAIR, null));
    }

    public void printPublicKey() throws CardException {
        final ResponseAPDU response = transmit(INS_GET_PUBLIC_KEY, null);
        if (isSuccess(response) && hasData(response)) {
            System.out.println("Public key: " + toHex(response.getData()));
        }
        printResponse(response);
    }

    public void signHash(byte[] hash) throws CardException {
        final ResponseAPDU response = transmit(INS_SIGN_HASH, hash);
        if (isSuccess(response) && hasData(response)) {
            System.out.println("Chữ ký: " + toHex(response.getData()));
        }
        printResponse(response);
    }
}
