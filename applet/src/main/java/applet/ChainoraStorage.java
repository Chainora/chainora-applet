package applet;

import javacard.framework.*;

// Applet to store data in the card's persistent storage.
public class ChainoraStorage extends Applet {

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ChainoraStorage();
    }

    public ChainoraStorage() {
        register();
    }

    public void process(APDU apdu) {
    }

}
