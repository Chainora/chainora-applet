package com.chainora.shareable;

import javacard.framework.JCSystem;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public final class Utils {
    public static final IChainoraSecure getChainoraStorage(AID serverAID) {
        IChainoraSecure storage = (IChainoraSecure) JCSystem.getAppletShareableInterfaceObject(serverAID, (byte) 0);
        if (storage == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        return storage;
    }
}
