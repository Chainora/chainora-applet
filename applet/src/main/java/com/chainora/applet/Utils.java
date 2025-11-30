package com.chainora.applet;

import javacard.framework.JCSystem;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public final class Utils {
    public static final IChainoraStorage getChainoraStorage(AID storageAID) {
        IChainoraStorage storage = (IChainoraStorage) JCSystem.getAppletShareableInterfaceObject(storageAID, (byte) 0);
        if (storage == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        return storage;
    }
}
