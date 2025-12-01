package com.chainora.shareable;

import javacard.framework.Shareable;

public interface IChainoraSecure extends Shareable {

    // === PIN Methods ===
    void initPin(byte[] pinBuffer, short pinOffset, byte pinLength);

    boolean isPinInitialize();

    void updatePin(byte[] pinBuffer, short pinOffset, byte pinLength);

    void verifyPin(byte[] pinBuffer, short pinOffset, byte pinLength);

    void resetPin();

    // === Very Secret Methods ===
    short getVerySecretKey(byte[] dest, short destOffset);
}
