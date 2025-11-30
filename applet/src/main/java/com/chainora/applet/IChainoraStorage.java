package com.chainora.applet;

import javacard.framework.Shareable;

public interface IChainoraStorage extends Shareable {

    // === PIN Methods ===
    void initPin(byte[] pinBuffer, short pinOffset, byte pinLength);

    boolean isPinInitialize();

    void updatePin(byte[] pinBuffer, short pinOffset, byte pinLength);

    void verifyPin(byte[] pinBuffer, short pinOffset, byte pinLength);

    void resetPin();

    // === Blockchain Methods ===
}
