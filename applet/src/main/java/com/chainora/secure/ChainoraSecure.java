package com.chainora.secure;

import com.chainora.shareable.Configuration;
import com.chainora.shareable.IChainoraSecure;

import javacard.framework.*;

public class ChainoraSecure extends Applet implements IChainoraSecure {
	// === PIN Management ===
	private boolean pinInitialized;
	private final OwnerPIN pin;

	// === Test Very Secret Key ===
	private byte[] verySecretKey;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ChainoraSecure();
	}

	public ChainoraSecure() {
		pinInitialized = false;
		verySecretKey = new byte[] { 'C', 'h', 'a', 'i', 'n', 'o', 'r', 'a', ' ', 'S', 't', 'o', 'r', 'a', 'g', 'e' };
		pin = new OwnerPIN(Configuration.PIN_TRY_LIMIT, Configuration.PIN_MAX_SIZE);
		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet())
			return;
		throw new ISOException(ISO7816.SW_INS_NOT_SUPPORTED);
	}

	// === PIN Management Interface ===
	@Override
	public void initPin(byte[] pinBuffer, short pinOffset, byte pinLength) {
		if (pinInitialized) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		pin.update(pinBuffer, pinOffset, pinLength);
		pinInitialized = true;
	}

	@Override
	public boolean isPinInitialize() {
		return pinInitialized;
	}

	@Override
	public void updatePin(byte[] pinBuffer, short pinOffset, byte pinLength) {
		if (!pinInitialized)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if (!pin.isValidated())
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		pin.update(pinBuffer, pinOffset, pinLength);
	}

	@Override
	public void verifyPin(byte[] pinBuffer, short pinOffset, byte pinLength) {
		if (!pinInitialized)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if (!pin.check(pinBuffer, pinOffset, pinLength)) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}

	@Override
	public void resetPin() {
		pin.reset();
		pinInitialized = false;
	}

	// === Test Very Secret Key Interface ===
	@Override
	public byte[] getVerySecretKey() {
		if (!pinInitialized || !pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		return verySecretKey;
	}

	// === Shareable Interface ===
	@Override
	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
		if (clientAID == null) {
			return null;
		}
		// Build AID array from individual bytes for comparison
		byte[] walletBytes = new byte[] {
				(byte) 0xF0, 0x56, 0x4E, 0x43, 0x48, 0x57, 0x01
		};
		if (clientAID.partialEquals(walletBytes, (short) 0,
				(byte) walletBytes.length) == false) {
			return null;
		}
		return this;
	}
}
