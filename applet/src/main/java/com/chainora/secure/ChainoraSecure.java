package com.chainora.secure;

import com.chainora.shareable.Configuration;
import com.chainora.shareable.IChainoraSecure;

import javacard.framework.*;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

public class ChainoraSecure extends Applet implements IChainoraSecure {
	// === PIN Management ===
	private boolean pinInitialized;
	private final OwnerPIN pin;

	// === KeyPair Management ===
	private ECPrivateKey privateKey;
	private ECPublicKey publicKey;
	private KeyPair keyPair;

	private static final byte[] P = {
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC, (byte) 0x2F
	};

	private static final byte[] A = { (byte) 0x00 };
	private static final byte[] B = { (byte) 0x07 };

	private static final byte[] G = {
			(byte) 0x04, // uncompressed prefix
			(byte) 0x79, (byte) 0xBE, (byte) 0x66, (byte) 0x7E, (byte) 0xF9, (byte) 0xDC, (byte) 0xBB, (byte) 0xAC,
			(byte) 0x55, (byte) 0xA0, (byte) 0x62, (byte) 0x95, (byte) 0xCE, (byte) 0x87, (byte) 0x0B, (byte) 0x07,
			(byte) 0x02, (byte) 0x9B, (byte) 0xFC, (byte) 0xDB, (byte) 0x2D, (byte) 0xCE, (byte) 0x28, (byte) 0xD9,
			(byte) 0x59, (byte) 0xF2, (byte) 0x81, (byte) 0x5B, (byte) 0x16, (byte) 0xF8, (byte) 0x17, (byte) 0x98,
			(byte) 0x48, (byte) 0x3A, (byte) 0xDA, (byte) 0x77, (byte) 0x26, (byte) 0xA3, (byte) 0xC4, (byte) 0x65,
			(byte) 0x5D, (byte) 0xA4, (byte) 0xFB, (byte) 0xFC, (byte) 0x0E, (byte) 0x11, (byte) 0x08, (byte) 0xA8,
			(byte) 0xFD, (byte) 0x17, (byte) 0xB4, (byte) 0x48, (byte) 0xA6, (byte) 0x85, (byte) 0x54, (byte) 0x19,
			(byte) 0x9C, (byte) 0x47, (byte) 0xD0, (byte) 0x8F, (byte) 0xFB, (byte) 0x10, (byte) 0xD4, (byte) 0xB8
	};

	private static final byte[] N = {
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
			(byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B,
			(byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41
	};

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ChainoraSecure();
	}

	public ChainoraSecure() {
		// === PIN Management Initialization ===
		pinInitialized = false;
		pin = new OwnerPIN(Configuration.PIN_TRY_LIMIT, Configuration.PIN_MAX_SIZE);

		// === KeyPair Management Initialization ===
		privateKey = (ECPrivateKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PRIVATE,
				Configuration.KEY_LENGTH_BITS,
				false);

		publicKey = (ECPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PUBLIC,
				Configuration.KEY_LENGTH_BITS,
				false);

		setCurveParameters(privateKey);
		setCurveParameters(publicKey);

		keyPair = new KeyPair(publicKey, privateKey);
		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}
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

	// === KeyPair Management Interface ===
	private void setCurveParameters(ECKey key) {
		key.setFieldFP(P, (short) 0, (short) P.length);
		key.setA(A, (short) 0, (short) A.length);
		key.setB(B, (short) 0, (short) B.length);
		key.setG(G, (short) 0, (short) G.length);
		key.setR(N, (short) 0, (short) N.length);
		key.setK((short) 1);
	}

	@Override
	public void generateKeyPair() {
		keyPair.genKeyPair();
	}

	@Override
	public short getPublicKey(byte[] dest, short destOffset) {
		if (!pinInitialized) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		return publicKey.getW(dest, destOffset);
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
