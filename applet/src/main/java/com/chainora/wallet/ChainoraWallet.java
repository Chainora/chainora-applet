package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class ChainoraWallet extends Applet {
	private static final byte INS_INIT_PIN = (byte) 0x10;
	private static final byte INS_VERIFY_PIN = (byte) 0x11;
	private static final byte INS_UPDATE_PIN = (byte) 0x12;
	private static final byte INS_RESET_PIN = (byte) 0x13;
	private static final byte INS_IS_PIN_INITIALIZED = (byte) 0x14;
	private static final byte INS_GEN_KEY_PAIR = (byte) 0x20;
	private static final byte INS_GET_PUBLIC_KEY = (byte) 0x21;
	private static final byte INS_SIGN_HASH = (byte) 0x22;

	private boolean pinInitialized;
	private final OwnerPIN pin;
	private final ECPrivateKey privateKey;
	private final ECPublicKey publicKey;
	private final KeyPair keyPair;
	private final Signature ecdsaSignature;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ChainoraWallet();
	}

	private ChainoraWallet() {
		pinInitialized = false;
		pin = new OwnerPIN(Configuration.PIN_TRY_LIMIT, Configuration.PIN_MAX_SIZE);

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

		ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		switch (buffer[ISO7816.OFFSET_INS]) {
			case INS_INIT_PIN:
				initPin(apdu);
				break;
			case INS_VERIFY_PIN:
				verifyPin(apdu);
				break;
			case INS_UPDATE_PIN:
				updatePin(apdu);
				break;
			case INS_RESET_PIN:
				resetPin();
				break;
			case INS_IS_PIN_INITIALIZED:
				sendPinState(apdu);
				break;
			case INS_GEN_KEY_PAIR:
				generateKeyPair();
				break;
			case INS_GET_PUBLIC_KEY:
				sendPublicKey(apdu);
				break;
			case INS_SIGN_HASH:
				signHash(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void initPin(APDU apdu) {
		if (pinInitialized) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		short bytesRead = receiveData(apdu);
		if (bytesRead <= 0 || bytesRead > Configuration.PIN_MAX_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		byte[] buffer = apdu.getBuffer();
		pin.update(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
		pinInitialized = true;
	}

	private void verifyPin(APDU apdu) {
		ensurePinInitialized();
		short bytesRead = receiveData(apdu);
		if (bytesRead <= 0 || bytesRead > Configuration.PIN_MAX_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		byte[] buffer = apdu.getBuffer();
		if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead)) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}

	private void updatePin(APDU apdu) {
		ensurePinInitialized();
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		short bytesRead = receiveData(apdu);
		if (bytesRead <= 0 || bytesRead > Configuration.PIN_MAX_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		byte[] buffer = apdu.getBuffer();
		pin.update(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void resetPin() {
		pin.reset();
		pinInitialized = false;
	}

	private void sendPinState(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		buffer[0] = (byte) (pinInitialized ? 1 : 0);
		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}

	private void generateKeyPair() {
		keyPair.genKeyPair();
	}

	private void sendPublicKey(APDU apdu) {
		ensurePinInitialized();
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		byte[] buffer = apdu.getBuffer();
		short length = publicKey.getW(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, length);
	}

	private void signHash(APDU apdu) {
		ensurePinInitialized();
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		short bytesRead = receiveData(apdu);
		if (bytesRead != 32) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		byte[] buffer = apdu.getBuffer();
		ecdsaSignature.init(privateKey, Signature.MODE_SIGN);
		short sigLength = ecdsaSignature.signPreComputedHash(
				buffer,
				ISO7816.OFFSET_CDATA,
				bytesRead,
				buffer,
				(short) 0);
		apdu.setOutgoingAndSend((short) 0, sigLength);
	}

	private short receiveData(APDU apdu) {
		short bytesRead = apdu.setIncomingAndReceive();
		if (bytesRead <= 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		return bytesRead;
	}

	private void ensurePinInitialized() {
		if (!pinInitialized) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
	}

	private void setCurveParameters(ECKey key) {
		key.setFieldFP(Secp256k1.P, (short) 0, (short) Secp256k1.P.length);
		key.setA(Secp256k1.A, (short) 0, (short) Secp256k1.A.length);
		key.setB(Secp256k1.B, (short) 0, (short) Secp256k1.B.length);
		key.setG(Secp256k1.G, (short) 0, (short) Secp256k1.G.length);
		key.setR(Secp256k1.N, (short) 0, (short) Secp256k1.N.length);
		key.setK((short) 1);
	}
}
