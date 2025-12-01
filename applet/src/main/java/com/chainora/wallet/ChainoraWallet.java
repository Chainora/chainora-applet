package com.chainora.wallet;

import com.chainora.shareable.IChainoraSecure;
import com.chainora.shareable.Utils;

import javacard.framework.*;

public class ChainoraWallet extends Applet {
	// === Storage AID ===
	private AID storageAID;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ChainoraWallet();
	}

	public ChainoraWallet() {
		byte[] storageBytes = new byte[] {
				(byte) 0xF0, 0x56, 0x4E, 0x43, 0x48, 0x58, 0x01
		};
		storageAID = new AID(storageBytes, (short) 0, (byte) storageBytes.length);
		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet())
			return;

		IChainoraSecure secure = null;
		try {
			secure = Utils.getChainoraSecure(storageAID);
		} catch (ISOException e) {
			ISOException.throwIt(e.getReason());
		}

		byte[] buffer = apdu.getBuffer();
		switch (buffer[ISO7816.OFFSET_INS]) {
			case 0x10: // INIT_PIN:
				initPin(secure, apdu);
				break;
			case 0x11: // VERIFY_PIN:
				verifyPin(secure, apdu);
				break;
			case 0x12: // UPDATE_PIN:
				updatePin(secure, apdu);
				break;
			case 0x13: // RESET_PIN:
				resetPin(secure, apdu);
				break;
			case 0x14: // IS_PIN_INITIALIZED:
				isPinInitialized(secure, apdu);
				break;
			case 0x20: // GEN_KEY_PAIR:
				genKeyPair(secure, apdu);
				break;
			case 0x21: // GET_PUBLIC_KEY:
				getPublicKey(secure, apdu);
				break;
			case 0x22: // SIGN_HASH:
				signHash(secure, apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				break;
		}
	}

	// === PIN Management Commands ===
	private void initPin(IChainoraSecure secure, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		secure.initPin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void verifyPin(IChainoraSecure secure, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		secure.verifyPin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void updatePin(IChainoraSecure secure, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		secure.updatePin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void resetPin(IChainoraSecure secure, APDU apdu) {
		secure.resetPin();
	}

	private void isPinInitialized(IChainoraSecure secure, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		buffer[0] = (byte) (secure.isPinInitialize() ? 1 : 0);
		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}

	private void genKeyPair(IChainoraSecure storage, APDU apdu) {
		storage.generateKeyPair();
	}

	private void getPublicKey(IChainoraSecure storage, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = storage.getPublicKey(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, length);
	}

	private void signHash(IChainoraSecure storage, APDU apdu) {
	}
}
