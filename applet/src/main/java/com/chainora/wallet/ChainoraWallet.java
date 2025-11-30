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

		IChainoraSecure storage = null;
		try {
			storage = Utils.getChainoraStorage(storageAID);
		} catch (ISOException e) {
			ISOException.throwIt(e.getReason());
		}

		byte[] buffer = apdu.getBuffer();
		switch (buffer[ISO7816.OFFSET_INS]) {
			case 0x10: // INIT_PIN:
				initPin(storage, apdu);
				break;
			case 0x11: // VERIFY_PIN:
				verifyPin(storage, apdu);
				break;
			case 0x12: // UPDATE_PIN:
				updatePin(storage, apdu);
				break;
			case 0x13: // RESET_PIN:
				resetPin(storage, apdu);
				break;
			case 0x20: // GEN_KEY_PAIR:
				genKeyPair(storage, apdu);
				break;
			case 0x21: // GET_PUBLIC_KEY:
				break;
			case 0x22: // SIGN_HASH:
				signHash(storage, apdu);
				break;
			case 0x30: // GET_VERY_SECRET_KEY:
				getVerySecretKey(storage, apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				break;
		}
	}

	private void initPin(IChainoraSecure storage, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		storage.initPin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void verifyPin(IChainoraSecure storage, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		storage.verifyPin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void updatePin(IChainoraSecure storage, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		storage.updatePin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void resetPin(IChainoraSecure storage, APDU apdu) {
		storage.resetPin();
	}

	private void getVerySecretKey(IChainoraSecure storage, APDU apdu) {
		byte[] secretKey = storage.getVerySecretKey();
		byte[] buffer = apdu.getBuffer();
		short lc = (short) secretKey.length;
		Util.arrayCopyNonAtomic(secretKey, (short) 0, buffer, (short) 0, lc);
		apdu.setOutgoingAndSend((short) 0, lc);
	}

	private void genKeyPair(IChainoraSecure storage, APDU apdu) {
	}

	private void signHash(IChainoraSecure storage, APDU apdu) {
	}
}
