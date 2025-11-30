package com.chainora.applet;

import javacard.framework.*;

public class ChainoraWalletApplet extends Applet {
	private static final byte INS_INIT_PIN = (byte) 0x10;
	private static final byte INS_UPDATE_PIN = (byte) 0x20;
	private static final byte INS_GEN_KEYPAIR = (byte) 0x30;
	private static final byte INS_GET_PUBLIC_KEY = (byte) 0x40;
	private static final byte INS_SIGN_HASH = (byte) 0x50;

	private AID walletAID;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ChainoraWalletApplet();
	}

	public ChainoraWalletApplet() {
		walletAID = new AID(Configuration.WALLET_AID_BYTES, (short) 0, (byte) Configuration.WALLET_AID_BYTES.length);
		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet())
			return;

		IChainoraStorage storage = Utils.getChainoraStorage(walletAID);

		byte[] buffer = apdu.getBuffer();
		switch (buffer[ISO7816.OFFSET_INS]) {
			case INS_INIT_PIN:
				initPin(storage, apdu);
				break;
			case INS_UPDATE_PIN:
				verifyPin(storage, apdu);
				updatePin(storage, apdu);
				break;
			case INS_GEN_KEYPAIR:
				verifyPin(storage, apdu);
				genKeyPair(storage, apdu);
				break;
			case INS_GET_PUBLIC_KEY:
				break;
			case INS_SIGN_HASH:
				verifyPin(storage, apdu);
				signHash(storage, apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				break;
		}
	}

	private void initPin(IChainoraStorage storage, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		storage.initPin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void verifyPin(IChainoraStorage storage, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		storage.verifyPin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void updatePin(IChainoraStorage storage, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		storage.updatePin(buffer, ISO7816.OFFSET_CDATA, (byte) bytesRead);
	}

	private void genKeyPair(IChainoraStorage storage, APDU apdu) {
	}

	private void signHash(IChainoraStorage storage, APDU apdu) {
	}
}
