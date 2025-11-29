package applet;

import javacard.framework.*;

// Applet that responds to to APDU
public class ChainoraWallet extends Applet {

	private static final byte[] helloWorld = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!' };

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ChainoraWallet();
	}

	public ChainoraWallet() {
		register();
	}

	public void process(APDU apdu) {
		sendHelloWorld(apdu);
	}

	private void sendHelloWorld(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = (short) helloWorld.length;
		Util.arrayCopyNonAtomic(helloWorld, (short) 0, buffer, (short) 0, length);
		apdu.setOutgoingAndSend((short) 0, length);
	}
}
