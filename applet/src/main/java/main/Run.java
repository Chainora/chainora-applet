package main;

import com.chainora.wallet.ChainoraWallet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.*;

public class Run {
    public static void main(String[] args) {
        // 1. create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, ChainoraWallet.class);

        // 3. select applet
        simulator.selectApplet(appletAID);

        // 4. send APDU
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x41, 0x00, 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        byte[] responseData = response.getData();
        if (responseData.length > 0) {
            System.out.println(new String(responseData));
        } else {
            System.out.println("No data received from applet.");
        }
    }

}