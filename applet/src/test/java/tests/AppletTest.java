package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import javacard.framework.ISO7816;

import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest extends BaseTest {

    public AppletTest() {
        // Change card type here if you want to use physical card
        setCardType(CardType.PHYSICAL);
    }

    @BeforeAll
    public static void setUpClass() throws Exception {
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
    }

    // Example test
    @Test
    public void getVerySecretKey_notVerifiedYet() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(0x00, 0x30, 0x00, 0x00);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, (short) responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
    }

    @Test
    public void getVerySecretKey_Verified() throws Exception {
        // Kết nối một lần và tái sử dụng
        final CardManager cardChannel = connect();

        // Reset PIN
        final CommandAPDU resetCmd = new CommandAPDU(0x00, 0x13, 0x00, 0x00);
        final ResponseAPDU resetResponse = cardChannel.transmit(resetCmd);
        Assert.assertNotNull(resetResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) resetResponse.getSW());

        // Init PIN
        final CommandAPDU cmd = new CommandAPDU(0x00, 0x10, 0x00, 0x00, new byte[] { '1', '2', '3', '4' });
        final ResponseAPDU responseAPDU = cardChannel.transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());

        // Verify PIN
        final CommandAPDU cmd2 = new CommandAPDU(0x00, 0x11, 0x00, 0x00, new byte[] { '1', '2', '3', '4' });
        final ResponseAPDU responseAPDU2 = cardChannel.transmit(cmd2);
        Assert.assertNotNull(responseAPDU2);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) responseAPDU2.getSW());
        Assert.assertNotNull(responseAPDU2.getBytes());

        // Get Very Secret Key
        final CommandAPDU cmd3 = new CommandAPDU(0x00, 0x30, 0x00, 0x00);
        final ResponseAPDU responseAPDU3 = cardChannel.transmit(cmd3);
        Assert.assertNotNull(responseAPDU3);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) responseAPDU3.getSW());
        Assert.assertNotNull(responseAPDU3.getBytes());
    }
}
