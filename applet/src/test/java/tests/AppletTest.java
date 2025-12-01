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

    @Test
    public void isPinInitialized_test() throws Exception {
        final CardManager cardManager = connect();

        // Reset PIN
        final CommandAPDU resetCmd = new CommandAPDU(0x00, 0x13, 0x00, 0x00);
        final ResponseAPDU resetResponse = cardManager.transmit(resetCmd);
        Assert.assertNotNull(resetResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) resetResponse.getSW());

        // Check is PIN initialized
        final CommandAPDU isInitCmd = new CommandAPDU(0x00, 0x14, 0x00, 0x00);
        final ResponseAPDU isInitResponse = cardManager.transmit(isInitCmd);
        Assert.assertNotNull(isInitResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) isInitResponse.getSW());
        Assert.assertNotNull(isInitResponse.getBytes());
        Assert.assertEquals(0x00, isInitResponse.getData()[0]); // Not initialized
    }

    // Test getPublicKey not verified Pin
    @Test
    public void getPublicKey_notVerified() throws Exception {
        final CardManager cardManager = connect();

        // Get Public Key
        final CommandAPDU getPubKeyCmd = new CommandAPDU(0x00, 0x21, 0x00, 0x00);
        final ResponseAPDU getPubKeyResponse = cardManager.transmit(getPubKeyCmd);
        Assert.assertNotNull(getPubKeyResponse);
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) getPubKeyResponse.getSW());
        Assert.assertNotNull(getPubKeyResponse.getBytes());
    }

    // Test getPublicKey verified Pin
    @Test
    public void getPublicKey_verified() throws Exception {
        final CardManager cardManager = connect();

        // Reset PIN
        final CommandAPDU resetCmd = new CommandAPDU(0x00, 0x13, 0x00, 0x00);
        final ResponseAPDU resetResponse = cardManager.transmit(resetCmd);
        Assert.assertNotNull(resetResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) resetResponse.getSW());

        // Init PIN
        final CommandAPDU initCmd = new CommandAPDU(0x00, 0x10, 0x00, 0x00, new byte[] { '1', '2', '3', '4' });
        final ResponseAPDU initResponse = cardManager.transmit(initCmd);
        Assert.assertNotNull(initResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) initResponse.getSW());

        // Verify PIN
        final CommandAPDU verifyCmd = new CommandAPDU(0x00, 0x11, 0x00, 0x00, new byte[] { '1', '2', '3', '4' });
        final ResponseAPDU verifyResponse = cardManager.transmit(verifyCmd);
        Assert.assertNotNull(verifyResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) verifyResponse.getSW());

        // Generate Key Pair
        final CommandAPDU genKeyCmd = new CommandAPDU(0x00, 0x20, 0x00, 0x00);
        final ResponseAPDU genKeyResponse = cardManager.transmit(genKeyCmd);
        Assert.assertNotNull(genKeyResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) genKeyResponse.getSW());

        // Get Public Key
        final CommandAPDU getPubKeyCmd = new CommandAPDU(0x00, 0x21, 0x00, 0x00);
        final ResponseAPDU getPubKeyResponse = cardManager.transmit(getPubKeyCmd);
        Assert.assertNotNull(getPubKeyResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) getPubKeyResponse.getSW());
        Assert.assertNotNull(getPubKeyResponse.getBytes());
        Assert.assertTrue(getPubKeyResponse.getData().length > 0);
    }
}
