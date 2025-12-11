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

    // Test sign data verified Pin but wrong data length
    @Test
    public void signData_verified_wrongLength() throws Exception {
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

        byte[] dataToSign = new byte[] {}; // Wrong length

        // Sign Data
        final CommandAPDU signCmd = new CommandAPDU(0x00, 0x22, 0x00, 0x00, dataToSign);
        final ResponseAPDU signResponse = cardManager.transmit(signCmd);
        Assert.assertNotNull(signResponse);
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) signResponse.getSW());
        Assert.assertNotNull(signResponse.getBytes());
    }

    // Test sign data verified Pin
    @Test
    public void signData_verified() throws Exception {
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

        // 32 bytes hash to sign
        byte[] dataToSign = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };

        // Sign Data
        final CommandAPDU signCmd = new CommandAPDU(0x00, 0x22, 0x00, 0x00, dataToSign);
        final ResponseAPDU signResponse = cardManager.transmit(signCmd);
        Assert.assertNotNull(signResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) signResponse.getSW());
        Assert.assertNotNull(signResponse.getBytes());
        Assert.assertTrue(signResponse.getData().length > 0);

        // signResponse.getData() contains the signature DER encoded
        // parse to s | r values
        final byte[][] rsComponents = TestUtils.decodeDerSignature(signResponse.getData(), 32);
        final byte[] rComponent = rsComponents[0];
        final byte[] sComponent = rsComponents[1];

        Assert.assertEquals(32, rComponent.length);
        Assert.assertEquals(32, sComponent.length);
        Assert.assertFalse(TestUtils.isAllZero(rComponent));
        Assert.assertFalse(TestUtils.isAllZero(sComponent));

        System.out.println("Signature R: " + TestUtils.bytesToHex(rComponent));
        System.out.println("Signature S: " + TestUtils.bytesToHex(sComponent));
    }

    // Test EVM-base signing flow
    @Test
    public void evmSignFlow_verified() throws Exception {
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
        final byte[] originalPubKey = getPubKeyResponse.getData();

        // Prepare EVM raw transaction (before hashing and rlp encoding)
        byte[] evmTx = TestUtils.prepareEvmRawTransaction();

        // Hash the transaction (keccak256)
        byte[] evmTxHash = TestUtils.keccak256Hash(evmTx);

        // Sign Data
        final CommandAPDU signCmd = new CommandAPDU(0x00, 0x22, 0x00, 0x00, evmTxHash);
        final ResponseAPDU signResponse = cardManager.transmit(signCmd);
        Assert.assertNotNull(signResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) signResponse.getSW());
        Assert.assertNotNull(signResponse.getBytes());
        Assert.assertTrue(signResponse.getData().length > 0);

        // signResponse.getData() contains the signature DER encoded
        // parse to s | r values
        final byte[][] rsComponents = TestUtils.decodeDerSignature(signResponse.getData(), 32);
        final byte[] rComponent = rsComponents[0];
        final byte[] sComponent = rsComponents[1];
        Assert.assertEquals(32, rComponent.length);
        Assert.assertEquals(32, sComponent.length);
        Assert.assertFalse(TestUtils.isAllZero(rComponent));
        Assert.assertFalse(TestUtils.isAllZero(sComponent));

        System.out.println("Signature R: " + TestUtils.bytesToHex(rComponent));
        System.out.println("Signature S: " + TestUtils.bytesToHex(sComponent));

        // Construct final signed EVM transaction (RLP encoding with v, r, s)
        final int recoveryId = TestUtils.determineRecoveryId(evmTxHash, rComponent, sComponent, originalPubKey);
        byte[] signedEvmTx = TestUtils.constructSignedEvmTransaction(evmTx, rComponent, sComponent, recoveryId);
        System.out.println("Signed EVM TX: 0x" + TestUtils.bytesToHex(signedEvmTx));

        // Verify signed transaction (recover the public key)
        byte[] recoveredPubKey = TestUtils.recoverEvmPublicKeyFromSignedTransaction(signedEvmTx, evmTxHash);
        System.out.println("Recovered PubKey: " + TestUtils.bytesToHex(recoveredPubKey));

        // Compare recovered public key with original
        // Note: getPubKeyResponse returns uncompressed key (0x04 | X | Y)
        Assert.assertArrayEquals(originalPubKey, recoveredPubKey);

    }
}
