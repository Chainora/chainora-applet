package tests;

import java.util.Arrays;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import javacard.framework.ISO7816;

import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.chainora.wallet.Configuration;

/**
 * Test class for the Chainora applet.
 * Tests MUST run on physical card - simulator cannot use ECC with secp256k1 curve.
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
@SuppressWarnings("restriction")
public class AppletTest extends BaseTest {
    private static final int APPLET_CLA = 0x80;
    private static final byte BACKUP_PROTOCOL_VERSION = 0x02;
    private static final byte CARD_ATTEST_FORMAT_VERSION = 0x01;
    private static final byte DEVICE_CERT_VERSION = 0x01;
    private static final short DEVICE_CERT_BODY_LENGTH = 83;
    private static final short DEVICE_CERT_PUBLIC_KEY_OFFSET = 17;
    private static final short DEVICE_CERT_SIGNATURE_LENGTH_OFFSET = 83;
    private static final short CARD_ATTEST_BODY_LENGTH = 49;
    private static final short CARD_ATTEST_CHALLENGE_OFFSET = 17;
    private static final short LINK_PROOF_BODY_LENGTH = 102;
    private static final short LINK_PROOF_COUNTER_OFFSET = 3;
    private static final short LINK_PROOF_DEVICE_PUBLIC_OFFSET = 21;
    private static final short ENVELOPE_COUNTER_OFFSET = 3;
    private static final short ENVELOPE_CIPHER_LENGTH_OFFSET = 53;
    private static final short LINK_PROOF_COUNTER = 1;
    private static final short ENVELOPE_COUNTER = 2;

    private static byte[] currentPin = new byte[] { '1', '2', '3', '4' };

    public AppletTest() {
        // Tests always use physical card - simulator cannot use secp256k1 ECC
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

    /**
     * Helper method to set up PIN state for tests.
     * Handles both fresh install (pin not initialized) and reused state (pin initialized).
     * After this method, PIN is reset and ready for fresh init.
     */
    private void setupPinForReset(CardManager cardManager) throws Exception {
        // Check if PIN is initialized
        final CommandAPDU isInitCmd = new CommandAPDU(APPLET_CLA, 0x14, 0x00, 0x00);
        final ResponseAPDU isInitResponse = cardManager.transmit(isInitCmd);
        boolean pinInitialized = isInitResponse.getData()[0] == 1;

        if (pinInitialized) {
            // PIN is initialized, verify it first then reset
            final CommandAPDU verifyCmd = new CommandAPDU(APPLET_CLA, 0x11, 0x00, 0x00, currentPin);
            cardManager.transmit(verifyCmd);
        } else {
            // PIN not initialized, init it
            final CommandAPDU initCmd = new CommandAPDU(APPLET_CLA, 0x10, 0x00, 0x00, currentPin);
            cardManager.transmit(initCmd);
            final CommandAPDU verifyCmd = new CommandAPDU(APPLET_CLA, 0x11, 0x00, 0x00, currentPin);
            cardManager.transmit(verifyCmd);
        }

        // Now RESET_PIN will work (requires validated PIN)
        final CommandAPDU resetCmd = new CommandAPDU(APPLET_CLA, 0x13, 0x00, 0x00);
        final ResponseAPDU resetResponse = cardManager.transmit(resetCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) resetResponse.getSW());
    }

    /**
     * Helper method to initialize and verify PIN for tests.
     * Handles both fresh install and reused state.
     */
    private void setupPinInitialized(CardManager cardManager) throws Exception {
        setupPinForReset(cardManager);

        // Init PIN - reset currentPin to default for initialization
        currentPin = new byte[] { '1', '2', '3', '4' };
        final CommandAPDU initCmd = new CommandAPDU(APPLET_CLA, 0x10, 0x00, 0x00, currentPin);
        final ResponseAPDU initResponse = cardManager.transmit(initCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) initResponse.getSW());

        // Verify PIN
        final CommandAPDU verifyCmd = new CommandAPDU(APPLET_CLA, 0x11, 0x00, 0x00, currentPin);
        final ResponseAPDU verifyResponse = cardManager.transmit(verifyCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) verifyResponse.getSW());
    }

    private byte[] getDeviceCertificate(CardManager cardManager) throws Exception {
        final CommandAPDU getCertCmd = new CommandAPDU(APPLET_CLA, 0x23, 0x00, 0x00);
        final ResponseAPDU certResponse = cardManager.transmit(getCertCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) certResponse.getSW());
        Assert.assertTrue(certResponse.getData().length > 0);
        return certResponse.getData();
    }

    private byte[] getFactoryCsrViaDedicatedIns(CardManager cardManager) throws Exception {
        final CommandAPDU csrCmd = new CommandAPDU(APPLET_CLA, 0x23, 0x10, 0x00);
        final ResponseAPDU csrResponse = cardManager.transmit(csrCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) csrResponse.getSW());
        return csrResponse.getData();
    }

    private byte[] signBackendChallenge(CardManager cardManager, byte[] challenge) throws Exception {
        final CommandAPDU attestCmd = new CommandAPDU(APPLET_CLA, 0x24, 0x00, 0x00, challenge);
        final ResponseAPDU attestResponse = cardManager.transmit(attestCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) attestResponse.getSW());
        return attestResponse.getData();
    }

    private byte[] extractCertificatePublicKey(byte[] certificate) {
        return Arrays.copyOfRange(certificate,
                DEVICE_CERT_PUBLIC_KEY_OFFSET,
                DEVICE_CERT_PUBLIC_KEY_OFFSET + Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);
    }

    private short readShort(byte[] data, int offset) {
        int high = data[offset] & 0xFF;
        int low = data[offset + 1] & 0xFF;
        return (short) ((high << 8) | low);
    }

    @Test
    public void isPinInitialized_PinReset_ReturnsNotInitialized() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state - requires init + verify before reset
        setupPinForReset(cardManager);

        // Check is PIN initialized
        final CommandAPDU isInitCmd = new CommandAPDU(APPLET_CLA, 0x14, 0x00, 0x00);
        final ResponseAPDU isInitResponse = cardManager.transmit(isInitCmd);
        Assert.assertNotNull(isInitResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) isInitResponse.getSW());
        Assert.assertNotNull(isInitResponse.getBytes());
        Assert.assertEquals(0x00, isInitResponse.getData()[0]); // Not initialized
    }

    // Test getPublicKey not verified Pin
    @Test
    public void getPublicKey_PinNotVerified_ReturnsConditionsNotSatisfied() throws Exception {
        final CardManager cardManager = connect();

        // Get Public Key
        final CommandAPDU getPubKeyCmd = new CommandAPDU(APPLET_CLA, 0x21, 0x00, 0x00);
        final ResponseAPDU getPubKeyResponse = cardManager.transmit(getPubKeyCmd);
        Assert.assertNotNull(getPubKeyResponse);
        Assert.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, (short) getPubKeyResponse.getSW());
        Assert.assertNotNull(getPubKeyResponse.getBytes());
    }

    // Test getPublicKey verified Pin
    @Test
    public void getPublicKey_PinVerified_ReturnsPublicKey() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state - requires init + verify before reset
        setupPinInitialized(cardManager);

        // Generate Key Pair
        final CommandAPDU genKeyCmd = new CommandAPDU(APPLET_CLA, 0x20, 0x00, 0x00);
        final ResponseAPDU genKeyResponse = cardManager.transmit(genKeyCmd);
        Assert.assertNotNull(genKeyResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) genKeyResponse.getSW());

        // Get Public Key
        final CommandAPDU getPubKeyCmd = new CommandAPDU(APPLET_CLA, 0x21, 0x00, 0x00);
        final ResponseAPDU getPubKeyResponse = cardManager.transmit(getPubKeyCmd);
        Assert.assertNotNull(getPubKeyResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) getPubKeyResponse.getSW());
        Assert.assertNotNull(getPubKeyResponse.getBytes());
        Assert.assertTrue(getPubKeyResponse.getData().length > 0);

        // Get EVM address from public key
        final byte[] pubKey = getPubKeyResponse.getData();
        final byte[] evmAddress = TestUtils.extractEvmAddressFromPublicKey(pubKey);
        System.out.println("EVM Address: 0x" + TestUtils.bytesToHex(evmAddress));
    }

    // Test sign data verified Pin but wrong data length
    @Test
    public void signData_InvalidHashLength_ReturnsWrongLength() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state - requires init + verify before reset
        setupPinInitialized(cardManager);

        byte[] dataToSign = new byte[] {}; // Wrong length

        // Sign Data
        final CommandAPDU signCmd = new CommandAPDU(APPLET_CLA, 0x22, 0x00, 0x00, dataToSign);
        final ResponseAPDU signResponse = cardManager.transmit(signCmd);
        Assert.assertNotNull(signResponse);
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) signResponse.getSW());
        Assert.assertNotNull(signResponse.getBytes());
    }

    // Test sign data verified Pin
    @Test
    public void signData_PinVerified_ReturnsSignature() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state - requires init + verify before reset
        setupPinInitialized(cardManager);

        // Generate Key Pair
        final CommandAPDU genKeyCmd = new CommandAPDU(APPLET_CLA, 0x20, 0x00, 0x00);
        final ResponseAPDU genKeyResponse = cardManager.transmit(genKeyCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) genKeyResponse.getSW());

        // 32 bytes hash to sign
        byte[] dataToSign = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };

        // Sign Data
        final CommandAPDU signCmd = new CommandAPDU(APPLET_CLA, 0x22, 0x00, 0x00, dataToSign);
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
    public void evmSignFlow_PinVerified_CompletesSuccessfully() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state - requires init + verify before reset
        setupPinInitialized(cardManager);

        // Generate Key Pair
        final CommandAPDU genKeyCmd = new CommandAPDU(APPLET_CLA, 0x20, 0x00, 0x00);
        final ResponseAPDU genKeyResponse = cardManager.transmit(genKeyCmd);
        Assert.assertNotNull(genKeyResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) genKeyResponse.getSW());

        // Get Public Key
        final CommandAPDU getPubKeyCmd = new CommandAPDU(APPLET_CLA, 0x21, 0x00, 0x00);
        final ResponseAPDU getPubKeyResponse = cardManager.transmit(getPubKeyCmd);
        Assert.assertNotNull(getPubKeyResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) getPubKeyResponse.getSW());
        Assert.assertNotNull(getPubKeyResponse.getBytes());
        Assert.assertTrue(getPubKeyResponse.getData().length > 0);

        // Save original public key for later comparison
        final byte[] originalPubKey = getPubKeyResponse.getData();

        // Prepare EVM raw transaction (before hashing and rlp encoding)
        byte[] evmTx = TestUtils.prepareEvmRawTransaction();

        // Hash the transaction (keccak256)
        byte[] evmTxHash = TestUtils.keccak256Hash(evmTx);

        // Sign Data
        final CommandAPDU signCmd = new CommandAPDU(APPLET_CLA, 0x22, 0x00, 0x00, evmTxHash);
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

    // ==================== SECURITY TESTS ====================

    /**
     * Test that the dedicated factory CSR command returns expected format.
     */
    @Test
    public void deviceCertGetFactoryCsr_ReturnsExpectedFormat() throws Exception {
        final CardManager cardManager = connect();

        final byte[] csr = getFactoryCsrViaDedicatedIns(cardManager);
        Assert.assertEquals(82, csr.length);
        Assert.assertEquals(DEVICE_CERT_VERSION, csr[0]);
        Assert.assertEquals(0x04, csr[17]);
    }

    /**
     * Test that the dedicated device certificate is verifiable with the factory root key.
     */
    @Test
    public void deviceCertGetDeviceCertificate_VerifiesFactoryRootSignature() throws Exception {
        final CardManager cardManager = connect();

        final byte[] certificate = getDeviceCertificate(cardManager);
        final short signatureLength = (short) (certificate[DEVICE_CERT_SIGNATURE_LENGTH_OFFSET] & 0xFF);
        final byte[] certificateBody = Arrays.copyOfRange(certificate, 0, DEVICE_CERT_BODY_LENGTH);
        final byte[] signature = Arrays.copyOfRange(
                certificate,
                DEVICE_CERT_SIGNATURE_LENGTH_OFFSET + 1,
                DEVICE_CERT_SIGNATURE_LENGTH_OFFSET + 1 + signatureLength);

        Assert.assertTrue(TestUtils.verifyEcdsaSha256(
                Configuration.CHAINORA_FACTORY_ROOT_PUBLIC_KEY,
                certificateBody,
                signature));
    }

    /**
     * Test that CARD_ATTEST rejects malformed challenge length.
     */
    @Test
    public void cardAttest_InvalidChallengeLength_ReturnsWrongLength() throws Exception {
        final CardManager cardManager = connect();

        final CommandAPDU cmd = new CommandAPDU(APPLET_CLA, 0x24, 0x00, 0x00, new byte[] { 0x01 });
        final ResponseAPDU response = cardManager.transmit(cmd);
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) response.getSW());
    }

    /**
     * Test that CARD_ATTEST returns proof signed by the device auth key from the certificate.
     */
    @Test
    public void cardAttest_ValidChallenge_ReturnsSignedProof() throws Exception {
        final CardManager cardManager = connect();

        final byte[] certificate = getDeviceCertificate(cardManager);
        final byte[] challenge = new byte[Configuration.CARD_CHALLENGE_LENGTH];
        for (int i = 0; i < challenge.length; i++) {
            challenge[i] = (byte) i;
        }

        final byte[] proof = signBackendChallenge(cardManager, challenge);
        Assert.assertTrue(proof.length > CARD_ATTEST_BODY_LENGTH + 1);
        Assert.assertEquals(CARD_ATTEST_FORMAT_VERSION, proof[0]);
        Assert.assertArrayEquals(
                Arrays.copyOfRange(certificate, 1, 1 + Configuration.DEVICE_ID_LENGTH),
                Arrays.copyOfRange(proof, 1, 1 + Configuration.DEVICE_ID_LENGTH));
        Assert.assertArrayEquals(
                challenge,
                Arrays.copyOfRange(proof,
                        CARD_ATTEST_CHALLENGE_OFFSET,
                        CARD_ATTEST_CHALLENGE_OFFSET + Configuration.CARD_CHALLENGE_LENGTH));

        final short signatureLength = (short) (proof[CARD_ATTEST_BODY_LENGTH] & 0xFF);
        final byte[] proofBody = Arrays.copyOfRange(proof, 0, CARD_ATTEST_BODY_LENGTH);
        final byte[] signature = Arrays.copyOfRange(
                proof,
                CARD_ATTEST_BODY_LENGTH + 1,
                CARD_ATTEST_BODY_LENGTH + 1 + signatureLength);

        Assert.assertTrue(TestUtils.verifyEcdsaSha256(
                extractCertificatePublicKey(certificate),
                proofBody,
                signature));
    }

    /**
     * Test that legacy factory CSR access via BACKUP_SESSION is no longer supported.
     */
    @Test
    public void backupGetFactoryCsr_LegacyPath_ReturnsIncorrectP1P2() throws Exception {
        final CardManager cardManager = connect();

        final CommandAPDU csrCmd = new CommandAPDU(APPLET_CLA, 0x30, 0x10, 0x00);
        final ResponseAPDU csrResponse = cardManager.transmit(csrCmd);
        Assert.assertNotNull(csrResponse);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, (short) csrResponse.getSW());
    }

    /**
     * Test that BACKUP_SESSION with unsupported P1 returns SW_INCORRECT_P1P2.
     */
    @Test
    public void backupSession_UnknownP1_ReturnsIncorrectP1P2() throws Exception {
        final CardManager cardManager = connect();

        final CommandAPDU cmd = new CommandAPDU(APPLET_CLA, 0x30, 0x7F, 0x00);
        final ResponseAPDU response = cardManager.transmit(cmd);
        Assert.assertNotNull(response);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, (short) response.getSW());
    }

    /**
     * Test that LOAD_PEER_CERT rejects malformed certificate payload.
     */
    @Test
    public void backupLoadPeerCert_InvalidPayload_ReturnsDataInvalid() throws Exception {
        final CardManager cardManager = connect();

        final byte[] invalidCert = new byte[] { 0x01, 0x02, 0x03 };
        final CommandAPDU cmd = new CommandAPDU(APPLET_CLA, 0x30, 0x02, 0x00, invalidCert);
        final ResponseAPDU response = cardManager.transmit(cmd);
        Assert.assertNotNull(response);
        Assert.assertEquals(ISO7816.SW_DATA_INVALID, (short) response.getSW());
    }

    /**
     * Test that LOAD_PEER_LINK_PROOF requires peer certificate and local link state.
     */
    @Test
    public void backupLoadPeerLinkProof_WithoutPeerCert_ReturnsConditionsNotSatisfied() throws Exception {
        final CardManager cardManager = connect();

        final CommandAPDU clearStateCmd = new CommandAPDU(APPLET_CLA, 0x30, 0x04, 0x00);
        final ResponseAPDU clearStateResponse = cardManager.transmit(clearStateCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) clearStateResponse.getSW());

        final byte[] fakeProof = new byte[] { 0x01 };
        final CommandAPDU cmd = new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, fakeProof);
        final ResponseAPDU response = cardManager.transmit(cmd);
        Assert.assertNotNull(response);
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) response.getSW());
    }

    /**
     * Test START_LINK_PROOF returns v2 format with sessionId/counter.
     */
    @Test
    public void backupStartLinkProof_ReturnsV2Format() throws Exception {
        final CardManager cardManager = connect();
        getDeviceCertificate(cardManager);

        final CommandAPDU startLinkProofCmd = new CommandAPDU(APPLET_CLA, 0x30, 0x01, 0x00);
        final ResponseAPDU startLinkProofResponse = cardManager.transmit(startLinkProofCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) startLinkProofResponse.getSW());

        final byte[] proof = startLinkProofResponse.getData();
        Assert.assertTrue(proof.length > (LINK_PROOF_BODY_LENGTH + 1));
        Assert.assertEquals(BACKUP_PROTOCOL_VERSION, proof[0]);
        Assert.assertEquals(LINK_PROOF_COUNTER, readShort(proof, LINK_PROOF_COUNTER_OFFSET));
        Assert.assertEquals(0x04, proof[LINK_PROOF_DEVICE_PUBLIC_OFFSET]);

        final short sigLen = (short) (proof[LINK_PROOF_BODY_LENGTH] & 0xFF);
        Assert.assertTrue(sigLen > 0);
        Assert.assertEquals(LINK_PROOF_BODY_LENGTH + 1 + sigLen, proof.length);
    }

    /**
     * Test replaying peer link proof in same session is rejected.
     */
    @Test
    public void backupLoadPeerLinkProof_ReplayInSameSession_ReturnsConditionsNotSatisfied() throws Exception {
        final CardManager cardManager = connect();
        getDeviceCertificate(cardManager);

        cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x04, 0x00));

        final byte[] peerCert = getDeviceCertificate(cardManager);
        final ResponseAPDU proofResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x01, 0x00));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) proofResponse.getSW());
        final byte[] proof = proofResponse.getData();

        final ResponseAPDU loadCertResponse = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x02, 0x00, peerCert));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) loadCertResponse.getSW());

        final ResponseAPDU firstLoadProofResponse = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, proof));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) firstLoadProofResponse.getSW());

        final ResponseAPDU replayLoadProofResponse = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, proof));
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) replayLoadProofResponse.getSW());
    }

    /**
     * Test LOAD_PEER_LINK_PROOF DoS threshold: 3 invalid attempts lock command for session.
     */
    @Test
    public void backupLoadPeerLinkProof_InvalidAttempts_ReachesThresholdAndLocks() throws Exception {
        final CardManager cardManager = connect();
        getDeviceCertificate(cardManager);
        cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x04, 0x00));

        final byte[] peerCert = getDeviceCertificate(cardManager);
        final ResponseAPDU startProofResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x01, 0x00));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) startProofResponse.getSW());
        final ResponseAPDU loadCertResponse = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x02, 0x00, peerCert));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) loadCertResponse.getSW());

        final byte[] malformedProof = new byte[] { BACKUP_PROTOCOL_VERSION };
        final ResponseAPDU invalid1 = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, malformedProof));
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) invalid1.getSW());

        final ResponseAPDU invalid2 = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, malformedProof));
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) invalid2.getSW());

        final ResponseAPDU invalid3 = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, malformedProof));
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) invalid3.getSW());

        final ResponseAPDU invalid4 = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, malformedProof));
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) invalid4.getSW());

        final ResponseAPDU clearStateResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x04, 0x00));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) clearStateResponse.getSW());

        final ResponseAPDU restartedProofResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x01, 0x00));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) restartedProofResponse.getSW());
        final ResponseAPDU restartedLoadCertResponse = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x02, 0x00, peerCert));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) restartedLoadCertResponse.getSW());

        final ResponseAPDU invalidAfterReset = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, malformedProof));
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) invalidAfterReset.getSW());
    }

    /**
     * Test BACKUP_IMPORT DoS threshold: 3 invalid attempts lock import in current session.
     */
    @Test
    public void backupImport_InvalidAttempts_ReachesThresholdAndLocks() throws Exception {
        final CardManager cardManager = connect();
        setupPinInitialized(cardManager);
        getDeviceCertificate(cardManager);
        cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x04, 0x00));

        final byte[] peerCert = getDeviceCertificate(cardManager);
        final ResponseAPDU proofResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x01, 0x00));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) proofResponse.getSW());
        final byte[] proof = proofResponse.getData();

        Assert.assertEquals(ISO7816.SW_NO_ERROR,
                (short) cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x02, 0x00, peerCert)).getSW());
        Assert.assertEquals(ISO7816.SW_NO_ERROR,
                (short) cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, proof)).getSW());

        final byte[] malformedEnvelope = new byte[] { BACKUP_PROTOCOL_VERSION };
        final ResponseAPDU invalid1 = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x32, 0x00, 0x00, malformedEnvelope));
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) invalid1.getSW());

        final ResponseAPDU invalid2 = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x32, 0x00, 0x00, malformedEnvelope));
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) invalid2.getSW());

        final ResponseAPDU invalid3 = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x32, 0x00, 0x00, malformedEnvelope));
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) invalid3.getSW());

        final ResponseAPDU invalid4 = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x32, 0x00, 0x00, malformedEnvelope));
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) invalid4.getSW());

        Assert.assertEquals(ISO7816.SW_NO_ERROR,
                (short) cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x04, 0x00)).getSW());
        final ResponseAPDU newProofResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x01, 0x00));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) newProofResponse.getSW());
        final byte[] newProof = newProofResponse.getData();
        Assert.assertEquals(ISO7816.SW_NO_ERROR,
                (short) cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x02, 0x00, peerCert)).getSW());
        Assert.assertEquals(ISO7816.SW_NO_ERROR,
                (short) cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, newProof)).getSW());

        final ResponseAPDU invalidAfterReset = cardManager
                .transmit(new CommandAPDU(APPLET_CLA, 0x32, 0x00, 0x00, malformedEnvelope));
        Assert.assertEquals(ISO7816.SW_WRONG_LENGTH, (short) invalidAfterReset.getSW());
    }

    /**
     * Test BACKUP_EXPORT emits v2 envelope and clears link state after success.
     */
    @Test
    public void backupExport_UsesV2EnvelopeAndClearsState() throws Exception {
        final CardManager cardManager = connect();
        setupPinInitialized(cardManager);
        getDeviceCertificate(cardManager);
        cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x04, 0x00));

        final CommandAPDU genKeyCmd = new CommandAPDU(APPLET_CLA, 0x20, 0x00, 0x00);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) cardManager.transmit(genKeyCmd).getSW());

        final byte[] peerCert = getDeviceCertificate(cardManager);
        final ResponseAPDU proofResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x01, 0x00));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) proofResponse.getSW());
        final byte[] proof = proofResponse.getData();

        Assert.assertEquals(ISO7816.SW_NO_ERROR,
                (short) cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x02, 0x00, peerCert)).getSW());
        Assert.assertEquals(ISO7816.SW_NO_ERROR,
                (short) cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x30, 0x03, 0x00, proof)).getSW());

        final ResponseAPDU exportResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x31, 0x00, 0x00));
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) exportResponse.getSW());
        final byte[] envelope = exportResponse.getData();
        Assert.assertTrue(envelope.length > ENVELOPE_CIPHER_LENGTH_OFFSET + 2);
        Assert.assertEquals(BACKUP_PROTOCOL_VERSION, envelope[0]);
        Assert.assertEquals(ENVELOPE_COUNTER, readShort(envelope, ENVELOPE_COUNTER_OFFSET));

        final short cipherLen = (short) (envelope[ENVELOPE_CIPHER_LENGTH_OFFSET] & 0xFF);
        final int signatureLengthOffset = ENVELOPE_CIPHER_LENGTH_OFFSET + 1 + cipherLen;
        final short signatureLength = (short) (envelope[signatureLengthOffset] & 0xFF);
        Assert.assertEquals(signatureLengthOffset + 1 + signatureLength, envelope.length);

        final ResponseAPDU replayExportResponse = cardManager.transmit(new CommandAPDU(APPLET_CLA, 0x31, 0x00, 0x00));
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) replayExportResponse.getSW());
    }

    /**
     * Test that RESET_PIN without PIN validation fails with SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    @Test
    public void resetPin_WithoutPinValidation_ReturnsSecurityStatusNotSatisfied() throws Exception {
        final CardManager cardManager = connect();

        // Reset PIN without initializing/verifying PIN first
        final CommandAPDU resetCmd = new CommandAPDU(APPLET_CLA, 0x13, 0x00, 0x00);
        final ResponseAPDU resetResponse = cardManager.transmit(resetCmd);
        Assert.assertNotNull(resetResponse);
        Assert.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, (short) resetResponse.getSW());
    }

    /**
     * Test that UPDATE_PIN without current PIN fails with SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    @Test
    public void updatePin_WithoutCurrentPin_ReturnsSecurityStatusNotSatisfied() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state
        setupPinInitialized(cardManager);

        // Try UPDATE_PIN with wrong length prefix - should fail security check
        // First byte is treated as currentPIN length, causing wrong PIN to be read
        // Format: [currentPINLen:1][currentPIN][newPIN]
        final byte[] newPin = new byte[] { '5', '6', '7', '8' };
        byte[] updateData = new byte[1 + newPin.length];
        updateData[0] = (byte) 4; // length of current PIN that will be read (wrong)
        System.arraycopy(newPin, 0, updateData, 1, newPin.length);

        final CommandAPDU updateCmd = new CommandAPDU(APPLET_CLA, 0x12, 0x00, 0x00, updateData);
        final ResponseAPDU updateResponse = cardManager.transmit(updateCmd);
        Assert.assertNotNull(updateResponse);
        Assert.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, (short) updateResponse.getSW());
    }

    /**
     * Test that UPDATE_PIN with wrong current PIN fails with SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    @Test
    public void updatePin_WithWrongCurrentPin_ReturnsSecurityStatusNotSatisfied() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state - uses currentPin class variable
        setupPinInitialized(cardManager);

        // UPDATE_PIN with wrong current PIN
        // Format: [currentPINLen:1][currentPIN][newPIN]
        byte[] wrongCurrentPin = new byte[] { '9', '9', '9', '9' };
        byte[] newPin = new byte[] { '5', '6', '7', '8' };
        byte[] updateData = new byte[1 + wrongCurrentPin.length + newPin.length];
        updateData[0] = (byte) wrongCurrentPin.length;
        System.arraycopy(wrongCurrentPin, 0, updateData, 1, wrongCurrentPin.length);
        System.arraycopy(newPin, 0, updateData, 1 + wrongCurrentPin.length, newPin.length);

        final CommandAPDU updateCmd = new CommandAPDU(APPLET_CLA, 0x12, 0x00, 0x00, updateData);
        final ResponseAPDU updateResponse = cardManager.transmit(updateCmd);
        Assert.assertNotNull(updateResponse);
        Assert.assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, (short) updateResponse.getSW());
    }

    /**
     * Test that UPDATE_PIN with correct current PIN succeeds.
     */
    @Test
    public void updatePin_WithCorrectCurrentPin_Succeeds() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state - uses currentPin class variable
        setupPinInitialized(cardManager);

        // UPDATE_PIN with correct current PIN
        // Format: [currentPINLen:1][currentPIN][newPIN]
        byte[] newPin = new byte[] { '5', '6', '7', '8' };
        byte[] updateData = new byte[1 + currentPin.length + newPin.length];
        updateData[0] = (byte) currentPin.length;
        System.arraycopy(currentPin, 0, updateData, 1, currentPin.length);
        System.arraycopy(newPin, 0, updateData, 1 + currentPin.length, newPin.length);

        final CommandAPDU updateCmd = new CommandAPDU(APPLET_CLA, 0x12, 0x00, 0x00, updateData);
        final ResponseAPDU updateResponse = cardManager.transmit(updateCmd);
        Assert.assertNotNull(updateResponse);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) updateResponse.getSW());

        // Update currentPin to new PIN for subsequent tests
        currentPin = newPin;

        // Verify new PIN works
        final CommandAPDU verifyNewCmd = new CommandAPDU(APPLET_CLA, 0x11, 0x00, 0x00, newPin);
        final ResponseAPDU verifyNewResponse = cardManager.transmit(verifyNewCmd);
        Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) verifyNewResponse.getSW());
    }

    /**
     * Test that generated signatures are Low-S normalized (s <= n/2).
     */
    @Test
    public void signHash_SignatureIsLowSNormalized() throws Exception {
        final CardManager cardManager = connect();

        // Setup PIN state - uses currentPin class variable
        setupPinInitialized(cardManager);

        // Generate key pair
        final CommandAPDU genKeyCmd = new CommandAPDU(APPLET_CLA, 0x20, 0x00, 0x00);
        cardManager.transmit(genKeyCmd);

        // n/2 value for secp256k1 (half of the curve order)
        byte[] nDiv2 = new byte[] {
            (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x5D, (byte) 0x57, (byte) 0x6E, (byte) 0x73,
            (byte) 0x5A, (byte) 0x44, (byte) 0x8A, (byte) 0x4C,
            (byte) 0x5F, (byte) 0x9C, (byte) 0x8D, (byte) 0xAB,
            (byte) 0x5E, (byte) 0xB0, (byte) 0x18, (byte) 0x41
        };

        // Sign hash multiple times and verify Low-S property
        for (int i = 0; i < 10; i++) {
            byte[] hash = new byte[32];
            hash[0] = (byte) i; // Different hash each iteration
            hash[31] = (byte) i;

            final CommandAPDU signCmd = new CommandAPDU(APPLET_CLA, 0x22, 0x00, 0x00, hash);
            final ResponseAPDU signResponse = cardManager.transmit(signCmd);
            Assert.assertEquals(ISO7816.SW_NO_ERROR, (short) signResponse.getSW());

            // Decode signature and verify S is Low-S normalized
            final byte[][] rsComponents = TestUtils.decodeDerSignature(signResponse.getData(), 32);
            final byte[] sComponent = rsComponents[1];

            // Verify S <= n/2 (Low-S normalized)
            Assert.assertTrue("Signature S should be Low-S normalized (s <= n/2)",
                compareBigInt(sComponent, nDiv2) <= 0);
        }
    }

    /**
     * Compares two big-endian byte arrays as unsigned integers.
     * @return negative if a < b, positive if a > b, zero if equal
     */
    private int compareBigInt(byte[] a, byte[] b) {
        for (int i = 0; i < a.length && i < b.length; i++) {
            int av = a[i] & 0xFF;
            int bv = b[i] & 0xFF;
            if (av != bv) {
                return av - bv;
            }
        }
        return a.length - b.length;
    }
}
