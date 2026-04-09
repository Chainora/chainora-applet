package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Handles backup provisioning and ECDH-based key backup commands.
 */
public class BackupCommandHandler implements CommandHandler {
    private static final short SW_INS_NOT_SUPPORTED = ISO7816.SW_INS_NOT_SUPPORTED;
    private static final short SW_WRONG_P1P2 = ISO7816.SW_INCORRECT_P1P2;
    private static final short SW_WRONG_LENGTH = ISO7816.SW_WRONG_LENGTH;
    private static final short SW_SECURITY = ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
    private static final short SW_CONDITIONS = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
    private static final short SW_DATA_INVALID = ISO7816.SW_DATA_INVALID;
    private static final short SW_RECORD_NOT_FOUND = ISO7816.SW_RECORD_NOT_FOUND;

    private static final short OFFSET_CERT_VERSION = 0;
    private static final short OFFSET_CERT_DEVICE_ID = 1;
    private static final short OFFSET_CERT_DEVICE_PUBLIC = (short) (OFFSET_CERT_DEVICE_ID + Configuration.DEVICE_ID_LENGTH);
    private static final short OFFSET_CERT_CAPABILITIES =
            (short) (OFFSET_CERT_DEVICE_PUBLIC + Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);
    private static final short OFFSET_CERT_SIGNATURE_LENGTH =
            (short) (OFFSET_CERT_CAPABILITIES + 1);

    private static final short OFFSET_LINK_VERSION = 0;
    private static final short OFFSET_LINK_SESSION_ID = (short) (OFFSET_LINK_VERSION + 1);
    private static final short OFFSET_LINK_COUNTER =
            (short) (OFFSET_LINK_SESSION_ID + Configuration.SESSION_ID_LENGTH);
    private static final short OFFSET_LINK_DEVICE_ID =
            (short) (OFFSET_LINK_COUNTER + Configuration.COUNTER_LENGTH);
    private static final short OFFSET_LINK_PUBLIC =
            (short) (OFFSET_LINK_DEVICE_ID + Configuration.DEVICE_ID_LENGTH);
    private static final short OFFSET_LINK_NONCE =
            (short) (OFFSET_LINK_PUBLIC + Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);

    private static final short OFFSET_ENVELOPE_VERSION = 0;
    private static final short OFFSET_ENVELOPE_SESSION_ID = (short) (OFFSET_ENVELOPE_VERSION + 1);
    private static final short OFFSET_ENVELOPE_COUNTER =
            (short) (OFFSET_ENVELOPE_SESSION_ID + Configuration.SESSION_ID_LENGTH);
    private static final short OFFSET_ENVELOPE_SOURCE_DEVICE_ID =
            (short) (OFFSET_ENVELOPE_COUNTER + Configuration.COUNTER_LENGTH);
    private static final short OFFSET_ENVELOPE_DEST_DEVICE_ID =
            (short) (OFFSET_ENVELOPE_SOURCE_DEVICE_ID + Configuration.DEVICE_ID_LENGTH);
    private static final short OFFSET_ENVELOPE_IV =
            (short) (OFFSET_ENVELOPE_DEST_DEVICE_ID + Configuration.DEVICE_ID_LENGTH);
    private static final short OFFSET_ENVELOPE_CIPHER_LENGTH = (short) (OFFSET_ENVELOPE_IV + Configuration.NONCE_LENGTH);
    private static final short OFFSET_ENVELOPE_CIPHER = (short) (OFFSET_ENVELOPE_CIPHER_LENGTH + 1);

    private final PinValidator pinValidator;
    private final ECPrivateKey walletPrivateKey;
    private final ECPublicKey walletPublicKey;

    private final ECPrivateKey deviceAuthPrivateKey;
    private final ECPublicKey deviceAuthPublicKey;
    private final ECPublicKey chainoraFactoryRootPublicKey;

    private final KeyPair sessionLinkKeyPair;
    private final ECPrivateKey sessionLinkPrivateKey;
    private final ECPublicKey sessionLinkPublicKey;
    private final ECPublicKey peerDeviceAuthPublicKey;
    private final ECPublicKey peerSessionLinkPublicKey;

    private final Signature deviceSignature;
    private final Signature verifySignature;
    private final KeyAgreement keyAgreement;
    private final MessageDigest sha256Digest;
    private final AESKey aesKey;
    private final Cipher aesCipher;
    private final RandomData randomData;

    private final byte[] deviceId;
    private final byte[] deviceAuthCertificate;
    private short deviceAuthCertificateLength;

    private final byte[] localSessionId;
    private final byte[] localNonce;
    private final byte[] peerDeviceId;
    private final byte[] peerSessionId;
    private final byte[] peerNonce;

    private boolean localLinkProofGenerated;
    private boolean peerCertificateLoaded;
    private boolean peerLinkProofLoaded;
    private short sessionCounter;
    private short peerProofCounter;
    private byte loadPeerLinkProofFailureCount;
    private byte backupImportFailureCount;
    private boolean loadPeerLinkProofLocked;
    private boolean backupImportLocked;

    private final byte[] sharedSecret;
    private final byte[] derivedSessionKey;
    private final byte[] payloadBuffer;
    private final byte[] keyScratch;

    public BackupCommandHandler(
            PinValidator pinValidator,
            ECPrivateKey walletPrivateKey,
            ECPublicKey walletPublicKey,
            KeyPair deviceAuthKeyPair,
            ECPublicKey chainoraFactoryRootPublicKey,
            KeyPair sessionLinkKeyPair,
            ECPublicKey peerDeviceAuthPublicKey,
            ECPublicKey peerSessionLinkPublicKey,
            Signature deviceSignature,
            Signature verifySignature,
            KeyAgreement keyAgreement,
            MessageDigest sha256Digest,
            AESKey aesKey,
            Cipher aesCipher,
            RandomData randomData) {
        this.pinValidator = pinValidator;
        this.walletPrivateKey = walletPrivateKey;
        this.walletPublicKey = walletPublicKey;

        this.deviceAuthPrivateKey = (ECPrivateKey) deviceAuthKeyPair.getPrivate();
        this.deviceAuthPublicKey = (ECPublicKey) deviceAuthKeyPair.getPublic();
        this.chainoraFactoryRootPublicKey = chainoraFactoryRootPublicKey;

        this.sessionLinkKeyPair = sessionLinkKeyPair;
        this.sessionLinkPrivateKey = (ECPrivateKey) sessionLinkKeyPair.getPrivate();
        this.sessionLinkPublicKey = (ECPublicKey) sessionLinkKeyPair.getPublic();
        this.peerDeviceAuthPublicKey = peerDeviceAuthPublicKey;
        this.peerSessionLinkPublicKey = peerSessionLinkPublicKey;

        this.deviceSignature = deviceSignature;
        this.verifySignature = verifySignature;
        this.keyAgreement = keyAgreement;
        this.sha256Digest = sha256Digest;
        this.aesKey = aesKey;
        this.aesCipher = aesCipher;
        this.randomData = randomData;

        this.deviceId = new byte[Configuration.DEVICE_ID_LENGTH];
        this.deviceAuthCertificate = new byte[Configuration.MAX_DEVICE_CERT_LENGTH];
        this.deviceAuthCertificateLength = 0;

        this.localSessionId = new byte[Configuration.SESSION_ID_LENGTH];
        this.localNonce = new byte[Configuration.NONCE_LENGTH];
        this.peerDeviceId = new byte[Configuration.DEVICE_ID_LENGTH];
        this.peerSessionId = new byte[Configuration.SESSION_ID_LENGTH];
        this.peerNonce = new byte[Configuration.NONCE_LENGTH];

        this.sessionCounter = 1;

        this.sharedSecret = JCSystem.makeTransientByteArray(
                Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH,
                JCSystem.CLEAR_ON_DESELECT);
        this.derivedSessionKey = JCSystem.makeTransientByteArray((short) MessageDigest.LENGTH_SHA_256, JCSystem.CLEAR_ON_DESELECT);
        this.payloadBuffer = JCSystem.makeTransientByteArray(Configuration.MAX_BACKUP_CIPHERTEXT_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        this.keyScratch = JCSystem.makeTransientByteArray(Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH, JCSystem.CLEAR_ON_DESELECT);

        randomData.generateData(deviceId, (short) 0, Configuration.DEVICE_ID_LENGTH);
        deviceAuthKeyPair.genKeyPair();
        clearLinkStateInternal();
    }

    @Override
    public short process(APDU apdu, byte ins) {
        switch (ins) {
            case Configuration.INS_BACKUP_SESSION:
                processSessionCommand(apdu);
                break;
            case Configuration.INS_BACKUP_EXPORT:
                exportBackupEnvelope(apdu);
                break;
            case Configuration.INS_BACKUP_IMPORT:
                importBackupEnvelope(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        return ISO7816.SW_NO_ERROR;
    }

    private void processSessionCommand(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if (p2 != 0x00) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }

        switch (p1) {
            case Configuration.P1_GET_DEVICE_CERT:
                sendDeviceCertificate(apdu);
                break;
            case Configuration.P1_START_LINK_PROOF:
                startLinkProof(apdu);
                break;
            case Configuration.P1_LOAD_PEER_CERT:
                loadPeerCertificate(apdu);
                break;
            case Configuration.P1_LOAD_PEER_LINK_PROOF:
                loadPeerLinkProof(apdu);
                break;
            case Configuration.P1_CLEAR_LINK_STATE:
                clearLinkStateInternal();
                break;
            case Configuration.P1_GET_FACTORY_CSR:
                sendFactoryCsr(apdu);
                break;
            case Configuration.P1_SET_DEVICE_CERT:
                setDeviceCertificate(apdu);
                break;
            default:
                ISOException.throwIt(SW_WRONG_P1P2);
        }
    }

    private void sendFactoryCsr(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        buffer[offset++] = Configuration.DEVICE_CERT_FORMAT_VERSION;
        Util.arrayCopyNonAtomic(deviceId, (short) 0, buffer, offset, Configuration.DEVICE_ID_LENGTH);
        offset += Configuration.DEVICE_ID_LENGTH;

        short publicLength = deviceAuthPublicKey.getW(buffer, offset);
        if (publicLength != Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        ApduUtils.sendData(apdu, (short) 0, (short) (offset + publicLength));
    }

    private void setDeviceCertificate(APDU apdu) {
        if (deviceAuthCertificateLength > 0) {
            ISOException.throwIt(SW_CONDITIONS);
        }

        short bytesRead = ApduUtils.receiveData(apdu);
        byte[] buffer = apdu.getBuffer();
        short dataOffset = ISO7816.OFFSET_CDATA;

        if (!isCertificateStructureValid(buffer, dataOffset, bytesRead)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        if (!isCertificateBoundToLocalDevice(buffer, dataOffset)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        if (!verifyCertificateSignature(buffer, dataOffset, bytesRead)) {
            ISOException.throwIt(SW_SECURITY);
        }

        Util.arrayCopyNonAtomic(buffer, dataOffset, deviceAuthCertificate, (short) 0, bytesRead);
        deviceAuthCertificateLength = bytesRead;
    }

    private void sendDeviceCertificate(APDU apdu) {
        if (deviceAuthCertificateLength <= 0) {
            ISOException.throwIt(SW_RECORD_NOT_FOUND);
        }

        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(deviceAuthCertificate, (short) 0, buffer, (short) 0, deviceAuthCertificateLength);
        ApduUtils.sendData(apdu, (short) 0, deviceAuthCertificateLength);
    }

    private void startLinkProof(APDU apdu) {
        ensureDeviceCertificateInstalled();
        clearPeerVerificationState();
        resetSessionGuards();

        setCurveParameters(sessionLinkPrivateKey);
        setCurveParameters(sessionLinkPublicKey);
        sessionLinkKeyPair.genKeyPair();
        incrementSessionCounter();
        randomData.generateData(localNonce, (short) 0, Configuration.NONCE_LENGTH);

        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        buffer[offset++] = Configuration.BACKUP_PROTOCOL_VERSION;
        Util.arrayCopyNonAtomic(localSessionId, (short) 0, buffer, offset, Configuration.SESSION_ID_LENGTH);
        offset += Configuration.SESSION_ID_LENGTH;
        writeShort(buffer, offset, Configuration.LINK_PROOF_COUNTER);
        offset += Configuration.COUNTER_LENGTH;
        Util.arrayCopyNonAtomic(deviceId, (short) 0, buffer, offset, Configuration.DEVICE_ID_LENGTH);
        offset += Configuration.DEVICE_ID_LENGTH;

        short publicLength = sessionLinkPublicKey.getW(buffer, offset);
        if (publicLength != Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        offset += publicLength;

        Util.arrayCopyNonAtomic(localNonce, (short) 0, buffer, offset, Configuration.NONCE_LENGTH);
        short bodyLength = Configuration.LINK_PROOF_BODY_LENGTH;

        deviceSignature.init(deviceAuthPrivateKey, Signature.MODE_SIGN);
        short signatureLength = deviceSignature.sign(buffer, (short) 0, bodyLength, buffer, (short) (bodyLength + 1));
        if (signatureLength <= 0 || signatureLength > Configuration.MAX_DER_SIGNATURE_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        buffer[bodyLength] = (byte) signatureLength;
        localLinkProofGenerated = true;
        peerLinkProofLoaded = false;

        ApduUtils.sendData(apdu, (short) 0, (short) (bodyLength + 1 + signatureLength));
    }

    private void loadPeerCertificate(APDU apdu) {
        short bytesRead = ApduUtils.receiveData(apdu);
        byte[] buffer = apdu.getBuffer();
        short dataOffset = ISO7816.OFFSET_CDATA;

        if (!isCertificateStructureValid(buffer, dataOffset, bytesRead)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        if (!verifyCertificateSignature(buffer, dataOffset, bytesRead)) {
            ISOException.throwIt(SW_SECURITY);
        }

        Util.arrayCopyNonAtomic(buffer, (short) (dataOffset + OFFSET_CERT_DEVICE_ID),
                peerDeviceId, (short) 0, Configuration.DEVICE_ID_LENGTH);

        setCurveParameters(peerDeviceAuthPublicKey);
        peerDeviceAuthPublicKey.setW(buffer, (short) (dataOffset + OFFSET_CERT_DEVICE_PUBLIC),
                Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);

        peerCertificateLoaded = true;
        peerLinkProofLoaded = false;
        peerProofCounter = 0;
        peerSessionLinkPublicKey.clearKey();
        Util.arrayFillNonAtomic(peerSessionId, (short) 0, Configuration.SESSION_ID_LENGTH, (byte) 0x00);
        Util.arrayFillNonAtomic(peerNonce, (short) 0, Configuration.NONCE_LENGTH, (byte) 0x00);
    }

    private void loadPeerLinkProof(APDU apdu) {
        if (loadPeerLinkProofLocked) {
            ISOException.throwIt(SW_CONDITIONS);
        }
        if (!localLinkProofGenerated || !peerCertificateLoaded) {
            ISOException.throwIt(SW_CONDITIONS);
        }
        if (peerLinkProofLoaded) {
            ISOException.throwIt(SW_CONDITIONS);
        }

        try {
            short bytesRead = ApduUtils.receiveData(apdu);
            byte[] buffer = apdu.getBuffer();
            short dataOffset = ISO7816.OFFSET_CDATA;

            if (bytesRead < (short) (Configuration.LINK_PROOF_BODY_LENGTH + 1 + 8)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }

            if (buffer[(short) (dataOffset + OFFSET_LINK_VERSION)] != Configuration.BACKUP_PROTOCOL_VERSION) {
                ISOException.throwIt(SW_DATA_INVALID);
            }

            short proofCounter = readShort(buffer, (short) (dataOffset + OFFSET_LINK_COUNTER));
            if (proofCounter != Configuration.LINK_PROOF_COUNTER) {
                ISOException.throwIt(SW_SECURITY);
            }

            short signatureLengthOffset = (short) (dataOffset + Configuration.LINK_PROOF_BODY_LENGTH);
            short signatureLength = (short) (buffer[signatureLengthOffset] & 0xFF);
            if (signatureLength <= 0 || signatureLength > Configuration.MAX_DER_SIGNATURE_LENGTH) {
                ISOException.throwIt(SW_DATA_INVALID);
            }

            short expectedLength = (short) (Configuration.LINK_PROOF_BODY_LENGTH + 1 + signatureLength);
            if (bytesRead != expectedLength) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }

            if (Util.arrayCompare(buffer, (short) (dataOffset + OFFSET_LINK_DEVICE_ID),
                    peerDeviceId, (short) 0, Configuration.DEVICE_ID_LENGTH) != 0) {
                ISOException.throwIt(SW_SECURITY);
            }

            verifySignature.init(peerDeviceAuthPublicKey, Signature.MODE_VERIFY);
            if (!verifySignature.verify(buffer, dataOffset, Configuration.LINK_PROOF_BODY_LENGTH,
                    buffer, (short) (signatureLengthOffset + 1), signatureLength)) {
                ISOException.throwIt(SW_SECURITY);
            }

            setCurveParameters(peerSessionLinkPublicKey);
            peerSessionLinkPublicKey.setW(buffer, (short) (dataOffset + OFFSET_LINK_PUBLIC),
                    Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);

            Util.arrayCopyNonAtomic(buffer, (short) (dataOffset + OFFSET_LINK_SESSION_ID),
                    peerSessionId, (short) 0, Configuration.SESSION_ID_LENGTH);
            Util.arrayCopyNonAtomic(buffer, (short) (dataOffset + OFFSET_LINK_NONCE),
                    peerNonce, (short) 0, Configuration.NONCE_LENGTH);
            peerProofCounter = proofCounter;
            peerLinkProofLoaded = true;
            loadPeerLinkProofFailureCount = 0;
        } catch (ISOException e) {
            registerLoadPeerLinkProofFailure(e.getReason());
            throw e;
        }
    }

    private void exportBackupEnvelope(APDU apdu) {
        ensureZeroP1P2(apdu);
        ensureExportImportPreconditions();
        ensureWalletKeyAvailable();

        deriveBackupSessionKey(
                deviceId, peerDeviceId,
                localNonce, peerNonce,
                localSessionId, peerSessionId,
                Configuration.LINK_PROOF_COUNTER, peerProofCounter);

        short payloadLength = buildBackupPayload();
        short paddedLength = applyPkcs7Padding(payloadLength);

        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        buffer[offset++] = Configuration.BACKUP_PROTOCOL_VERSION;
        Util.arrayCopyNonAtomic(localSessionId, (short) 0, buffer, offset, Configuration.SESSION_ID_LENGTH);
        offset += Configuration.SESSION_ID_LENGTH;
        writeShort(buffer, offset, Configuration.BACKUP_ENVELOPE_COUNTER);
        offset += Configuration.COUNTER_LENGTH;
        Util.arrayCopyNonAtomic(deviceId, (short) 0, buffer, offset, Configuration.DEVICE_ID_LENGTH);
        offset += Configuration.DEVICE_ID_LENGTH;
        Util.arrayCopyNonAtomic(peerDeviceId, (short) 0, buffer, offset, Configuration.DEVICE_ID_LENGTH);
        offset += Configuration.DEVICE_ID_LENGTH;

        randomData.generateData(buffer, offset, Configuration.NONCE_LENGTH);
        aesKey.setKey(derivedSessionKey, (short) 0);
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT, buffer, offset, Configuration.NONCE_LENGTH);
        offset += Configuration.NONCE_LENGTH;

        short ciphertextLengthOffset = offset;
        buffer[offset++] = 0x00;
        short ciphertextOffset = offset;
        short ciphertextLength = aesCipher.doFinal(payloadBuffer, (short) 0, paddedLength, buffer, ciphertextOffset);
        if (ciphertextLength <= 0 || ciphertextLength > Configuration.MAX_BACKUP_CIPHERTEXT_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        buffer[ciphertextLengthOffset] = (byte) ciphertextLength;
        offset = (short) (ciphertextOffset + ciphertextLength);

        short bodyLength = offset;
        deviceSignature.init(deviceAuthPrivateKey, Signature.MODE_SIGN);
        short signatureLength = deviceSignature.sign(buffer, (short) 0, bodyLength, buffer, (short) (bodyLength + 1));
        if (signatureLength <= 0 || signatureLength > Configuration.MAX_DER_SIGNATURE_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        buffer[bodyLength] = (byte) signatureLength;

        clearSecretBuffers();
        ApduUtils.sendData(apdu, (short) 0, (short) (bodyLength + 1 + signatureLength));
        clearLinkStateInternal();
    }

    private void importBackupEnvelope(APDU apdu) {
        ensureZeroP1P2(apdu);
        if (backupImportLocked) {
            ISOException.throwIt(SW_CONDITIONS);
        }
        ensureExportImportPreconditions();

        try {
            short bytesRead = ApduUtils.receiveData(apdu);
            byte[] buffer = apdu.getBuffer();
            short dataOffset = ISO7816.OFFSET_CDATA;

            if (bytesRead < (short) (OFFSET_ENVELOPE_CIPHER + 1 + 1 + 8)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }

            if (buffer[(short) (dataOffset + OFFSET_ENVELOPE_VERSION)] != Configuration.BACKUP_PROTOCOL_VERSION) {
                ISOException.throwIt(SW_DATA_INVALID);
            }

            if (Util.arrayCompare(buffer, (short) (dataOffset + OFFSET_ENVELOPE_SESSION_ID),
                    peerSessionId, (short) 0, Configuration.SESSION_ID_LENGTH) != 0) {
                ISOException.throwIt(SW_SECURITY);
            }

            short envelopeCounter = readShort(buffer, (short) (dataOffset + OFFSET_ENVELOPE_COUNTER));
            if (envelopeCounter != Configuration.BACKUP_ENVELOPE_COUNTER) {
                ISOException.throwIt(SW_SECURITY);
            }

            short ciphertextLength = (short) (buffer[(short) (dataOffset + OFFSET_ENVELOPE_CIPHER_LENGTH)] & 0xFF);
            if (ciphertextLength <= 0 || ciphertextLength > Configuration.MAX_BACKUP_CIPHERTEXT_LENGTH) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }

            short signatureLengthOffset = (short) (dataOffset + OFFSET_ENVELOPE_CIPHER + ciphertextLength);
            if (signatureLengthOffset >= (short) (dataOffset + bytesRead)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }

            short signatureLength = (short) (buffer[signatureLengthOffset] & 0xFF);
            if (signatureLength <= 0 || signatureLength > Configuration.MAX_DER_SIGNATURE_LENGTH) {
                ISOException.throwIt(SW_DATA_INVALID);
            }

            short expectedLength = (short) (OFFSET_ENVELOPE_CIPHER + ciphertextLength + 1 + signatureLength);
            if (bytesRead != expectedLength) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }

            if (Util.arrayCompare(buffer, (short) (dataOffset + OFFSET_ENVELOPE_SOURCE_DEVICE_ID),
                    peerDeviceId, (short) 0, Configuration.DEVICE_ID_LENGTH) != 0) {
                ISOException.throwIt(SW_SECURITY);
            }

            if (Util.arrayCompare(buffer, (short) (dataOffset + OFFSET_ENVELOPE_DEST_DEVICE_ID),
                    deviceId, (short) 0, Configuration.DEVICE_ID_LENGTH) != 0) {
                ISOException.throwIt(SW_SECURITY);
            }

            verifySignature.init(peerDeviceAuthPublicKey, Signature.MODE_VERIFY);
            if (!verifySignature.verify(buffer, dataOffset, (short) (OFFSET_ENVELOPE_CIPHER + ciphertextLength),
                    buffer, (short) (signatureLengthOffset + 1), signatureLength)) {
                ISOException.throwIt(SW_SECURITY);
            }

            deriveBackupSessionKey(
                    peerDeviceId, deviceId,
                    peerNonce, localNonce,
                    peerSessionId, localSessionId,
                    peerProofCounter, Configuration.LINK_PROOF_COUNTER);

            aesKey.setKey(derivedSessionKey, (short) 0);
            aesCipher.init(aesKey, Cipher.MODE_DECRYPT, buffer, (short) (dataOffset + OFFSET_ENVELOPE_IV),
                    Configuration.NONCE_LENGTH);
            short plainLengthWithPadding = aesCipher.doFinal(buffer, (short) (dataOffset + OFFSET_ENVELOPE_CIPHER),
                    ciphertextLength, payloadBuffer, (short) 0);

            short plainLength = removePkcs7Padding(plainLengthWithPadding);
            if (plainLength != Configuration.BACKUP_PAYLOAD_LENGTH) {
                ISOException.throwIt(SW_DATA_INVALID);
            }

            if (payloadBuffer[0] != Configuration.BACKUP_PROTOCOL_VERSION) {
                ISOException.throwIt(SW_DATA_INVALID);
            }

            if (payloadBuffer[(short) (1 + Configuration.PRIVATE_KEY_LENGTH)] != 0x04) {
                ISOException.throwIt(SW_DATA_INVALID);
            }

            if (walletPrivateKey.isInitialized() && walletPublicKey.isInitialized() && !isExistingWalletKeyEqual()) {
                ISOException.throwIt(SW_CONDITIONS);
            }

            walletPrivateKey.setS(payloadBuffer, (short) 1, Configuration.PRIVATE_KEY_LENGTH);
            walletPublicKey.setW(payloadBuffer, (short) (1 + Configuration.PRIVATE_KEY_LENGTH),
                    Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);

            backupImportFailureCount = 0;
            clearLinkStateInternal();
        } catch (ISOException e) {
            registerBackupImportFailure(e.getReason());
            throw e;
        } finally {
            clearSecretBuffers();
        }
    }

    private short buildBackupPayload() {
        payloadBuffer[0] = Configuration.BACKUP_PROTOCOL_VERSION;

        short privateLength = walletPrivateKey.getS(keyScratch, (short) 0);
        if (privateLength <= 0 || privateLength > Configuration.PRIVATE_KEY_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        Util.arrayFillNonAtomic(payloadBuffer, (short) 1, Configuration.PRIVATE_KEY_LENGTH, (byte) 0x00);
        short privateCopyOffset = (short) (1 + Configuration.PRIVATE_KEY_LENGTH - privateLength);
        Util.arrayCopyNonAtomic(keyScratch, (short) 0, payloadBuffer, privateCopyOffset, privateLength);

        short publicLength = walletPublicKey.getW(keyScratch, (short) 0);
        if (publicLength != Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        Util.arrayCopyNonAtomic(keyScratch, (short) 0, payloadBuffer, (short) (1 + Configuration.PRIVATE_KEY_LENGTH),
                Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);

        return Configuration.BACKUP_PAYLOAD_LENGTH;
    }

    private short applyPkcs7Padding(short payloadLength) {
        short padLength = (short) (Configuration.AES_BLOCK_SIZE - (payloadLength % Configuration.AES_BLOCK_SIZE));
        if (padLength == 0) {
            padLength = Configuration.AES_BLOCK_SIZE;
        }

        short paddedLength = (short) (payloadLength + padLength);
        if (paddedLength > Configuration.MAX_BACKUP_CIPHERTEXT_LENGTH) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        for (short i = payloadLength; i < paddedLength; i++) {
            payloadBuffer[i] = (byte) padLength;
        }
        return paddedLength;
    }

    private short removePkcs7Padding(short lengthWithPadding) {
        if (lengthWithPadding <= 0 || (lengthWithPadding % Configuration.AES_BLOCK_SIZE) != 0) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        short padLength = (short) (payloadBuffer[(short) (lengthWithPadding - 1)] & 0xFF);
        if (padLength <= 0 || padLength > Configuration.AES_BLOCK_SIZE || padLength > lengthWithPadding) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        short padStart = (short) (lengthWithPadding - padLength);
        for (short i = padStart; i < lengthWithPadding; i++) {
            if (payloadBuffer[i] != (byte) padLength) {
                ISOException.throwIt(SW_DATA_INVALID);
            }
        }

        return (short) (lengthWithPadding - padLength);
    }

    private void deriveBackupSessionKey(
            byte[] sourceDeviceId, byte[] destinationDeviceId,
            byte[] sourceNonce, byte[] destinationNonce,
            byte[] sourceSessionId, byte[] destinationSessionId,
            short sourceProofCounter, short destinationProofCounter) {
        short peerPublicLength = peerSessionLinkPublicKey.getW(keyScratch, (short) 0);
        if (peerPublicLength != Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        keyAgreement.init(sessionLinkPrivateKey);
        short sharedSecretLength = keyAgreement.generateSecret(
                keyScratch, (short) 0, peerPublicLength, sharedSecret, (short) 0);
        if (sharedSecretLength <= 0) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        sha256Digest.reset();
        sha256Digest.update(sharedSecret, (short) 0, sharedSecretLength);
        sha256Digest.update(sourceDeviceId, (short) 0, Configuration.DEVICE_ID_LENGTH);
        sha256Digest.update(destinationDeviceId, (short) 0, Configuration.DEVICE_ID_LENGTH);
        sha256Digest.update(sourceNonce, (short) 0, Configuration.NONCE_LENGTH);
        sha256Digest.update(destinationNonce, (short) 0, Configuration.NONCE_LENGTH);
        sha256Digest.update(sourceSessionId, (short) 0, Configuration.SESSION_ID_LENGTH);
        sha256Digest.update(destinationSessionId, (short) 0, Configuration.SESSION_ID_LENGTH);
        writeShort(keyScratch, (short) 0, sourceProofCounter);
        sha256Digest.update(keyScratch, (short) 0, Configuration.COUNTER_LENGTH);
        writeShort(keyScratch, (short) 0, destinationProofCounter);
        sha256Digest.update(keyScratch, (short) 0, Configuration.COUNTER_LENGTH);
        sha256Digest.doFinal(Configuration.BACKUP_KDF_LABEL, (short) 0, (short) Configuration.BACKUP_KDF_LABEL.length,
                derivedSessionKey, (short) 0);
    }

    private boolean isExistingWalletKeyEqual() {
        short existingPrivateLength = walletPrivateKey.getS(keyScratch, (short) 0);
        if (existingPrivateLength <= 0 || existingPrivateLength > Configuration.PRIVATE_KEY_LENGTH) {
            return false;
        }

        short leftPad = (short) (Configuration.PRIVATE_KEY_LENGTH - existingPrivateLength);
        for (short i = 0; i < Configuration.PRIVATE_KEY_LENGTH; i++) {
            byte existing = (i < leftPad) ? (byte) 0x00 : keyScratch[(short) (i - leftPad)];
            byte incoming = payloadBuffer[(short) (1 + i)];
            if (existing != incoming) {
                return false;
            }
        }

        short existingPublicLength = walletPublicKey.getW(keyScratch, (short) 0);
        if (existingPublicLength != Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) {
            return false;
        }

        return Util.arrayCompare(keyScratch, (short) 0,
                payloadBuffer, (short) (1 + Configuration.PRIVATE_KEY_LENGTH),
                Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) == 0;
    }

    private boolean isCertificateStructureValid(byte[] buffer, short offset, short length) {
        if (length < (short) (Configuration.DEVICE_CERT_BODY_LENGTH + 1 + 8)
                || length > Configuration.MAX_DEVICE_CERT_LENGTH) {
            return false;
        }

        if (buffer[(short) (offset + OFFSET_CERT_VERSION)] != Configuration.DEVICE_CERT_FORMAT_VERSION) {
            return false;
        }

        if (buffer[(short) (offset + OFFSET_CERT_DEVICE_PUBLIC)] != 0x04) {
            return false;
        }

        byte capabilities = buffer[(short) (offset + OFFSET_CERT_CAPABILITIES)];
        if ((capabilities & Configuration.DEVICE_CERT_CAPABILITY_BACKUP) == 0) {
            return false;
        }

        short signatureLength = (short) (buffer[(short) (offset + OFFSET_CERT_SIGNATURE_LENGTH)] & 0xFF);
        if (signatureLength <= 0 || signatureLength > Configuration.MAX_DER_SIGNATURE_LENGTH) {
            return false;
        }

        return length == (short) (Configuration.DEVICE_CERT_BODY_LENGTH + 1 + signatureLength);
    }

    private boolean isCertificateBoundToLocalDevice(byte[] buffer, short offset) {
        if (Util.arrayCompare(buffer, (short) (offset + OFFSET_CERT_DEVICE_ID),
                deviceId, (short) 0, Configuration.DEVICE_ID_LENGTH) != 0) {
            return false;
        }

        short localPublicLength = deviceAuthPublicKey.getW(keyScratch, (short) 0);
        if (localPublicLength != Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) {
            return false;
        }

        return Util.arrayCompare(buffer, (short) (offset + OFFSET_CERT_DEVICE_PUBLIC),
                keyScratch, (short) 0, Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) == 0;
    }

    private boolean verifyCertificateSignature(byte[] buffer, short offset, short length) {
        short signatureLength = (short) (buffer[(short) (offset + OFFSET_CERT_SIGNATURE_LENGTH)] & 0xFF);
        short signatureOffset = (short) (offset + Configuration.DEVICE_CERT_BODY_LENGTH + 1);
        if (length != (short) (Configuration.DEVICE_CERT_BODY_LENGTH + 1 + signatureLength)) {
            return false;
        }

        verifySignature.init(chainoraFactoryRootPublicKey, Signature.MODE_VERIFY);
        return verifySignature.verify(
                buffer, offset, Configuration.DEVICE_CERT_BODY_LENGTH,
                buffer, signatureOffset, signatureLength);
    }

    private void incrementSessionCounter() {
        if (sessionCounter == 0) {
            sessionCounter = 1;
        }
        localSessionId[0] = (byte) (sessionCounter >> 8);
        localSessionId[1] = (byte) (sessionCounter & 0xFF);
        sessionCounter++;
    }

    private void clearLinkStateInternal() {
        localLinkProofGenerated = false;
        clearPeerVerificationState();
        resetSessionGuards();

        Util.arrayFillNonAtomic(localSessionId, (short) 0, Configuration.SESSION_ID_LENGTH, (byte) 0x00);
        Util.arrayFillNonAtomic(localNonce, (short) 0, Configuration.NONCE_LENGTH, (byte) 0x00);
        sessionLinkPrivateKey.clearKey();
        sessionLinkPublicKey.clearKey();
    }

    private void clearPeerVerificationState() {
        peerCertificateLoaded = false;
        peerLinkProofLoaded = false;
        peerProofCounter = 0;

        Util.arrayFillNonAtomic(peerDeviceId, (short) 0, Configuration.DEVICE_ID_LENGTH, (byte) 0x00);
        Util.arrayFillNonAtomic(peerSessionId, (short) 0, Configuration.SESSION_ID_LENGTH, (byte) 0x00);
        Util.arrayFillNonAtomic(peerNonce, (short) 0, Configuration.NONCE_LENGTH, (byte) 0x00);
        peerDeviceAuthPublicKey.clearKey();
        peerSessionLinkPublicKey.clearKey();
    }

    private void clearSecretBuffers() {
        Util.arrayFillNonAtomic(sharedSecret, (short) 0, (short) sharedSecret.length, (byte) 0x00);
        Util.arrayFillNonAtomic(derivedSessionKey, (short) 0, (short) derivedSessionKey.length, (byte) 0x00);
        Util.arrayFillNonAtomic(payloadBuffer, (short) 0, (short) payloadBuffer.length, (byte) 0x00);
        Util.arrayFillNonAtomic(keyScratch, (short) 0, (short) keyScratch.length, (byte) 0x00);
    }

    private void ensureZeroP1P2(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_P1] != 0x00 || buffer[ISO7816.OFFSET_P2] != 0x00) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
    }

    private void ensureDeviceCertificateInstalled() {
        if (deviceAuthCertificateLength <= 0) {
            ISOException.throwIt(SW_CONDITIONS);
        }
    }

    private void ensureWalletKeyAvailable() {
        if (!walletPrivateKey.isInitialized() || !walletPublicKey.isInitialized()) {
            ISOException.throwIt(SW_CONDITIONS);
        }
    }

    private void ensureExportImportPreconditions() {
        ensureDeviceCertificateInstalled();
        pinValidator.ensureInitializedAndValidated();

        if (!localLinkProofGenerated || !peerCertificateLoaded || !peerLinkProofLoaded) {
            ISOException.throwIt(SW_CONDITIONS);
        }
        if (peerProofCounter != Configuration.LINK_PROOF_COUNTER) {
            ISOException.throwIt(SW_CONDITIONS);
        }
    }

    private void resetSessionGuards() {
        loadPeerLinkProofFailureCount = 0;
        backupImportFailureCount = 0;
        loadPeerLinkProofLocked = false;
        backupImportLocked = false;
    }

    private void registerLoadPeerLinkProofFailure(short sw) {
        if (!isTrackableFailure(sw)) {
            return;
        }
        loadPeerLinkProofFailureCount++;
        if (loadPeerLinkProofFailureCount >= Configuration.BACKUP_FAILURE_THRESHOLD) {
            loadPeerLinkProofLocked = true;
            ISOException.throwIt(SW_CONDITIONS);
        }
    }

    private void registerBackupImportFailure(short sw) {
        if (!isTrackableFailure(sw)) {
            return;
        }
        backupImportFailureCount++;
        if (backupImportFailureCount >= Configuration.BACKUP_FAILURE_THRESHOLD) {
            backupImportLocked = true;
            ISOException.throwIt(SW_CONDITIONS);
        }
    }

    private boolean isTrackableFailure(short sw) {
        return sw == SW_WRONG_LENGTH || sw == SW_DATA_INVALID || sw == SW_SECURITY;
    }

    private void writeShort(byte[] buffer, short offset, short value) {
        buffer[offset] = (byte) (value >> 8);
        buffer[(short) (offset + 1)] = (byte) (value & 0xFF);
    }

    private short readShort(byte[] buffer, short offset) {
        short high = (short) (buffer[offset] & 0xFF);
        short low = (short) (buffer[(short) (offset + 1)] & 0xFF);
        return (short) ((short) (high << 8) | low);
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
