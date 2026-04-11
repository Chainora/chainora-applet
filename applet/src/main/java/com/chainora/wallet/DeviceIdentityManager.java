package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;

/**
 * Stores device identity material shared by factory provisioning, backup, and backend attestation.
 */
final class DeviceIdentityManager {
    private static final short SW_CONDITIONS = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
    private static final short SW_SECURITY = ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
    private static final short SW_DATA_INVALID = ISO7816.SW_DATA_INVALID;
    private static final short SW_RECORD_NOT_FOUND = ISO7816.SW_RECORD_NOT_FOUND;

    private static final short OFFSET_CERT_VERSION = 0;
    private static final short OFFSET_CERT_DEVICE_ID = 1;
    private static final short OFFSET_CERT_DEVICE_PUBLIC =
            (short) (OFFSET_CERT_DEVICE_ID + Configuration.DEVICE_ID_LENGTH);
    private static final short OFFSET_CERT_CAPABILITIES =
            (short) (OFFSET_CERT_DEVICE_PUBLIC + Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);
    private static final short OFFSET_CERT_SIGNATURE_LENGTH =
            (short) (OFFSET_CERT_CAPABILITIES + 1);

    private final ECPrivateKey deviceAuthPrivateKey;
    private final ECPublicKey deviceAuthPublicKey;
    private final ECPublicKey chainoraFactoryRootPublicKey;
    private final Signature deviceSignature;
    private final Signature verifySignature;

    private final byte[] deviceId;
    private final byte[] deviceAuthCertificate;
    private final byte[] keyScratch;
    private short deviceAuthCertificateLength;

    DeviceIdentityManager(
            KeyPair deviceAuthKeyPair,
            ECPublicKey chainoraFactoryRootPublicKey,
            Signature deviceSignature,
            Signature verifySignature,
            RandomData randomData) {
        this.deviceAuthPrivateKey = (ECPrivateKey) deviceAuthKeyPair.getPrivate();
        this.deviceAuthPublicKey = (ECPublicKey) deviceAuthKeyPair.getPublic();
        this.chainoraFactoryRootPublicKey = chainoraFactoryRootPublicKey;
        this.deviceSignature = deviceSignature;
        this.verifySignature = verifySignature;

        this.deviceId = new byte[Configuration.DEVICE_ID_LENGTH];
        this.deviceAuthCertificate = new byte[Configuration.MAX_DEVICE_CERT_LENGTH];
        this.keyScratch = JCSystem.makeTransientByteArray(
                Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH,
                JCSystem.CLEAR_ON_DESELECT);
        this.deviceAuthCertificateLength = 0;

        randomData.generateData(deviceId, (short) 0, Configuration.DEVICE_ID_LENGTH);
        deviceAuthKeyPair.genKeyPair();
    }

    void sendFactoryCsr(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        buffer[offset++] = Configuration.DEVICE_CERT_FORMAT_VERSION;
        copyDeviceId(buffer, offset);
        offset += Configuration.DEVICE_ID_LENGTH;

        short publicLength = deviceAuthPublicKey.getW(buffer, offset);
        if (publicLength != Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH) {
            ISOException.throwIt(SW_DATA_INVALID);
        }

        ApduUtils.sendData(apdu, (short) 0, (short) (offset + publicLength));
    }

    void setDeviceCertificate(APDU apdu) {
        short bytesRead = ApduUtils.receiveData(apdu);
        byte[] buffer = apdu.getBuffer();
        setDeviceCertificate(buffer, ISO7816.OFFSET_CDATA, bytesRead);
    }

    void setDeviceCertificate(byte[] buffer, short offset, short length) {
        if (deviceAuthCertificateLength > 0) {
            ISOException.throwIt(SW_CONDITIONS);
        }
        if (!isCertificateStructureValid(buffer, offset, length)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        if (!isCertificateBoundToLocalDevice(buffer, offset)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        if (!verifyCertificateSignature(buffer, offset, length)) {
            ISOException.throwIt(SW_SECURITY);
        }

        Util.arrayCopyNonAtomic(buffer, offset, deviceAuthCertificate, (short) 0, length);
        deviceAuthCertificateLength = length;
    }

    void sendDeviceCertificate(APDU apdu) {
        ensureCertificateInstalled(SW_RECORD_NOT_FOUND);

        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(deviceAuthCertificate, (short) 0, buffer, (short) 0, deviceAuthCertificateLength);
        ApduUtils.sendData(apdu, (short) 0, deviceAuthCertificateLength);
    }

    void ensureCertificateInstalledForOperation() {
        ensureCertificateInstalled(SW_CONDITIONS);
    }

    void ensureCertificateInstalledForRead() {
        ensureCertificateInstalled(SW_RECORD_NOT_FOUND);
    }

    void copyDeviceId(byte[] buffer, short offset) {
        Util.arrayCopyNonAtomic(deviceId, (short) 0, buffer, offset, Configuration.DEVICE_ID_LENGTH);
    }

    short signWithDeviceKey(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        deviceSignature.init(deviceAuthPrivateKey, Signature.MODE_SIGN);
        return deviceSignature.sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    void verifyAndLoadPeerCertificate(
            byte[] buffer,
            short offset,
            short length,
            byte[] peerDeviceId,
            ECPublicKey peerDeviceAuthPublicKey) {
        if (!isCertificateStructureValid(buffer, offset, length)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
        if (!verifyCertificateSignature(buffer, offset, length)) {
            ISOException.throwIt(SW_SECURITY);
        }

        Util.arrayCopyNonAtomic(buffer, (short) (offset + OFFSET_CERT_DEVICE_ID),
                peerDeviceId, (short) 0, Configuration.DEVICE_ID_LENGTH);
        peerDeviceAuthPublicKey.setW(buffer,
                (short) (offset + OFFSET_CERT_DEVICE_PUBLIC),
                Configuration.PUBLIC_KEY_UNCOMPRESSED_LENGTH);
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
                buffer,
                offset,
                Configuration.DEVICE_CERT_BODY_LENGTH,
                buffer,
                signatureOffset,
                signatureLength);
    }

    private void ensureCertificateInstalled(short statusWord) {
        if (deviceAuthCertificateLength <= 0) {
            ISOException.throwIt(statusWord);
        }
    }
}
