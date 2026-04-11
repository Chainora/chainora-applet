package tools;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.RunConfig;
import cz.muni.fi.crocs.rcard.client.Util;

/**
 * Provisions factory-signed device certificate after applet installation.
 */
public final class InstallCertificateProvisioner {
    private static final String APPLET_AID = "f0564e43485701";

    private static final byte CLA = (byte) 0x80;
    private static final byte INS_DEVICE_CERT = (byte) 0x23;

    private static final byte P1_GET_DEVICE_CERT = (byte) 0x00;
    private static final byte P1_GET_FACTORY_CSR = (byte) 0x10;
    private static final byte P1_SET_DEVICE_CERT = (byte) 0x11;

    private static final int SW_SUCCESS = 0x9000;
    private static final int SW_CONDITIONS_NOT_SATISFIED = 0x6985;
    private static final int SW_RECORD_NOT_FOUND = 0x6A83;

    private static final byte CERT_VERSION = 0x01;
    private static final byte DEVICE_CERT_CAPABILITY_BACKUP = 0x01;
    private static final int DEVICE_ID_LENGTH = 16;
    private static final int PUBLIC_KEY_UNCOMPRESSED_LENGTH = 65;
    private static final int CSR_LENGTH = 1 + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH;
    private static final int MAX_DER_SIGNATURE_LENGTH = 72;

    private static final String FACTORY_ROOT_PRIVATE_KEY_HEX =
            "4627946b9d7da5245af8160d49e7680c159d40f45a7ed7bf1f4be74bff870057";

    private static final ECDomainParameters SECP256K1 = createSecp256k1Domain();
    private static final BigInteger HALF_CURVE_ORDER = SECP256K1.getN().shiftRight(1);

    private InstallCertificateProvisioner() {
    }

    public static void main(String[] args) throws Exception {
        CardManager cardManager = new CardManager(true, Util.hexStringToByteArray(APPLET_AID));
        RunConfig runConfig = RunConfig.getDefaultConfig();
        runConfig.setTestCardType(CardType.PHYSICAL);

        if (!cardManager.connect(runConfig)) {
            throw new IllegalStateException("Cannot connect to card for certificate provisioning.");
        }

        try {
            ensureDeviceCertificate(cardManager);
        } finally {
            try {
                cardManager.disconnect(false);
            } catch (Exception ignored) {
                // No-op.
            }
        }
    }

    private static void ensureDeviceCertificate(CardManager cardManager) throws Exception {
        byte[] existing = tryReadDeviceCertificate(cardManager);
        if (existing != null) {
            System.out.println("Device certificate already present on card.");
            return;
        }

        byte[] csr = readFactoryCsr(cardManager);
        byte[] certificate = issueDeviceCertificate(csr);

        ResponseAPDU setResponse = transmit(
                cardManager,
                new CommandAPDU(CLA & 0xFF, INS_DEVICE_CERT & 0xFF,
                        P1_SET_DEVICE_CERT & 0xFF, 0x00, certificate));

        if (setResponse.getSW() != SW_SUCCESS && setResponse.getSW() != SW_CONDITIONS_NOT_SATISFIED) {
            throw new IllegalStateException(
                    String.format("SET_DEVICE_CERT failed with SW=%04X", setResponse.getSW()));
        }

        byte[] installed = requireDeviceCertificate(cardManager);
        if (setResponse.getSW() == SW_SUCCESS && !Arrays.equals(certificate, installed)) {
            throw new IllegalStateException("Certificate verification mismatch after provisioning.");
        }

        System.out.println("Factory device certificate is present on card.");
    }

    private static byte[] tryReadDeviceCertificate(CardManager cardManager) throws Exception {
        ResponseAPDU response = transmit(
                cardManager,
                new CommandAPDU(CLA & 0xFF, INS_DEVICE_CERT & 0xFF, P1_GET_DEVICE_CERT & 0xFF, 0x00));

        if (response.getSW() == SW_SUCCESS) {
            return response.getData();
        }
        if (response.getSW() == SW_RECORD_NOT_FOUND) {
            return null;
        }

        throw new IllegalStateException(String.format("GET_DEVICE_CERT failed with SW=%04X", response.getSW()));
    }

    private static byte[] requireDeviceCertificate(CardManager cardManager) throws Exception {
        byte[] certificate = tryReadDeviceCertificate(cardManager);
        if (certificate == null || certificate.length == 0) {
            throw new IllegalStateException("Device certificate is missing after provisioning.");
        }
        return certificate;
    }

    private static byte[] readFactoryCsr(CardManager cardManager) throws Exception {
        ResponseAPDU response = transmit(
                cardManager,
                new CommandAPDU(CLA & 0xFF, INS_DEVICE_CERT & 0xFF, P1_GET_FACTORY_CSR & 0xFF, 0x00));

        if (response.getSW() != SW_SUCCESS) {
            throw new IllegalStateException(String.format("GET_FACTORY_CSR failed with SW=%04X", response.getSW()));
        }

        byte[] csr = response.getData();
        if (csr == null || csr.length != CSR_LENGTH) {
            throw new IllegalStateException("Card returned invalid CSR length.");
        }
        if (csr[0] != CERT_VERSION) {
            throw new IllegalStateException("Card returned unsupported CSR version.");
        }
        if (csr[1 + DEVICE_ID_LENGTH] != 0x04) {
            throw new IllegalStateException("CSR public key is not uncompressed secp256k1.");
        }

        return csr;
    }

    private static byte[] issueDeviceCertificate(byte[] csr) {
        byte[] certBody = new byte[1 + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH + 1];
        certBody[0] = CERT_VERSION;
        System.arraycopy(csr, 1, certBody, 1, DEVICE_ID_LENGTH);
        System.arraycopy(csr, 1 + DEVICE_ID_LENGTH, certBody, 1 + DEVICE_ID_LENGTH, PUBLIC_KEY_UNCOMPRESSED_LENGTH);
        certBody[certBody.length - 1] = DEVICE_CERT_CAPABILITY_BACKUP;

        byte[] digest = sha256(certBody);
        byte[] signature = signDigest(digest);
        Arrays.fill(digest, (byte) 0x00);

        if (signature.length > MAX_DER_SIGNATURE_LENGTH) {
            throw new IllegalStateException("Unexpected certificate signature length.");
        }

        byte[] certificate = new byte[certBody.length + 1 + signature.length];
        System.arraycopy(certBody, 0, certificate, 0, certBody.length);
        certificate[certBody.length] = (byte) signature.length;
        System.arraycopy(signature, 0, certificate, certBody.length + 1, signature.length);
        return certificate;
    }

    private static byte[] signDigest(byte[] digest) {
        BigInteger privateScalar = new BigInteger(1, hexToBytes(FACTORY_ROOT_PRIVATE_KEY_HEX));
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privateScalar, SECP256K1));

        BigInteger[] rs = signer.generateSignature(digest);
        BigInteger r = rs[0];
        BigInteger s = rs[1];
        if (s.compareTo(HALF_CURVE_ORDER) > 0) {
            s = SECP256K1.getN().subtract(s);
        }

        try {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1Integer(r));
            vector.add(new ASN1Integer(s));
            return new DERSequence(vector).getEncoded();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to DER-encode certificate signature.", ex);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 not available.", ex);
        }
    }

    private static ResponseAPDU transmit(CardManager cardManager, CommandAPDU command) throws Exception {
        ResponseAPDU response = cardManager.transmit(command);
        if (response == null) {
            throw new IllegalStateException("Card returned null APDU response.");
        }
        return response;
    }

    private static ECDomainParameters createSecp256k1Domain() {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        return new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null || (hex.length() % 2) != 0) {
            throw new IllegalArgumentException("Invalid hex input.");
        }

        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex character.");
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
