package com.chainora.client.wallet.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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

/**
 * Issues temporary development certificates for card provisioning.
 */
public class BackupProvisioningService {
    private static final byte CERT_VERSION = 0x01;
    private static final byte DEVICE_CERT_CAPABILITY_BACKUP = 0x01;

    private static final int DEVICE_ID_LENGTH = 16;
    private static final int PUBLIC_KEY_UNCOMPRESSED_LENGTH = 65;
    private static final int CSR_LENGTH = 1 + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH;

    private static final ECDomainParameters SECP256K1 = createSecp256k1Domain();
    private static final BigInteger HALF_CURVE_ORDER = SECP256K1.getN().shiftRight(1);

    // Temporary development root private key for local provisioning only.
    private static final byte[] CHAINORA_DEV_ROOT_PRIVATE_KEY = hexToBytes(
            "a39b307b3a8752f2f1a9abaff2b3ba2cd967de3fbaf23d0b81b17a79a27e20de");

    private static final String DEV_PROVISIONING_ENV = "CHAINORA_ENABLE_DEV_PROVISIONING";

    /**
     * Issues a signed device certificate from CSR payload returned by the card.
     *
     * @param csr device CSR payload
     * @return signed device certificate payload
     */
    public byte[] issueDeviceCertificate(byte[] csr) {
        ensureDevProvisioningEnabled();

        if (csr == null || csr.length != CSR_LENGTH) {
            throw new IllegalArgumentException("Invalid device CSR length");
        }
        if (csr[0] != CERT_VERSION) {
            throw new IllegalArgumentException("Unsupported CSR version");
        }
        if (csr[1 + DEVICE_ID_LENGTH] != 0x04) {
            throw new IllegalArgumentException("CSR public key must be uncompressed secp256k1");
        }

        byte[] certBody = new byte[1 + DEVICE_ID_LENGTH + PUBLIC_KEY_UNCOMPRESSED_LENGTH + 1];
        certBody[0] = CERT_VERSION;
        System.arraycopy(csr, 1, certBody, 1, DEVICE_ID_LENGTH);
        System.arraycopy(csr, 1 + DEVICE_ID_LENGTH, certBody, 1 + DEVICE_ID_LENGTH, PUBLIC_KEY_UNCOMPRESSED_LENGTH);
        certBody[certBody.length - 1] = DEVICE_CERT_CAPABILITY_BACKUP;

        byte[] digest = sha256(certBody);
        byte[] signature = signDigest(digest);
        if (signature.length > 72) {
            throw new IllegalStateException("Unexpected certificate signature length");
        }

        byte[] certificate = new byte[certBody.length + 1 + signature.length];
        System.arraycopy(certBody, 0, certificate, 0, certBody.length);
        certificate[certBody.length] = (byte) signature.length;
        System.arraycopy(signature, 0, certificate, certBody.length + 1, signature.length);

        Arrays.fill(digest, (byte) 0x00);
        return certificate;
    }

    private void ensureDevProvisioningEnabled() {
        String envValue = System.getenv(DEV_PROVISIONING_ENV);
        if (envValue == null || !"1".equals(envValue.trim())) {
            throw new IllegalStateException(
                    "Dev provisioning disabled. Set CHAINORA_ENABLE_DEV_PROVISIONING=1 to allow temporary factory cert issuance.");
        }
    }

    private byte[] signDigest(byte[] digest) {
        BigInteger privateScalar = new BigInteger(1, CHAINORA_DEV_ROOT_PRIVATE_KEY);
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
            throw new IllegalStateException("Failed to DER-encode certificate signature", ex);
        }
    }

    private byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private static ECDomainParameters createSecp256k1Domain() {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        return new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null || (hex.length() % 2) != 0) {
            throw new IllegalArgumentException("Invalid hex input");
        }

        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex character");
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
