package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.OwnerPIN;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Chainora Wallet Applet - Main entry point.
 * Handles applet lifecycle and command dispatching.
 */
public class ChainoraWallet extends Applet {
    private final CommandDispatcher dispatcher;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ChainoraWallet();
    }

    private ChainoraWallet() {
        OwnerPIN pin = new OwnerPIN(Configuration.PIN_TRY_LIMIT, Configuration.PIN_MAX_SIZE);
        PinValidator pinValidator = new PinValidator(pin);

        ECPrivateKey walletPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE,
                Configuration.KEY_LENGTH_BITS,
                false);

        ECPublicKey walletPublicKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC,
                Configuration.KEY_LENGTH_BITS,
                false);

        setCurveParameters(walletPrivateKey);
        setCurveParameters(walletPublicKey);
        KeyPair walletKeyPair = new KeyPair(walletPublicKey, walletPrivateKey);

        ECPrivateKey deviceAuthPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE,
                Configuration.KEY_LENGTH_BITS,
                false);
        ECPublicKey deviceAuthPublicKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC,
                Configuration.KEY_LENGTH_BITS,
                false);
        setCurveParameters(deviceAuthPrivateKey);
        setCurveParameters(deviceAuthPublicKey);
        KeyPair deviceAuthKeyPair = new KeyPair(deviceAuthPublicKey, deviceAuthPrivateKey);

        ECPrivateKey sessionLinkPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE,
                Configuration.KEY_LENGTH_BITS,
                false);
        ECPublicKey sessionLinkPublicKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC,
                Configuration.KEY_LENGTH_BITS,
                false);
        setCurveParameters(sessionLinkPrivateKey);
        setCurveParameters(sessionLinkPublicKey);
        KeyPair sessionLinkKeyPair = new KeyPair(sessionLinkPublicKey, sessionLinkPrivateKey);

        ECPublicKey chainoraFactoryRootPublicKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC,
                Configuration.KEY_LENGTH_BITS,
                false);
        setCurveParameters(chainoraFactoryRootPublicKey);
        chainoraFactoryRootPublicKey.setW(
                Configuration.CHAINORA_FACTORY_ROOT_PUBLIC_KEY,
                (short) 0,
                (short) Configuration.CHAINORA_FACTORY_ROOT_PUBLIC_KEY.length);

        ECPublicKey peerDeviceAuthPublicKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC,
                Configuration.KEY_LENGTH_BITS,
                false);
        setCurveParameters(peerDeviceAuthPublicKey);

        ECPublicKey peerSessionLinkPublicKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC,
                Configuration.KEY_LENGTH_BITS,
                false);
        setCurveParameters(peerSessionLinkPublicKey);

        Signature walletSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        Signature deviceAuthSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        Signature sharedVerifySignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        Signature backupVerifySignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        MessageDigest sha256Digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_128,
                false);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        this.dispatcher = createDispatcher(
                pinValidator,
                walletKeyPair,
                walletPublicKey,
                walletPrivateKey,
                walletSignature,
                deviceAuthKeyPair,
                chainoraFactoryRootPublicKey,
                sessionLinkKeyPair,
                peerDeviceAuthPublicKey,
                peerSessionLinkPublicKey,
                deviceAuthSignature,
                sharedVerifySignature,
                backupVerifySignature,
                keyAgreement,
                sha256Digest,
                aesKey,
                aesCipher,
                randomData);

        register();
    }

    private CommandDispatcher createDispatcher(
            PinValidator pinValidator,
            KeyPair walletKeyPair,
            ECPublicKey walletPublicKey,
            ECPrivateKey walletPrivateKey,
            Signature walletSignature,
            KeyPair deviceAuthKeyPair,
            ECPublicKey chainoraFactoryRootPublicKey,
            KeyPair sessionLinkKeyPair,
            ECPublicKey peerDeviceAuthPublicKey,
            ECPublicKey peerSessionLinkPublicKey,
            Signature deviceAuthSignature,
            Signature sharedVerifySignature,
            Signature backupVerifySignature,
            KeyAgreement keyAgreement,
            MessageDigest sha256Digest,
            AESKey aesKey,
            Cipher aesCipher,
            RandomData randomData) {
        PinCommandHandler pinHandler = new PinCommandHandler(pinValidator);
        KeyCommandHandler keyHandler = new KeyCommandHandler(pinValidator, walletKeyPair, walletPublicKey);
        SignCommandHandler signHandler = new SignCommandHandler(pinValidator, walletPrivateKey, walletSignature);
        DeviceIdentityManager deviceIdentityManager = new DeviceIdentityManager(
                deviceAuthKeyPair,
                chainoraFactoryRootPublicKey,
                deviceAuthSignature,
                sharedVerifySignature,
                randomData);
        DeviceCertificateCommandHandler deviceCertificateHandler =
                new DeviceCertificateCommandHandler(deviceIdentityManager);
        CardAttestationCommandHandler cardAttestationHandler =
                new CardAttestationCommandHandler(deviceIdentityManager);
        BackupCommandHandler backupHandler = new BackupCommandHandler(
                pinValidator,
                walletPrivateKey,
                walletPublicKey,
                deviceIdentityManager,
                sessionLinkKeyPair,
                peerDeviceAuthPublicKey,
                peerSessionLinkPublicKey,
                backupVerifySignature,
                keyAgreement,
                sha256Digest,
                aesKey,
                aesCipher,
                randomData);

        return CommandDispatcher.builder()
                .register((byte) 0x10, pinHandler)
                .register((byte) 0x11, pinHandler)
                .register((byte) 0x12, pinHandler)
                .register((byte) 0x13, pinHandler)
                .register((byte) 0x14, pinHandler)
                .register((byte) 0x20, keyHandler)
                .register((byte) 0x21, keyHandler)
                .register((byte) 0x22, signHandler)
                .register(Configuration.INS_DEVICE_CERT, deviceCertificateHandler)
                .register(Configuration.INS_CARD_ATTEST, cardAttestationHandler)
                .register(Configuration.INS_BACKUP_SESSION, backupHandler)
                .register(Configuration.INS_BACKUP_EXPORT, backupHandler)
                .register(Configuration.INS_BACKUP_IMPORT, backupHandler)
                .build();
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        dispatcher.dispatch(apdu, ins);
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
