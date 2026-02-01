package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.OwnerPIN;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

/**
 * Chainora Wallet Applet - Main entry point.
 * Handles applet lifecycle and command dispatching.
 */
public class ChainoraWallet extends Applet {
    private static final short SW_NO_ERROR = ISO7816.SW_NO_ERROR;

    private final CommandDispatcher dispatcher;
    private final PinValidator pinValidator;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ChainoraWallet();
    }

    private ChainoraWallet() {
        OwnerPIN pin = new OwnerPIN(Configuration.PIN_TRY_LIMIT, Configuration.PIN_MAX_SIZE);
        this.pinValidator = new PinValidator(pin);

        ECPrivateKey privateKey = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE,
                Configuration.KEY_LENGTH_BITS,
                false);

        ECPublicKey publicKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC,
                Configuration.KEY_LENGTH_BITS,
                false);

        setCurveParameters(privateKey);
        setCurveParameters(publicKey);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        Signature ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        this.dispatcher = createDispatcher(keyPair, publicKey, privateKey, ecdsaSignature);

        register();
    }

    private CommandDispatcher createDispatcher(KeyPair keyPair, ECPublicKey publicKey,
            ECPrivateKey privateKey, Signature ecdsaSignature) {
        PinCommandHandler pinHandler = new PinCommandHandler(pinValidator);

        return CommandDispatcher.builder()
                .register((byte) 0x10, pinHandler)
                .register((byte) 0x11, pinHandler)
                .register((byte) 0x12, pinHandler)
                .register((byte) 0x13, pinHandler)
                .register((byte) 0x14, pinHandler)
                .register((byte) 0x20, new KeyCommandHandler(pinValidator, keyPair, publicKey))
                .register((byte) 0x21, new KeyCommandHandler(pinValidator, keyPair, publicKey))
                .register((byte) 0x22, new SignCommandHandler(pinValidator, privateKey, ecdsaSignature))
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
