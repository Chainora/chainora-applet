package com.chainora.client.apdu;

import javax.smartcardio.CardException;

import cz.muni.fi.crocs.rcard.client.CardManager;

/**
 * Facade providing a unified interface to all card operations.
 * Combines PIN, key, and signing operations into a wallet-focused API.
 */
public class CardClient {
    private final PinApdu pinApdu;
    private final KeyApdu keyApdu;
    private final SignApdu signApdu;
    private final DeviceCertificateApdu deviceCertificateApdu;
    private final CardAttestationApdu cardAttestationApdu;
    private final BackupApdu backupApdu;

    public CardClient(CardManager cardManager) {
        this.pinApdu = new PinApdu(cardManager);
        this.keyApdu = new KeyApdu(cardManager);
        this.signApdu = new SignApdu(cardManager);
        this.deviceCertificateApdu = new DeviceCertificateApdu(cardManager);
        this.cardAttestationApdu = new CardAttestationApdu(cardManager);
        this.backupApdu = new BackupApdu(cardManager);
    }

    /**
     * Checks if the wallet is ready (PIN initialized and key pair generated).
     *
     * @return true if wallet is fully initialized
     */
    public boolean isWalletReady() {
        try {
            return pinApdu.isInitialized() && keyExists();
        } catch (CardException e) {
            return false;
        }
    }

    /**
     * Checks if a key pair exists on the card.
     *
     * @return true if key pair exists
     */
    public boolean keyExists() {
        try {
            keyApdu.getPublicKey();
            return true;
        } catch (CardOperationException e) {
            // 0x6982 = Security condition not satisfied (PIN required) = key exists but needs validation
            // Other errors = key doesn't exist
            return e.getSw() == 0x6982;
        } catch (CardException e) {
            return false;
        }
    }

    /**
     * Sets up a new wallet: resets PIN and generates a new key pair.
     *
     * @param pin the initial PIN
     * @throws CardException if any operation fails
     */
    public void setupWallet(byte[] pin) throws CardException {
        pinApdu.init(pin);
        pinApdu.verify(pin);  // Verify PIN so key generation succeeds
        keyApdu.generateKeyPair();
    }

    /**
     * Verifies the PIN on the card.
     *
     * @param pin the PIN to verify
     * @return true if PIN is correct
     * @throws CardException if communication fails
     */
    public boolean verifyPin(byte[] pin) throws CardException {
        return pinApdu.verify(pin);
    }

    /**
     * Retrieves the public key from the card.
     *
     * @return the public key bytes
     * @throws CardException if communication fails
     */
    public byte[] getPublicKey() throws CardException {
        return keyApdu.getPublicKey();
    }

    /**
     * Generates a new key pair on the card.
     *
     * @throws CardException if communication fails
     */
    public void generateKeyPair() throws CardException {
        keyApdu.generateKeyPair();
    }

    /**
     * Signs a transaction hash with the card's private key.
     *
     * @param txHash the 32-byte transaction hash to sign
     * @return the DER-encoded signature
     * @throws CardException if communication fails
     */
    public byte[] signTransaction(byte[] txHash) throws CardException {
        return signApdu.signHash(txHash);
    }

    /**
     * Checks if PIN is initialized on the card.
     *
     * @return true if PIN is initialized
     * @throws CardException if communication fails
     */
    public boolean isPinInitialized() throws CardException {
        return pinApdu.isInitialized();
    }

    /**
     * Initializes the PIN on the card.
     *
     * @param pin the PIN to set
     * @throws CardException if communication fails
     */
    public void initPin(byte[] pin) throws CardException {
        pinApdu.init(pin);
    }

    /**
     * Resets the PIN on the card.
     *
     * @throws CardException if communication fails
     */
    public void resetPin() throws CardException {
        pinApdu.reset();
    }

    /**
     * Updates the PIN on the card.
     *
     * @param currentPin the current PIN
     * @param newPin the new PIN
     * @throws CardException if communication fails
     */
    public void updatePin(byte[] currentPin, byte[] newPin) throws CardException {
        pinApdu.update(currentPin, newPin);
    }

    public byte[] getDeviceCertificate() throws CardException {
        return deviceCertificateApdu.getDeviceCertificate();
    }

    public byte[] getFactoryCsr() throws CardException {
        return deviceCertificateApdu.getFactoryCsr();
    }

    public void setDeviceCertificate(byte[] certificate) throws CardException {
        deviceCertificateApdu.setDeviceCertificate(certificate);
    }

    public byte[] signBackendChallenge(byte[] challenge) throws CardException {
        return cardAttestationApdu.signChallenge(challenge);
    }

    /**
     * Starts a new backup link proof session and returns attestation payload.
     */
    public byte[] startBackupLinkProof() throws CardException {
        return backupApdu.startLinkProof();
    }

    /**
     * Loads and verifies the peer device certificate.
     */
    public void loadBackupPeerCertificate(byte[] peerCertificate) throws CardException {
        backupApdu.loadPeerCertificate(peerCertificate);
    }

    /**
     * Loads and verifies the peer link proof.
     */
    public void loadBackupPeerLinkProof(byte[] peerLinkProof) throws CardException {
        backupApdu.loadPeerLinkProof(peerLinkProof);
    }

    /**
     * Clears backup session state on the card.
     */
    public void clearBackupLinkState() throws CardException {
        backupApdu.clearLinkState();
    }

    /**
     * Exports encrypted wallet backup envelope.
     */
    public byte[] exportBackupEnvelope() throws CardException {
        return backupApdu.exportBackupEnvelope();
    }

    /**
     * Imports encrypted wallet backup envelope.
     */
    public void importBackupEnvelope(byte[] backupEnvelope) throws CardException {
        backupApdu.importBackupEnvelope(backupEnvelope);
    }
}
