package com.chainora.client.wallet;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Arrays;

import javax.smartcardio.CardException;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.RunConfig;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;

import com.chainora.client.apdu.CardClient;
import com.chainora.client.apdu.CardOperationException;
import com.chainora.client.ui.ConsoleUI;
import com.chainora.client.wallet.BalanceService.Provider;
import com.chainora.client.wallet.TransactionService.Network;
import com.chainora.client.wallet.crypto.SignatureBuilder;

/**
 * Main wallet business logic service.
 * Orchestrates card operations, balance fetching, and transaction signing.
 */
public class WalletService {
    private static final int SW_RECORD_NOT_FOUND = 0x6A83;
    private static final int SW_SECURITY_NOT_SATISFIED = 0x6982;
    private static final int SW_CONDITIONS_NOT_SATISFIED = 0x6985;

    private final CardClient card;
    private final CardManager cardManager;
    private final RunConfig runConfig;
    private final BalanceService balanceService;
    private final TransactionService transactionService;
    private final SignatureBuilder signatureBuilder;
    private final ConfigService configService;

    private boolean loggedIn;
    private byte[] loggedInPublicKey;

    public WalletService(CardClient card, CardManager cardManager, RunConfig runConfig, BalanceService balanceService,
            TransactionService transactionService, SignatureBuilder signatureBuilder,
            ConfigService configService) {
        this.card = card;
        this.cardManager = cardManager;
        this.runConfig = runConfig;
        this.balanceService = balanceService;
        this.transactionService = transactionService;
        this.signatureBuilder = signatureBuilder;
        this.configService = configService;
        this.loggedIn = false;
        this.loggedInPublicKey = null;
    }

    /**
     * Initializes a new wallet with PIN and key generation.
     *
     * @param ui the UI for prompts
     */
    public void initWallet(ConsoleUI ui) {
        activateWallet(ui);
    }

    /**
     * Activates a new wallet and automatically opens a login session.
     *
     * @param ui the UI for prompts
     * @return true if activation and auto-login succeed
     */
    public boolean activateWallet(ConsoleUI ui) {
        try {
            reconnectCard();

            if (isWalletReady()) {
                ui.showError("Wallet is already activated. Please use Login.");
                return false;
            }

            ui.showInfo("Activating wallet...");

            byte[] pin = ui.promptPin4Digits("Enter new PIN (4 digits): ");
            byte[] pinConfirm = ui.promptPin4Digits("Confirm PIN: ");

            if (!Arrays.equals(pin, pinConfirm)) {
                ui.showError("PINs do not match. Wallet activation cancelled.");
                clearLoginState();
                return false;
            }

            card.setupWallet(pin);
            ui.showInfo("Wallet activated successfully!");

            byte[] publicKey = card.getPublicKey();
            String address = deriveAddress(publicKey);
            ui.showInfo("Wallet address: " + address);
            markLoggedIn(publicKey);
            ui.showInfo("Logged in successfully.");
            return true;
        } catch (Exception e) {
            clearLoginState();
            ui.showError("Failed to activate wallet: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verifies the PIN and opens a login session.
     *
     * @param ui the UI for prompts
     * @return true if login succeeds
     */
    public boolean login(ConsoleUI ui) {
        try {
            reconnectCard();

            if (!isWalletReady()) {
                ui.showError("Wallet is not activated. Please activate first.");
                clearLoginState();
                return false;
            }

            byte[] pin = ui.promptPin4Digits("Enter PIN to login: ");
            if (!card.verifyPin(pin)) {
                ui.showError("Invalid PIN.");
                clearLoginState();
                return false;
            }

            byte[] publicKey = card.getPublicKey();
            markLoggedIn(publicKey);
            ui.showInfo("Login successful.");
            return true;
        } catch (Exception e) {
            clearLoginState();
            ui.showError("Login failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Clears local login session and reconnects to reset card validation state.
     */
    public void logout() {
        clearLoginState();
        try {
            reconnectCard();
        } catch (Exception ignored) {
            // Local session is already cleared.
        }
    }

    /**
     * Returns true when client is currently logged in.
     */
    public boolean isLoggedIn() {
        return loggedIn;
    }

    /**
     * Re-validates current login session against the connected card.
     * Returns false and clears local session when card state changed.
     */
    public boolean refreshLoginSession() {
        if (!loggedIn) {
            return false;
        }
        try {
            byte[] currentPublicKey = card.getPublicKey();
            if (!isSamePublicKey(loggedInPublicKey, currentPublicKey)) {
                clearLoginState();
                return false;
            }
            return true;
        } catch (Exception e) {
            clearLoginState();
            return false;
        }
    }

    /**
     * Views wallet information including address and balance.
     *
     * @param ui the UI for display
     * @return the wallet info, or null if unavailable
     */
    public WalletInfo viewWallet(ConsoleUI ui) {
        if (!requireLoggedInSession(ui)) {
            return null;
        }

        try {
            byte[] publicKey = card.getPublicKey();
            String address = deriveAddress(publicKey);

            Provider provider = configService.getBalanceProvider();
            BigDecimal balance = balanceService.fetch(provider, address);

            ui.showWallet(address, balance);
            return new WalletInfo(address, balance);
        } catch (Exception e) {
            ui.showError("Failed to view wallet: " + e.getMessage());
            return null;
        }
    }

    /**
     * Updates the wallet PIN.
     *
     * @param ui the UI for prompts
     */
    public void updatePin(ConsoleUI ui) {
        if (!requireLoggedInSession(ui)) {
            return;
        }

        try {
            byte[][] pins = ui.promptUpdatePin();
            if (pins == null) {
                return;
            }

            byte[] currentPin = pins[0];
            byte[] newPin = pins[1];

            card.updatePin(currentPin, newPin);
            ui.showInfo("PIN updated successfully!");
        } catch (CardOperationException e) {
            if (isSessionFailureStatus(e.getSw())) {
                clearLoginState();
                ui.showError("PIN update failed: session expired. Please login again.");
                return;
            }
            ui.showError("Failed to update PIN: " + e.getMessage());
        } catch (Exception e) {
            ui.showError("Failed to update PIN: " + e.getMessage());
        }
    }

    /**
     * Backs up wallet key material from source card to destination card.
     * Uses certificate-based mutual authentication + ECDH encrypted transfer.
     */
    public void backupWallet(ConsoleUI ui) {
        if (!requireLoggedInSession(ui)) {
            return;
        }

        try {
            ui.showInfo("Starting Chainora secure backup flow...");

            byte[] destinationPinFromInitialization = null;

            ui.promptCardSwap("Insert destination backup card and press Enter.");
            reconnectCard();
            card.clearBackupLinkState();
            destinationPinFromInitialization = ensureDestinationPinInitialized(ui);
            byte[] destinationCert = ensureDeviceCertificateInstalled("destination");
            byte[] destinationLinkProof = card.startBackupLinkProof();

            ui.promptCardSwap("Insert source card and press Enter.");
            reconnectCard();
            card.clearBackupLinkState();
            ensurePinInitialized("source");
            byte[] sourceCert = ensureDeviceCertificateInstalled("source");
            byte[] sourceLinkProof = card.startBackupLinkProof();
            card.loadBackupPeerCertificate(destinationCert);
            card.loadBackupPeerLinkProof(destinationLinkProof);

            byte[] sourcePin = ui.promptPin4Digits("Enter source card PIN: ");
            if (!card.verifyPin(sourcePin)) {
                ui.showError("Invalid source PIN. Backup cancelled.");
                return;
            }

            byte[] sourcePublicKey = card.getPublicKey();
            byte[] backupEnvelope = card.exportBackupEnvelope();

            ui.promptCardSwap("Reinsert destination backup card and press Enter.");
            reconnectCard();
            card.loadBackupPeerCertificate(sourceCert);
            card.loadBackupPeerLinkProof(sourceLinkProof);

            byte[] destinationPin = destinationPinFromInitialization != null
                    ? destinationPinFromInitialization
                    : ui.promptPin4Digits("Enter destination card PIN: ");
            if (!card.verifyPin(destinationPin)) {
                ui.showError("Invalid destination PIN. Backup cancelled.");
                return;
            }

            card.importBackupEnvelope(backupEnvelope);
            byte[] importedPublicKey = card.getPublicKey();
            if (!isSamePublicKey(sourcePublicKey, importedPublicKey)) {
                throw new IllegalStateException("Imported key does not match source key.");
            }

            card.clearBackupLinkState();
            ui.showInfo("Backup completed successfully.");
            ui.showInfo("Destination card now contains the same wallet key as source card.");
        } catch (Exception e) {
            ui.showError("Backup failed: " + e.getMessage());
        } finally {
            clearLoginState();
            ui.showInfo("Backup flow closed the login session. Please login again.");
        }
    }

    private byte[] ensureDestinationPinInitialized(ConsoleUI ui) throws CardException {
        if (card.isPinInitialized()) {
            return null;
        }

        ui.showInfo("Destination card PIN is not initialized. Creating PIN now...");
        byte[] newPin = ui.promptPin4Digits("Set destination card PIN (4 digits): ");
        byte[] confirmPin = ui.promptPin4Digits("Confirm destination card PIN: ");
        if (!Arrays.equals(newPin, confirmPin)) {
            throw new IllegalStateException("Destination PINs do not match.");
        }

        card.initPin(newPin);
        ui.showInfo("Destination PIN initialized.");
        return newPin;
    }

    /**
     * Sends ETH to a recipient.
     *
     * @param ui the UI for prompts
     */
    public void sendEth(ConsoleUI ui) {
        if (!requireLoggedInSession(ui)) {
            return;
        }

        try {
            Network network = configService.getActiveNetwork();
            String recipient = ui.promptAddress();
            BigDecimal amount = ui.promptEthAmount();
            byte[] pin = ui.promptPin4Digits("Enter PIN to confirm transaction: ");

            // Verify PIN
            if (!card.verifyPin(pin)) {
                clearLoginState();
                ui.showError("Invalid PIN. Transaction cancelled. Please login again.");
                return;
            }

            // Get public key and derive sender address
            byte[] publicKey = card.getPublicKey();
            String senderAddress = deriveAddress(publicKey);

            // Fetch transaction parameters
            BigInteger nonce = transactionService.fetchNonce(network, senderAddress);
            BigInteger gasPrice = transactionService.fetchGasPrice(network);
            BigInteger valueWei = transactionService.toWei(amount);
            BigInteger balanceWei = transactionService.fetchBalanceWei(network, senderAddress);

            if (balanceWei == null) {
                ui.showError("Unable to verify on-chain balance. Transaction cancelled.");
                return;
            }

            // Check sufficient balance
            BigInteger requiredWei = valueWei.add(gasPrice.multiply(TransactionService.DEFAULT_GAS_LIMIT));
            if (balanceWei.compareTo(requiredWei) < 0) {
                ui.showError(String.format(
                        "Insufficient funds. Balance: %s ETH, required: %s ETH.",
                        formatWei(balanceWei), formatWei(requiredWei)));
                return;
            }

            // Create and sign transaction
            RawTransaction tx = transactionService.createEthTransaction(
                    recipient, valueWei, nonce, gasPrice, network);

            byte[] unsignedTx = transactionService.encodeTransaction(tx, network.chainId);
            byte[] hashToSign = TransactionService.keccak256(unsignedTx);

            byte[] derSignature = card.signTransaction(hashToSign);
            Sign.SignatureData signature = signatureBuilder.build(derSignature, hashToSign, publicKey, network.chainId);

            byte[] signedPayload = transactionService.encodeSignedTransaction(tx, signature, network.chainId);
            String rawTxHex = "0x" + TransactionService.toHex(signedPayload);

            // Broadcast transaction
            ui.showInfo("Broadcasting transaction on " + network.displayName + "...");
            String txHash = transactionService.send(network, rawTxHex);
            ui.showTransactionSent(txHash);
        } catch (CardOperationException e) {
            if (isSessionFailureStatus(e.getSw())) {
                clearLoginState();
                ui.showError("Transaction failed: session expired. Please login again.");
                return;
            }
            ui.showError("Transaction failed: " + e.getMessage());
        } catch (Exception e) {
            ui.showError("Transaction failed: " + e.getMessage());
        }
    }

    /**
     * Checks if the wallet is ready (PIN initialized and key generated).
     */
    public boolean isWalletReady() {
        return card.isWalletReady();
    }

    /**
     * Gets the wallet address if ready.
     *
     * @return the address or null if not ready
     */
    public String getAddress() {
        try {
            if (card.keyExists()) {
                return deriveAddress(card.getPublicKey());
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    private boolean requireLoggedInSession(ConsoleUI ui) {
        if (!loggedIn) {
            ui.showError("Please login first.");
            return false;
        }
        if (!refreshLoginSession()) {
            ui.showError("Login session expired or card changed. Please login again.");
            return false;
        }
        return true;
    }

    private void markLoggedIn(byte[] publicKey) {
        loggedInPublicKey = normalizePublicKey(publicKey);
        loggedIn = true;
    }

    private void clearLoginState() {
        loggedIn = false;
        loggedInPublicKey = null;
    }

    private boolean isSessionFailureStatus(int sw) {
        return sw == SW_SECURITY_NOT_SATISFIED || sw == SW_CONDITIONS_NOT_SATISFIED;
    }

    private void ensurePinInitialized(String cardRole) throws CardException {
        if (!card.isPinInitialized()) {
            throw new IllegalStateException("PIN is not initialized on " + cardRole + " card.");
        }
    }

    private byte[] ensureDeviceCertificateInstalled(String cardRole) throws CardException {
        try {
            return card.getDeviceCertificate();
        } catch (CardOperationException ex) {
            if (ex.getSw() != SW_RECORD_NOT_FOUND) {
                throw ex;
            }
            throw new IllegalStateException(
                    "Device certificate is missing on " + cardRole + " card. Reinstall applet to provision certificate.");
        }
    }

    private void reconnectCard() throws CardException {
        try {
            cardManager.disconnect(false);
        } catch (CardException ignored) {
            // Card can already be disconnected during swap.
        }
        if (!cardManager.connect(runConfig)) {
            throw new IllegalStateException("Cannot connect to selected card.");
        }
    }

    private boolean isSamePublicKey(byte[] left, byte[] right) {
        return Arrays.equals(normalizePublicKey(left), normalizePublicKey(right));
    }

    private byte[] normalizePublicKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length < 64) {
            throw new IllegalArgumentException("Invalid public key");
        }
        int offset = publicKey.length == 65 ? 1 : 0;
        return Arrays.copyOfRange(publicKey, offset, publicKey.length);
    }

    private String deriveAddress(byte[] publicKey) {
        if (publicKey == null || publicKey.length < 64) {
            throw new IllegalArgumentException("Invalid public key");
        }
        int offset = publicKey.length == 65 ? 1 : 0;
        byte[] xy = Arrays.copyOfRange(publicKey, offset, publicKey.length);
        byte[] hash = TransactionService.keccak256(xy);
        byte[] addressBytes = Arrays.copyOfRange(hash, hash.length - 20, hash.length);
        return toChecksumAddress(addressBytes);
    }

    private String toChecksumAddress(byte[] addressBytes) {
        String hex = TransactionService.toHex(addressBytes).toLowerCase();
        byte[] hash = TransactionService.keccak256(hex.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        StringBuilder builder = new StringBuilder("0x");
        for (int i = 0; i < hex.length(); i++) {
            char ch = hex.charAt(i);
            int hashByte = hash[i / 2] & 0xFF;
            int nibble = (i % 2 == 0) ? (hashByte >>> 4) : (hashByte & 0x0F);
            if (Character.isLetter(ch) && nibble >= 8) {
                builder.append(Character.toUpperCase(ch));
            } else {
                builder.append(ch);
            }
        }
        return builder.toString();
    }

    private String formatWei(BigInteger wei) {
        return new BigDecimal(wei)
                .divide(new BigDecimal("1000000000000000000"), 18, RoundingMode.DOWN)
                .stripTrailingZeros()
                .toPlainString();
    }

    /**
     * Wallet information data class.
     */
    public static class WalletInfo {
        public final String address;
        public final BigDecimal balance;

        public WalletInfo(String address, BigDecimal balance) {
            this.address = address;
            this.balance = balance;
        }
    }
}
