package com.chainora.client.wallet;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Arrays;

import com.chainora.client.apdu.CardClient;
import com.chainora.client.ui.ConsoleUI;
import com.chainora.client.wallet.BalanceService.Provider;
import com.chainora.client.wallet.TransactionService.Network;
import com.chainora.client.wallet.crypto.SignatureBuilder;

import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;

/**
 * Main wallet business logic service.
 * Orchestrates card operations, balance fetching, and transaction signing.
 */
public class WalletService {
    private final CardClient card;
    private final BalanceService balanceService;
    private final TransactionService transactionService;
    private final SignatureBuilder signatureBuilder;
    private final ConfigService configService;

    public WalletService(CardClient card, BalanceService balanceService,
            TransactionService transactionService, SignatureBuilder signatureBuilder,
            ConfigService configService) {
        this.card = card;
        this.balanceService = balanceService;
        this.transactionService = transactionService;
        this.signatureBuilder = signatureBuilder;
        this.configService = configService;
    }

    /**
     * Initializes a new wallet with PIN and key generation.
     *
     * @param ui the UI for prompts
     */
    public void initWallet(ConsoleUI ui) {
        try {
            ui.showInfo("Initializing wallet...");

            byte[] pin = ui.promptPin4Digits("Enter new PIN (4 digits): ");
            byte[] pinConfirm = ui.promptPin4Digits("Confirm PIN: ");

            if (!Arrays.equals(pin, pinConfirm)) {
                ui.showError("PINs do not match. Wallet initialization cancelled.");
                return;
            }

            card.setupWallet(pin);
            ui.showInfo("Wallet initialized successfully!");

            // Verify the key was generated
            byte[] publicKey = card.getPublicKey();
            String address = deriveAddress(publicKey);
            ui.showInfo("Wallet address: " + address);
        } catch (Exception e) {
            ui.showError("Failed to initialize wallet: " + e.getMessage());
        }
    }

    /**
     * Views wallet information including address and balance.
     *
     * @param ui the UI for display
     * @return the wallet info, or null if unavailable
     */
    public WalletInfo viewWallet(ConsoleUI ui) {
        try {
            byte[] pin = ui.promptPin4Digits("Enter PIN to view wallet: ");
            if (!card.verifyPin(pin)) {
                ui.showError("Invalid PIN.");
                return null;
            }

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
        try {
            byte[][] pins = ui.promptUpdatePin();
            if (pins == null) {
                return;
            }

            byte[] currentPin = pins[0];
            byte[] newPin = pins[1];

            card.updatePin(currentPin, newPin);
            ui.showInfo("PIN updated successfully!");
        } catch (Exception e) {
            ui.showError("Failed to update PIN: " + e.getMessage());
        }
    }

    /**
     * Sends ETH to a recipient.
     *
     * @param ui the UI for prompts
     */
    public void sendEth(ConsoleUI ui) {
        try {
            Network network = configService.getActiveNetwork();
            String recipient = ui.promptAddress();
            BigDecimal amount = ui.promptEthAmount();
            byte[] pin = ui.promptPin4Digits("Enter PIN to confirm transaction: ");

            // Verify PIN
            if (!card.verifyPin(pin)) {
                ui.showError("Invalid PIN. Transaction cancelled.");
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
