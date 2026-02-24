package com.chainora.client.ui;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Scanner;

import com.chainora.client.wallet.BalanceService;
import com.chainora.client.wallet.TransactionService;

/**
 * Centralized UI handling for all console prompts and user interactions.
 * Eliminates duplication of input validation and formatting logic.
 */
public class ConsoleUI {
    private static final int ETH_ADDRESS_LENGTH = 40;
    private static final String MAINNET_RPC = "https://cloudflare-eth.com";
    private static final String HARDHAT_RPC = "http://127.0.0.1:8545";

    private final Scanner scanner;

    public ConsoleUI(Scanner scanner) {
        this.scanner = scanner;
    }

    /**
     * Prompts the user for a PIN.
     *
     * @param label the prompt label
     * @param exactLength if true, requires exactly 4 digits; otherwise accepts 4-16 digits
     * @return the PIN bytes
     */
    public byte[] promptPin(String label, boolean exactLength) {
        while (true) {
            System.out.print(label);
            String pin = scanner.nextLine().trim();
            if (exactLength) {
                if (!pin.matches("\\d{4}")) {
                    System.out.println("PIN must contain exactly 4 digits.");
                    continue;
                }
            } else {
                if (pin.isEmpty()) {
                    System.out.println("PIN must not be empty.");
                    continue;
                }
                byte[] bytes = pin.getBytes(StandardCharsets.UTF_8);
                if (bytes.length > 16) {
                    System.out.println("PIN must be at most 16 bytes.");
                    continue;
                }
            }
            return pin.getBytes(StandardCharsets.UTF_8);
        }
    }

    /**
     * Prompts for a PIN with exactly 4 digits.
     */
    public byte[] promptPin4Digits(String label) {
        return promptPin(label, true);
    }

    /**
     * Prompts for current PIN and new PIN for update.
     *
     * @return array of [currentPin, newPin] or null if cancelled
     */
    public byte[][] promptUpdatePin() {
        byte[] currentPin = promptPin4Digits("Enter current PIN: ");
        byte[] newPin = promptPin4Digits("Enter new PIN (4 digits): ");
        byte[] newPinConfirm = promptPin4Digits("Confirm new PIN: ");

        if (!Arrays.equals(newPin, newPinConfirm)) {
            showError("New PINs do not match. PIN update cancelled.");
            return null;
        }

        if (Arrays.equals(currentPin, newPin)) {
            showError("New PIN must be different from current PIN.");
            return null;
        }

        return new byte[][]{currentPin, newPin};
    }

    /**
     * Prompts for an Ethereum address.
     *
     * @return the checksum address with 0x prefix
     */
    public String promptAddress() {
        while (true) {
            System.out.print("Enter recipient address (0x...): ");
            String input = scanner.nextLine().trim();
            if (input.isEmpty()) {
                System.out.println("Address must not be empty.");
                continue;
            }
            // Remove 0x prefix if present
            if (input.startsWith("0x") || input.startsWith("0X")) {
                input = input.substring(2);
            }
            if (input.length() != ETH_ADDRESS_LENGTH || !input.matches("[0-9a-fA-F]+")) {
                System.out.println("Address must contain exactly 40 hex characters.");
                continue;
            }
            return toChecksumAddress(input);
        }
    }

    /**
     * Prompts for an ETH amount.
     *
     * @return the amount with 18 decimal places
     */
    public BigDecimal promptEthAmount() {
        while (true) {
            System.out.print("Enter amount in ETH: ");
            String line = scanner.nextLine().trim();
            try {
                BigDecimal value = new BigDecimal(line);
                if (value.compareTo(BigDecimal.ZERO) <= 0) {
                    System.out.println("Amount must be greater than 0.");
                    continue;
                }
                return value.setScale(18, RoundingMode.DOWN);
            } catch (NumberFormatException ex) {
                System.out.println("Invalid value. Please enter a number.");
            }
        }
    }

    /**
     * Prompts to select the transaction network.
     *
     * @return the selected network
     */
    public TransactionService.Network promptNetwork() {
        while (true) {
            System.out.println();
            System.out.println("Select transaction network:");
            System.out.println("1 - Ethereum mainnet (" + MAINNET_RPC + ")");
            System.out.println("2 - Hardhat local node (" + HARDHAT_RPC + ")");
            System.out.print("Enter 1-2: ");
            String choice = scanner.nextLine().trim();
            if ("1".equals(choice)) {
                return TransactionService.Network.MAINNET;
            }
            if ("2".equals(choice)) {
                return TransactionService.Network.HARDHAT;
            }
            System.out.println("Invalid choice. Please enter 1 or 2.");
        }
    }

    /**
     * Prompts to select the balance provider.
     *
     * @return the selected provider
     */
    public BalanceService.Provider promptBalanceProvider() {
        while (true) {
            System.out.println();
            System.out.println("Select balance source:");
            System.out.println("1 - BlockCypher (Ethereum mainnet)");
            System.out.println("2 - Hardhat local node");
            System.out.print("Enter 1-2: ");
            String choice = scanner.nextLine().trim();
            if ("1".equals(choice)) {
                return BalanceService.Provider.BLOCKCYPHER;
            }
            if ("2".equals(choice)) {
                return BalanceService.Provider.HARDHAT;
            }
            System.out.println("Invalid choice. Please enter 1 or 2.");
        }
    }

    /**
     * Prompts for a menu choice.
     *
     * @param min minimum choice value
     * @param max maximum choice value
     * @return the selected choice
     */
    public int promptChoice(int min, int max) {
        while (true) {
            String input = scanner.nextLine().trim();
            try {
                int value = Integer.parseInt(input);
                if (value >= min && value <= max) {
                    return value;
                }
            } catch (NumberFormatException ignored) {
            }
            System.out.printf("Please enter a number between %d and %d.%n", min, max);
        }
    }

    /**
     * Displays the wallet information.
     *
     * @param address the wallet address
     * @param balance the balance in ETH
     */
    public void showWallet(String address, BigDecimal balance) {
        System.out.println();
        System.out.println("=== WALLET INFO ===");
        System.out.println("Address: " + address);
        if (balance != null) {
            System.out.printf("Balance: %s ETH%n", balance.stripTrailingZeros().toPlainString());
        } else {
            System.out.println("Balance: Unable to fetch");
        }
    }

    /**
     * Displays transaction sent confirmation.
     *
     * @param txHash the transaction hash
     */
    public void showTransactionSent(String txHash) {
        System.out.println("Transaction sent successfully!");
        System.out.println("Hash: " + txHash);
    }

    /**
     * Shows a setup prompt for the main menu.
     *
     * @return the selected option
     */
    public int promptMainMenu() {
        System.out.println();
        System.out.println("CHAINORA WALLET");
        System.out.println("===============================================");
        System.out.println("1 - Init/Setup Wallet");
        System.out.println("2 - View Wallet");
        System.out.println("3 - Send ETH");
        System.out.println("4 - Update PIN");
        System.out.println("5 - Backup Wallet Key");
        System.out.println("6 - Settings");
        System.out.println("7 - Exit");
        System.out.println("===============================================");
        System.out.print("Enter 1-7: ");
        return promptChoice(1, 7);
    }

    /**
     * Prompts user to swap/insert a card and continue.
     *
     * @param message the card operation prompt
     */
    public void promptCardSwap(String message) {
        System.out.println();
        System.out.println(message);
        System.out.print("Press Enter when ready...");
        scanner.nextLine();
    }

    /**
     * Prompts user to confirm one-time certificate provisioning.
     *
     * @param cardRole destination/source label
     * @return true if user confirms provisioning
     */
    public boolean confirmDeviceProvisioning(String cardRole) {
        System.out.println();
        System.out.println("No device certificate found on " + cardRole + " card.");
        System.out.println("Provisioning is one-time and writes a development certificate.");
        System.out.print("Proceed with provisioning? (y/n): ");
        String input = scanner.nextLine().trim().toLowerCase();
        return "y".equals(input);
    }

    /**
     * Shows wallet not ready message and prompts for initialization.
     *
     * @return true if user wants to initialize
     */
    public boolean promptWalletNotReady() {
        System.out.println();
        System.out.println("Wallet is not initialized.");
        System.out.print("Would you like to initialize it now? (y/n): ");
        String input = scanner.nextLine().trim().toLowerCase();
        return "y".equals(input);
    }

    /**
     * Shows an error message.
     *
     * @param message the error message
     */
    public void showError(String message) {
        System.out.println("Error: " + message);
    }

    /**
     * Shows an info message.
     *
     * @param message the info message
     */
    public void showInfo(String message) {
        System.out.println(message);
    }

    /**
     * Clears the console screen using ANSI escape codes (cross-platform).
     */
    public void clearScreen() {
        System.out.print("\033[H\033[2J");
    }

    /**
     * Clears the screen and prints a section banner.
     *
     * @param title the banner title
     */
    public void showBanner(String title) {
        clearScreen();
        System.out.println();
        System.out.println("=== " + title + " ===");
        System.out.println();
    }

    /**
     * Pauses execution and waits for Enter key.
     */
    public void pause() {
        System.out.print("Press Enter to continue...");
        scanner.nextLine();
    }

    private String toChecksumAddress(String input) {
        String hex = input.toLowerCase(Locale.ROOT);
        byte[] hash = TransactionService.keccak256(hex.getBytes(StandardCharsets.US_ASCII));
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
}
