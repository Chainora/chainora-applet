import java.nio.charset.StandardCharsets;
import java.util.Scanner;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.RunConfig;
import cz.muni.fi.crocs.rcard.client.Util;

import javax.smartcardio.CardException;

public class ChainoraClient {
    private static final String APPLET_AID = "f0564e43485701";
    private static final byte[] APPLET_AID_BYTES = Util.hexStringToByteArray(APPLET_AID);

    public static void main(String[] args) {
        printBanner();

        try (Scanner scanner = new Scanner(System.in)) {
            // Change CardType here to switch between physical and simulated cards
            final CardType cardType = CardType.PHYSICAL;

            final CardManager cardManager = new CardManager(true, APPLET_AID_BYTES);
            final RunConfig config = prepareRunConfig(cardType);

            connect(cardManager, config);

            final PinManager pinManager = new PinManager(cardManager);
            final KeyManager keyManager = new KeyManager(cardManager);
            final WalletManager walletManager = new WalletManager(cardManager);

            runCli(scanner, pinManager, keyManager, walletManager);
            System.out.println("Goodbye!");
        } catch (Exception e) {
            System.err.println("Chainora client failed: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void runCli(Scanner scanner, PinManager pinManager, KeyManager keyManager,
            WalletManager walletManager)
            throws CardException {
        boolean exit = false;
        while (!exit) {
            System.out.println();
            System.out.println("CHAINORA CLIENT READY");
            System.out.println("===============================================");
            System.out.println("SELECT COMMAND GROUP:");
            System.out.println("1 - PIN Management");
            System.out.println("2 - Key Management");
            System.out.println("3 - Wallet Operations");
            System.out.println("4 - Exit");
            System.out.println("===============================================");
            System.out.print("Enter 1-4: ");

            final int choice = readChoice(scanner, 1, 4);
            switch (choice) {
                case 1:
                    handlePinMenu(scanner, pinManager);
                    break;
                case 2:
                    handleKeyMenu(scanner, keyManager);
                    break;
                case 3:
                    handleWalletMenu(walletManager);
                    break;
                case 4:
                    exit = true;
                    break;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    private static void handlePinMenu(Scanner scanner, PinManager pinManager) throws CardException {
        boolean back = false;
        while (!back) {
            System.out.println();
            System.out.println("--- PIN MANAGEMENT ---");
            System.out.println("1 - Check if PIN initialized");
            System.out.println("2 - Initialize PIN");
            System.out.println("3 - Verify PIN");
            System.out.println("4 - Update PIN (requires previous verify)");
            System.out.println("5 - Reset PIN");
            System.out.println("6 - Back");
            System.out.print("Enter 1-6: ");

            final int choice = readChoice(scanner, 1, 6);
            switch (choice) {
                case 1:
                    pinManager.printPinState();
                    break;
                case 2:
                    pinManager.initPin(promptPin(scanner, "Enter new PIN: "));
                    break;
                case 3:
                    pinManager.verifyPin(promptPin(scanner, "Enter PIN to verify: "));
                    break;
                case 4:
                    System.out.println("(Requires successful VERIFY beforehand)");
                    pinManager.updatePin(promptPin(scanner, "Enter new PIN: "));
                    break;
                case 5:
                    pinManager.resetPin();
                    break;
                case 6:
                    back = true;
                    break;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    private static void handleKeyMenu(Scanner scanner, KeyManager keyManager) throws CardException {
        boolean back = false;
        while (!back) {
            System.out.println();
            System.out.println("--- KEY MANAGEMENT ---");
            System.out.println("1 - Generate key pair");
            System.out.println("2 - Fetch public key");
            System.out.println("3 - Back");
            System.out.print("Enter 1-3: ");

            final int choice = readChoice(scanner, 1, 3);
            switch (choice) {
                case 1:
                    keyManager.generateKeyPair();
                    break;
                case 2:
                    keyManager.printPublicKey();
                    break;
                case 3:
                    back = true;
                    break;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    private static void handleWalletMenu(WalletManager walletManager) {
        walletManager.printComingSoon();
    }

    private static byte[] promptPin(Scanner scanner, String label) {
        while (true) {
            System.out.print(label);
            final String pin = scanner.nextLine();
            if (pin == null || pin.isEmpty()) {
                System.out.println("PIN must not be empty.");
                continue;
            }
            final byte[] bytes = pin.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > 16) {
                System.out.println("PIN must be at most 16 bytes.");
                continue;
            }
            return bytes;
        }
    }

    private static int readChoice(Scanner scanner, int min, int max) {
        while (true) {
            final String input = scanner.nextLine().trim();
            try {
                final int value = Integer.parseInt(input);
                if (value >= min && value <= max) {
                    return value;
                }
            } catch (NumberFormatException ignored) {
            }
            System.out.printf("Please enter a number between %d and %d.%n", min, max);
        }
    }

    private static void connect(CardManager cardManager, RunConfig config) throws CardException {
        System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
        System.setProperty("com.licel.jcardsim.sign.dsasigner.computedhash", "1");
        if (!cardManager.connect(config)) {
            throw new IllegalStateException("Không thể kết nối tới thẻ");
        }
    }

    private static RunConfig prepareRunConfig(CardType cardType) {
        final RunConfig config = RunConfig.getDefaultConfig();
        config.setTestCardType(cardType);
        return config;
    }

    private static void printBanner() {
        System.out.println();
        System.out.println("  _______        _                      ________          __ ");
        System.out.println(" / ___/ /  ___ _(_)__  ___  _______ _  / ___/ (_)__ ___  / /_");
        System.out.println("/ /__/ _ \\ / _ `/ / _ \\ _ \\/ __/ _ `/ / /__/ / / -_) _ \\/ __/");
        System.out.println("\\___/_//_/\\_,_/_/_//_/\\___/_/  \\_,_/  \\___/_/_/\\__/_//_/\\__/ ");
        System.out.println();
    }
}
