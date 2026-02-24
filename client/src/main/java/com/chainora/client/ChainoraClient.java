package com.chainora.client;

import java.util.Scanner;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.RunConfig;
import cz.muni.fi.crocs.rcard.client.Util;

import com.chainora.client.apdu.CardClient;
import com.chainora.client.ui.ConsoleUI;
import com.chainora.client.wallet.BalanceService;
import com.chainora.client.wallet.ConfigService;
import com.chainora.client.wallet.TransactionService;
import com.chainora.client.wallet.WalletService;
import com.chainora.client.wallet.crypto.SignatureBuilder;

/**
 * Main entry point for the Chainora wallet CLI.
 * Provides a modular, user-friendly interface for Ethereum wallet operations.
 */
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

            // Initialize services
            BalanceService balanceService = new BalanceService();
            TransactionService transactionService = new TransactionService();
            SignatureBuilder signatureBuilder = new SignatureBuilder();
            ConfigService configService = new ConfigService(balanceService, transactionService);
            CardClient cardClient = new CardClient(cardManager);
            WalletService walletService = new WalletService(
                    cardClient, cardManager, config, balanceService, transactionService,
                    signatureBuilder, configService);
            ConsoleUI ui = new ConsoleUI(scanner);

            // Load saved config
            ConfigService.WalletConfig configData = configService.load();
            configService.setBalanceProvider(configData.balanceProvider);
            configService.setActiveNetwork(configData.activeNetwork);

            runCli(ui, walletService, configService);
            System.out.println("Goodbye!");
        } catch (Exception e) {
            System.err.println("Chainora client failed: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void runCli(ConsoleUI ui, WalletService walletService, ConfigService configService) {
        boolean exit = false;
        while (!exit) {
            if (walletService.isLoggedIn() && !walletService.refreshLoginSession()) {
                ui.showError("Login session expired or card changed. Please login again.");
            }

            if (!walletService.isLoggedIn()) {
                int guestChoice = ui.promptGuestMenu();
                switch (guestChoice) {
                    case 1:
                        handleLogin(ui, walletService);
                        break;
                    case 2:
                        handleActivateWallet(ui, walletService);
                        break;
                    case 3:
                        exit = true;
                        break;
                    default:
                        break;
                }
                continue;
            }

            int choice = ui.promptWalletMenu();
            switch (choice) {
                case 1:
                    handleViewWallet(ui, walletService);
                    break;
                case 2:
                    handleSendEth(ui, walletService);
                    break;
                case 3:
                    handleUpdatePin(ui, walletService);
                    break;
                case 4:
                    handleBackupWallet(ui, walletService);
                    break;
                case 5:
                    handleSettings(ui, configService);
                    break;
                case 6:
                    handleLogout(ui, walletService);
                    break;
                case 7:
                    exit = true;
                    break;
                default:
                    break;
            }
        }
    }

    private static void handleActivateWallet(ConsoleUI ui, WalletService walletService) {
        ui.showBanner("ACTIVATE WALLET");
        walletService.activateWallet(ui);
        ui.pause();
    }

    private static void handleLogin(ConsoleUI ui, WalletService walletService) {
        ui.showBanner("LOGIN");
        walletService.login(ui);
        ui.pause();
    }

    private static void handleLogout(ConsoleUI ui, WalletService walletService) {
        ui.showBanner("LOGOUT");
        walletService.logout();
        ui.showInfo("Logged out.");
        ui.pause();
    }

    private static void handleViewWallet(ConsoleUI ui, WalletService walletService) {
        ui.showBanner("VIEW WALLET");
        walletService.viewWallet(ui);
        ui.pause();
    }

    private static void handleSendEth(ConsoleUI ui, WalletService walletService) {
        ui.showBanner("SEND ETH");
        walletService.sendEth(ui);
        ui.pause();
    }

    private static void handleUpdatePin(ConsoleUI ui, WalletService walletService) {
        ui.showBanner("UPDATE PIN");
        walletService.updatePin(ui);
        ui.pause();
    }

    private static void handleBackupWallet(ConsoleUI ui, WalletService walletService) {
        ui.showBanner("BACKUP WALLET");
        walletService.backupWallet(ui);
        ui.pause();
    }

    private static void handleSettings(ConsoleUI ui, ConfigService configService) {
        ui.showBanner("SETTINGS");
        System.out.println("1 - Change balance provider");
        System.out.println("2 - Change network");
        System.out.println("3 - Back");
        System.out.print("Enter 1-3: ");

        int choice = ui.promptChoice(1, 3);
        switch (choice) {
            case 1:
                configService.setBalanceProvider(ui.promptBalanceProvider());
                ui.showInfo("Balance provider updated.");
                break;
            case 2:
                configService.setActiveNetwork(ui.promptNetwork());
                ui.showInfo("Network updated.");
                break;
            case 3:
                // Back
                break;
        }
    }

    private static void connect(CardManager cardManager, RunConfig config) throws Exception {
        System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
        System.setProperty("com.licel.jcardsim.sign.dsasigner.computedhash", "1");
        if (!cardManager.connect(config)) {
            throw new IllegalStateException("Cannot connect to card");
        }
    }

    private static RunConfig prepareRunConfig(CardType cardType) {
        RunConfig config = RunConfig.getDefaultConfig();
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
