package com.chainora.client.wallet;

import com.chainora.client.wallet.BalanceService.Provider;
import com.chainora.client.wallet.TransactionService.Network;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Service for loading and saving wallet configuration.
 */
public class ConfigService {
    private static final String CONFIG_DIR = ".chainora";
    private static final String CONFIG_FILE = "config.properties";

    private final BalanceService balanceService;
    private final TransactionService transactionService;

    private Provider balanceProvider;
    private Network activeNetwork;

    public ConfigService(BalanceService balanceService, TransactionService transactionService) {
        this.balanceService = balanceService;
        this.transactionService = transactionService;
    }

    /**
     * Loads the configuration from file.
     *
     * @return the loaded configuration
     */
    public WalletConfig load() {
        WalletConfig config = new WalletConfig();
        Path configPath = getConfigPath();

        if (!Files.exists(configPath)) {
            // Use defaults if config doesn't exist
            config.balanceProvider = Provider.BLOCKCYPHER;
            config.activeNetwork = Network.MAINNET;
            return config;
        }

        Properties props = new Properties();
        try (BufferedReader reader = new BufferedReader(new FileReader(configPath.toFile()))) {
            props.load(reader);

            String balanceProviderStr = props.getProperty("balanceProvider", "BLOCKCYPHER");
            try {
                config.balanceProvider = Provider.valueOf(balanceProviderStr);
            } catch (IllegalArgumentException e) {
                config.balanceProvider = Provider.BLOCKCYPHER;
            }

            String networkStr = props.getProperty("activeNetwork", "MAINNET");
            try {
                config.activeNetwork = Network.valueOf(networkStr);
            } catch (IllegalArgumentException e) {
                config.activeNetwork = Network.MAINNET;
            }
        } catch (IOException e) {
            System.out.println("Failed to load config: " + e.getMessage());
            config.balanceProvider = Provider.BLOCKCYPHER;
            config.activeNetwork = Network.MAINNET;
        }

        return config;
    }

    /**
     * Saves the configuration to file.
     *
     * @param config the configuration to save
     */
    public void save(WalletConfig config) {
        Path configDir = getConfigDir();
        try {
            Files.createDirectories(configDir);
        } catch (IOException e) {
            System.out.println("Failed to create config directory: " + e.getMessage());
            return;
        }

        Properties props = new Properties();
        // Use defaults if values are null
        Provider bp = config.balanceProvider != null ? config.balanceProvider : Provider.BLOCKCYPHER;
        Network an = config.activeNetwork != null ? config.activeNetwork : Network.MAINNET;
        props.setProperty("balanceProvider", bp.name());
        props.setProperty("activeNetwork", an.name());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(getConfigPath().toFile()))) {
            props.store(writer, "Chainora Wallet Configuration");
        } catch (IOException e) {
            System.out.println("Failed to save config: " + e.getMessage());
        }
    }

    /**
     * Gets the current balance provider.
     */
    public Provider getBalanceProvider() {
        return balanceProvider;
    }

    /**
     * Sets the current balance provider and saves.
     */
    public void setBalanceProvider(Provider provider) {
        this.balanceProvider = provider;
        save(new WalletConfig(provider, activeNetwork));
    }

    /**
     * Gets the current transaction network.
     */
    public Network getActiveNetwork() {
        return activeNetwork;
    }

    /**
     * Sets the current transaction network and saves.
     */
    public void setActiveNetwork(Network network) {
        this.activeNetwork = network;
        save(new WalletConfig(balanceProvider, network));
    }

    private Path getConfigDir() {
        String userHome = System.getProperty("user.home");
        return Paths.get(userHome, CONFIG_DIR);
    }

    private Path getConfigPath() {
        return getConfigPath(getConfigDir());
    }

    private Path getConfigPath(Path dir) {
        return dir.resolve(CONFIG_FILE);
    }

    /**
     * Wallet configuration data class.
     */
    public static class WalletConfig {
        public Provider balanceProvider;
        public Network activeNetwork;

        public WalletConfig() {
        }

        public WalletConfig(Provider balanceProvider, Network activeNetwork) {
            this.balanceProvider = balanceProvider;
            this.activeNetwork = activeNetwork;
        }
    }
}
