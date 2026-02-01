package com.chainora.client;

import com.chainora.client.wallet.BalanceService.Provider;
import com.chainora.client.wallet.TransactionService.Network;

/**
 * Persisted wallet configuration.
 * This class is kept for backward compatibility; ConfigService now handles loading/saving.
 */
public class WalletConfig {
    public Provider balanceProvider = Provider.BLOCKCYPHER;
    public Network activeNetwork = Network.MAINNET;

    public WalletConfig() {
    }

    public WalletConfig(Provider balanceProvider, Network activeNetwork) {
        this.balanceProvider = balanceProvider;
        this.activeNetwork = activeNetwork;
    }
}
