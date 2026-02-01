package com.chainora.client.wallet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.utils.Numeric;

/**
 * Service for building and broadcasting Ethereum transactions.
 */
public class TransactionService {
    private static final String MAINNET_RPC = "https://cloudflare-eth.com";
    private static final String HARDHAT_RPC = "http://127.0.0.1:8545";
    private static final String BALANCE_ENDPOINT = "https://api.blockcypher.com/v1/eth/main/addrs/%s/balance";
    private static final BigDecimal WEI_IN_ETH = new BigDecimal("1000000000000000000");
    public static final BigInteger DEFAULT_GAS_LIMIT = BigInteger.valueOf(21_000);
    private static final BigInteger FALLBACK_GAS_PRICE = new BigInteger("2000000000");

    /**
     * Network options for transactions.
     */
    public enum Network {
        MAINNET("Ethereum mainnet", MAINNET_RPC, 1L),
        HARDHAT("Hardhat local node", HARDHAT_RPC, 31_337L);

        final String displayName;
        final String rpcEndpoint;
        final long chainId;

        Network(String displayName, String rpcEndpoint, long chainId) {
            this.displayName = displayName;
            this.rpcEndpoint = rpcEndpoint;
            this.chainId = chainId;
        }
    }

    /**
     * Creates an ETH transfer transaction.
     *
     * @param to recipient address
     * @param valueWei value in wei
     * @param nonce the transaction nonce
     * @param gasPrice the gas price in wei
     * @param network the network to use
     * @return the RawTransaction ready for signing
     */
    public RawTransaction createEthTransaction(String to, BigInteger valueWei,
            BigInteger nonce, BigInteger gasPrice, Network network) {
        return RawTransaction.createEtherTransaction(
                nonce, gasPrice, DEFAULT_GAS_LIMIT, to, valueWei);
    }

    /**
     * Sends a raw transaction to the network.
     *
     * @param network the network to broadcast on
     * @param rawTxHex the signed transaction as hex string
     * @return the transaction hash
     * @throws IOException if the request fails
     */
    public String send(Network network, String rawTxHex) throws IOException {
        String payload = String.format(Locale.US,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendRawTransaction\",\"params\":[\"%s\"],\"id\":1}",
                rawTxHex);
        String response = httpPost(network.rpcEndpoint, payload);
        String result = parseStringField(response, "result");
        if (result != null) {
            return result;
        }
        String error = parseErrorMessage(response);
        throw new IOException(error != null ? error : "RPC missing transaction hash.");
    }

    /**
     * Fetches the nonce (transaction count) for an address.
     *
     * @param network the network to query
     * @param address the address to check
     * @return the nonce
     * @throws IOException if the request fails
     */
    public BigInteger fetchNonce(Network network, String address) throws IOException {
        String payload = String.format(Locale.US,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionCount\",\"params\":[\"%s\",\"latest\"],\"id\":1}",
                address);
        String response = httpPost(network.rpcEndpoint, payload);
        String resultHex = parseStringField(response, "result");
        BigInteger nonce = hexToBigInteger(resultHex);
        if (nonce != null) {
            return nonce;
        }
        String error = parseErrorMessage(response);
        throw new IOException(error != null ? error : "RPC missing transaction count result.");
    }

    /**
     * Fetches the current gas price from the network.
     *
     * @param network the network to query
     * @return the gas price in wei, or fallback if unavailable
     */
    public BigInteger fetchGasPrice(Network network) {
        String payload = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}";
        try {
            String response = httpPost(network.rpcEndpoint, payload);
            String resultHex = parseStringField(response, "result");
            BigInteger gasPrice = hexToBigInteger(resultHex);
            if (gasPrice != null) {
                return gasPrice;
            }
            String error = parseErrorMessage(response);
            if (error != null) {
                System.out.println("Gas price RPC error: " + error + ". Using fallback value.");
            }
        } catch (IOException e) {
            System.out.println("Unable to fetch gas price: " + e.getMessage() + ". Using fallback value.");
        }
        return FALLBACK_GAS_PRICE;
    }

    /**
     * Fetches the balance in wei for an address.
     *
     * @param network the network to query
     * @param address the address to check
     * @return the balance in wei, or null if fetch failed
     */
    public BigInteger fetchBalanceWei(Network network, String address) {
        String payload = String.format(Locale.US,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"%s\",\"latest\"],\"id\":1}",
                address);
        try {
            String response = httpPost(network.rpcEndpoint, payload);
            String resultHex = parseStringField(response, "result");
            return hexToBigInteger(resultHex);
        } catch (IOException e) {
            System.out.println("Balance RPC unavailable: " + e.getMessage());
            return null;
        }
    }

    /**
     * Converts ETH to wei.
     *
     * @param amount the amount in ETH
     * @return the amount in wei
     */
    public BigInteger toWei(BigDecimal amount) {
        try {
            return amount.multiply(WEI_IN_ETH).toBigIntegerExact();
        } catch (ArithmeticException ex) {
            return amount.multiply(WEI_IN_ETH).toBigInteger();
        }
    }

    /**
     * Computes Keccak256 hash of the input data.
     *
     * @param data the data to hash
     * @return the 32-byte hash
     */
    public static byte[] keccak256(byte[] data) {
        KeccakDigest digest = new KeccakDigest(256);
        if (data != null && data.length > 0) {
            digest.update(data, 0, data.length);
        }
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * Encodes a transaction for signing.
     *
     * @param transaction the raw transaction
     * @param chainId the chain ID
     * @return the encoded bytes
     */
    public byte[] encodeTransaction(RawTransaction transaction, long chainId) {
        return TransactionEncoder.encode(transaction, chainId);
    }

    /**
     * Encodes a signed transaction.
     *
     * @param transaction the raw transaction
     * @param signatureData the signature data
     * @param chainId the chain ID
     * @return the encoded bytes
     */
    public byte[] encodeSignedTransaction(RawTransaction transaction,
            org.web3j.crypto.Sign.SignatureData signatureData, long chainId) {
        return TransactionEncoder.encode(transaction, signatureData);
    }

    /**
     * Converts bytes to hex string.
     *
     * @param data the bytes
     * @return hex string
     */
    public static String toHex(byte[] data) {
        if (data == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private String httpPost(String endpoint, String payload) throws IOException {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        try (OutputStream out = conn.getOutputStream()) {
            out.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        int status = conn.getResponseCode();
        InputStream stream = status >= 200 && status < 300
                ? conn.getInputStream()
                : conn.getErrorStream();

        if (stream == null) {
            conn.disconnect();
            throw new IOException("Server returned no response");
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            if (status >= 200 && status < 300) {
                return sb.toString();
            }
            throw new IOException("HTTP " + status + ": " + sb);
        } finally {
            conn.disconnect();
        }
    }

    private String parseStringField(String json, String fieldName) {
        return parseStringField(json, fieldName, 0);
    }

    private String parseStringField(String json, String fieldName, int fromIndex) {
        String token = '"' + fieldName + '"';
        int index = json.indexOf(token, fromIndex);
        if (index == -1) {
            return null;
        }
        index += token.length();
        while (index < json.length() && Character.isWhitespace(json.charAt(index))) {
            index++;
        }
        if (index >= json.length() || json.charAt(index) != ':') {
            return null;
        }
        index++;
        while (index < json.length() && Character.isWhitespace(json.charAt(index))) {
            index++;
        }
        if (index >= json.length() || json.charAt(index) != '"') {
            return null;
        }
        index++;
        StringBuilder builder = new StringBuilder();
        while (index < json.length()) {
            char ch = json.charAt(index);
            if (ch == '"') {
                return builder.toString();
            }
            if (ch == '\\' && index + 1 < json.length()) {
                index++;
                ch = json.charAt(index);
            }
            builder.append(ch);
            index++;
        }
        return null;
    }

    private String parseErrorMessage(String json) {
        int errorIndex = json.indexOf("\"error\"");
        if (errorIndex == -1) {
            return null;
        }
        return parseStringField(json, "message", errorIndex);
    }

    private BigInteger hexToBigInteger(String hex) {
        if (hex == null) {
            return null;
        }
        String cleaned = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        if (cleaned.isEmpty()) {
            return BigInteger.ZERO;
        }
        return new BigInteger(cleaned, 16);
    }
}
