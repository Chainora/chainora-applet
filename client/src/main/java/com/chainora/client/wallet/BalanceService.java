package com.chainora.client.wallet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Service for fetching wallet balance from various providers.
 */
public class BalanceService {
    private static final String BLOCKCYPHER_ENDPOINT = "https://api.blockcypher.com/v1/eth/main/addrs/%s/balance";
    private static final String HARDHAT_RPC = "http://127.0.0.1:8545";
    private static final BigDecimal WEI_IN_ETH = new BigDecimal("1000000000000000000");

    /**
     * Balance provider options.
     */
    public enum Provider {
        BLOCKCYPHER,
        HARDHAT
    }

    /**
     * Fetches the balance for an address.
     *
     * @param provider the balance provider to use
     * @param address the Ethereum address
     * @return the balance in ETH, or null if fetch failed
     */
    public BigDecimal fetch(Provider provider, String address) {
        if (provider == Provider.BLOCKCYPHER) {
            return fetchBlockCypher(address);
        } else {
            return fetchHardhat(address);
        }
    }

    private BigDecimal fetchBlockCypher(String address) {
        String normalized = address.startsWith("0x") ? address.substring(2) : address;
        String endpoint = String.format(Locale.US, BLOCKCYPHER_ENDPOINT, normalized);
        try {
            String response = httpGet(endpoint);
            BigIntegerWrapper balance = parseBigIntegerField(response, "balance");
            if (balance != null) {
                return new BigDecimal(balance.value).divide(WEI_IN_ETH, 18, RoundingMode.DOWN);
            }
        } catch (IOException e) {
            System.out.println("Balance service unavailable: " + e.getMessage());
        }
        return null;
    }

    private BigDecimal fetchHardhat(String address) {
        BigIntegerWrapper balanceWei = fetchBalanceWei(HARDHAT_RPC, address);
        if (balanceWei != null) {
            return new BigDecimal(balanceWei.value).divide(WEI_IN_ETH, 18, RoundingMode.DOWN);
        }
        return null;
    }

    private BigIntegerWrapper fetchBalanceWei(String rpcEndpoint, String address) {
        String payload = String.format(Locale.US,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"%s\",\"latest\"],\"id\":1}",
                address);
        try {
            String response = httpPost(rpcEndpoint, payload);
            String resultHex = parseStringField(response, "result");
            if (resultHex != null) {
                return new BigIntegerWrapper(hexToBigInteger(resultHex));
            }
            String error = parseErrorMessage(response);
            System.out.println(error != null ? error : "Unable to fetch balance from RPC.");
        } catch (IOException e) {
            System.out.println("Balance RPC unavailable: " + e.getMessage());
        }
        return null;
    }

    private String httpGet(String endpoint) throws IOException {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

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

    private BigIntegerWrapper parseBigIntegerField(String json, String fieldName) {
        String token = '"' + fieldName + '"' + ':';
        int index = json.indexOf(token);
        if (index == -1) {
            return null;
        }
        index += token.length();
        while (index < json.length() && Character.isWhitespace(json.charAt(index))) {
            index++;
        }
        int start = index;
        while (index < json.length() && Character.isDigit(json.charAt(index))) {
            index++;
        }
        if (start == index) {
            return null;
        }
        return new BigIntegerWrapper(new java.math.BigInteger(json.substring(start, index)));
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

    private java.math.BigInteger hexToBigInteger(String hex) {
        if (hex == null) {
            return null;
        }
        String cleaned = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        if (cleaned.isEmpty()) {
            return java.math.BigInteger.ZERO;
        }
        return new java.math.BigInteger(cleaned, 16);
    }

    private static class BigIntegerWrapper {
        final java.math.BigInteger value;

        BigIntegerWrapper(java.math.BigInteger value) {
            this.value = value;
        }
    }
}
