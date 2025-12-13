import cz.muni.fi.crocs.rcard.client.CardManager;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
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
import java.util.Arrays;
import java.util.Locale;
import java.util.Scanner;

import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.SignedRawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionDecoder;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.utils.Numeric;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.digests.KeccakDigest;

public class WalletManager extends BaseApduManager {
    private static final byte INS_INIT_PIN = (byte) 0x10;
    private static final byte INS_VERIFY_PIN = (byte) 0x11;
    private static final byte INS_RESET_PIN = (byte) 0x13;
    private static final byte INS_GEN_KEY_PAIR = (byte) 0x20;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x21;
    private static final byte INS_SIGN_HASH = (byte) 0x22;

    private static final String BALANCE_ENDPOINT = "https://api.blockcypher.com/v1/eth/main/addrs/%s/balance";
    private static final String MAINNET_RPC_ENDPOINT = "https://cloudflare-eth.com";
    private static final String HARDHAT_RPC_ENDPOINT = "http://127.0.0.1:8545";
    private static final BigDecimal WEI_IN_ETH = new BigDecimal("1000000000000000000");
    private static final int ETH_ADDRESS_LENGTH = 40;
    private static final BigInteger DEFAULT_GAS_LIMIT = BigInteger.valueOf(21_000);
    private static final BigInteger FALLBACK_GAS_PRICE_WEI = new BigInteger("2000000000");
    private static final ECDomainParameters SECP256K1 = createSecp256k1Domain();
    private static final BigInteger HALF_CURVE_ORDER = SECP256K1.getN().shiftRight(1);

    private final Scanner scanner;
    private TransactionNetwork activeNetwork;
    private BalanceProvider balanceProvider;

    public WalletManager(Scanner scanner, CardManager cardManager) {
        super(cardManager);
        this.scanner = scanner;
    }

    public void initWallet() {
        try {
            final ResponseAPDU resetResponse = transmit(INS_RESET_PIN, null);
            printResponse(resetResponse);
            if (!isSuccess(resetResponse)) {
                System.out.println("Failed to reset PIN.");
                return;
            }

            final byte[] pin = promptPin("Enter new PIN (4 digits): ");
            final ResponseAPDU initResponse = transmit(INS_INIT_PIN, pin);
            printResponse(initResponse);
            if (!isSuccess(initResponse)) {
                System.out.println("Failed to initialize PIN.");
                return;
            }

            final ResponseAPDU keyResponse = transmit(INS_GEN_KEY_PAIR, null);
            printResponse(keyResponse);
            if (isSuccess(keyResponse)) {
                System.out.println("Wallet initialized and key pair generated successfully.");
            } else {
                System.out.println("Key pair generation failed. Please try again.");
            }
        } catch (CardException e) {
            handleCardError("initializing wallet", e);
        }
    }

    public void viewWallet() {
        try {
            final byte[] pin = promptPin("Enter PIN to view wallet: ");
            final ResponseAPDU verifyResponse = transmit(INS_VERIFY_PIN, pin);
            printResponse(verifyResponse);
            if (!isSuccess(verifyResponse)) {
                System.out.println("Invalid PIN. Cannot display wallet.");
                return;
            }

            final ResponseAPDU publicKeyResponse = transmit(INS_GET_PUBLIC_KEY, null);
            printResponse(publicKeyResponse);
            if (!isSuccess(publicKeyResponse) || !hasData(publicKeyResponse)) {
                System.out.println("Unable to fetch public key from card.");
                return;
            }

            final byte[] publicKey = publicKeyResponse.getData();
            final String address = deriveEthereumAddress(publicKey);
            System.out.println("Wallet address: " + address);

            final BigDecimal balance = requireBalanceProvider() == BalanceProvider.HARDHAT
                    ? fetchHardhatBalance(address)
                    : fetchEthBalance(address);
            if (balance != null) {
                final String label = requireBalanceProvider() == BalanceProvider.HARDHAT
                        ? "Hardhat balance"
                        : "Estimated balance";
                System.out.printf("%s: %s ETH%n", label, balance.stripTrailingZeros().toPlainString());
            } else {
                final String source = requireBalanceProvider() == BalanceProvider.HARDHAT
                        ? "local Hardhat RPC"
                        : "public API";
                System.out.println("Failed to fetch balance from " + source + '.');
            }
        } catch (CardException e) {
            handleCardError("viewing wallet", e);
        }
    }

    public void selectBalanceProvider() {
        this.balanceProvider = promptBalanceProvider();
        System.out.println("Active balance provider: " + balanceProvider);
    }

    private BalanceProvider requireBalanceProvider() {
        if (balanceProvider == null) {
            System.out.println("Balance provider not selected yet. Please choose one.");
            balanceProvider = promptBalanceProvider();
        }
        return balanceProvider;
    }

    public void selectTransactionNetwork() {
        this.activeNetwork = promptTransactionNetwork();
        System.out.println("Active network: " + activeNetwork.displayName);
    }

    private TransactionNetwork requireActiveNetwork() {
        if (activeNetwork == null) {
            System.out.println("Transaction network not selected yet. Please choose one.");
            activeNetwork = promptTransactionNetwork();
        }
        return activeNetwork;
    }

    public void sendEth() {
        try {
            final TransactionNetwork network = requireActiveNetwork();
            final String recipient = promptAddress();
            final BigDecimal amount = promptEthAmount();
            final byte[] pin = promptPin("Enter PIN to confirm transaction: ");

            final ResponseAPDU verifyResponse = transmit(INS_VERIFY_PIN, pin);
            printResponse(verifyResponse);
            if (!isSuccess(verifyResponse)) {
                System.out.println("Invalid PIN. Transaction cancelled.");
                return;
            }

            final ResponseAPDU publicKeyResponse = transmit(INS_GET_PUBLIC_KEY, null);
            printResponse(publicKeyResponse);
            if (!isSuccess(publicKeyResponse) || !hasData(publicKeyResponse)) {
                System.out.println("Unable to fetch public key for signing.");
                return;
            }

            final byte[] publicKey = publicKeyResponse.getData();
            final String senderAddress = deriveEthereumAddress(publicKey);
            System.out.println("Sender address: " + senderAddress);

            final BigInteger nonce = fetchTransactionCount(network.rpcEndpoint, senderAddress);
            final BigInteger gasPrice = resolveGasPrice(network.rpcEndpoint);
            final BigInteger valueWei = toWei(amount);
            final BigInteger balanceWei = fetchBalanceWei(network.rpcEndpoint, senderAddress);
            if (balanceWei == null) {
                System.out.println("Unable to verify on-chain balance. Transaction cancelled.");
                return;
            }

            final BigInteger requiredWei = valueWei.add(gasPrice.multiply(DEFAULT_GAS_LIMIT));
            if (balanceWei.compareTo(requiredWei) < 0) {
                System.out.printf(
                        Locale.US,
                        "Insufficient funds. Balance: %s ETH, required: %s ETH (amount + estimated fee).%n",
                        formatWei(balanceWei),
                        formatWei(requiredWei));
                return;
            }

            final RawTransaction rawTransaction = RawTransaction.createEtherTransaction(
                    nonce,
                    gasPrice,
                    DEFAULT_GAS_LIMIT,
                    recipient,
                    valueWei);

            final byte[] unsignedTransaction = TransactionEncoder.encode(rawTransaction, network.chainId);
            final byte[] hashToSign = keccak256(unsignedTransaction);

            final ResponseAPDU signatureResponse = transmit(INS_SIGN_HASH, hashToSign);
            printResponse(signatureResponse);
            if (!isSuccess(signatureResponse) || !hasData(signatureResponse)) {
                System.out.println("Failed to sign transaction.");
                return;
            }

            final SignatureValues signatureValues = buildSignatureValues(
                    signatureResponse.getData(),
                    hashToSign,
                    publicKey);

            final Sign.SignatureData finalSignature = toSignatureData(signatureValues, network.chainId);
            final byte[] signedPayload = TransactionEncoder.encode(rawTransaction, finalSignature);
            final String rawTxHex = "0x" + toHex(signedPayload);

            try {
                final SignedRawTransaction decoded = (SignedRawTransaction) TransactionDecoder.decode(rawTxHex);
                System.out.println("Recovered sender from raw transaction: " + decoded.getFrom());
            } catch (Exception decodeException) {
                System.out.println("Failed to decode raw transaction locally: " + decodeException.getMessage());
            }

            System.out.printf("Broadcasting transaction on %s...%n", network.displayName);
            final String txHash = sendRawTransaction(network.rpcEndpoint, rawTxHex);
            System.out.println("Transaction sent. Hash: " + txHash);
        } catch (CardException e) {
            handleCardError("sending ETH", e);
        } catch (IOException e) {
            System.out.println("Network error: " + e.getMessage());
        } catch (IllegalStateException | IllegalArgumentException e) {
            System.out.println("Transaction assembly failed: " + e.getMessage());
        }
    }

    private byte[] promptPin(String label) {
        while (true) {
            System.out.print(label);
            final String value = scanner.nextLine().trim();
            if (!value.matches("\\d{4}")) {
                System.out.println("PIN must contain exactly 4 digits.");
                continue;
            }
            return value.getBytes(StandardCharsets.UTF_8);
        }
    }

    private String promptAddress() {
        while (true) {
            System.out.print("Enter recipient address (0x...): ");
            String input = scanner.nextLine().trim();
            if (input.isEmpty()) {
                System.out.println("Address must not be empty.");
                continue;
            }
            if (input.startsWith("0x") || input.startsWith("0X")) {
                input = input.substring(2);
            }
            if (input.length() != ETH_ADDRESS_LENGTH || !input.matches("[0-9a-fA-F]+")) {
                System.out.println("Address must contain exactly 40 hex characters.");
                continue;
            }
            final byte[] addressBytes = Numeric.hexStringToByteArray("0x" + input);
            return toChecksumAddress(addressBytes);
        }
    }

    private BigDecimal promptEthAmount() {
        while (true) {
            System.out.print("Enter amount in ETH: ");
            final String line = scanner.nextLine().trim();
            try {
                final BigDecimal value = new BigDecimal(line);
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

    private BalanceProvider promptBalanceProvider() {
        while (true) {
            System.out.println();
            System.out.println("Select balance source:");
            System.out.println("1 - BlockCypher (Ethereum mainnet)");
            System.out.println("2 - Hardhat local node (http://127.0.0.1:8545)");
            System.out.print("Enter 1-2: ");
            final String choice = scanner.nextLine().trim();
            if ("1".equals(choice)) {
                return BalanceProvider.BLOCKCYPHER;
            }
            if ("2".equals(choice)) {
                return BalanceProvider.HARDHAT;
            }
            System.out.println("Invalid choice. Please enter 1 or 2.");
        }
    }

    private TransactionNetwork promptTransactionNetwork() {
        while (true) {
            System.out.println();
            System.out.println("Select transaction network:");
            System.out.println("1 - Ethereum mainnet (" + MAINNET_RPC_ENDPOINT + ")");
            System.out.println("2 - Hardhat local node (" + HARDHAT_RPC_ENDPOINT + ")");
            System.out.print("Enter 1-2: ");
            final String choice = scanner.nextLine().trim();
            if ("1".equals(choice)) {
                return TransactionNetwork.MAINNET;
            }
            if ("2".equals(choice)) {
                return TransactionNetwork.HARDHAT;
            }
            System.out.println("Invalid choice. Please enter 1 or 2.");
        }
    }

    private String deriveEthereumAddress(byte[] publicKey) {
        if (publicKey == null || publicKey.length < 64) {
            throw new IllegalArgumentException("Invalid public key.");
        }
        final int offset = publicKey.length == 65 ? 1 : 0;
        final byte[] xy = Arrays.copyOfRange(publicKey, offset, publicKey.length);
        final byte[] hash = keccak256(xy);
        final byte[] addressBytes = Arrays.copyOfRange(hash, hash.length - 20, hash.length);
        return toChecksumAddress(addressBytes);
    }

    private String toChecksumAddress(byte[] addressBytes) {
        final String hex = toHex(addressBytes).toLowerCase(Locale.ROOT);
        final byte[] hash = keccak256(hex.getBytes(StandardCharsets.US_ASCII));
        final StringBuilder builder = new StringBuilder("0x");
        for (int i = 0; i < hex.length(); i++) {
            final char ch = hex.charAt(i);
            final int hashByte = hash[i / 2] & 0xFF;
            final int nibble = (i % 2 == 0) ? (hashByte >>> 4) : (hashByte & 0x0F);
            if (Character.isLetter(ch) && nibble >= 8) {
                builder.append(Character.toUpperCase(ch));
            } else {
                builder.append(ch);
            }
        }
        return builder.toString();
    }

    private BigDecimal fetchEthBalance(String address) {
        final String normalized = address.startsWith("0x") ? address.substring(2) : address;
        final String endpoint = String.format(Locale.US, BALANCE_ENDPOINT, normalized);
        try {
            final String response = httpGet(endpoint);
            final BigInteger balanceWei = parseBigIntegerField(response, "balance");
            if (balanceWei == null) {
                return null;
            }
            return new BigDecimal(balanceWei).divide(WEI_IN_ETH, 18, RoundingMode.DOWN);
        } catch (IOException e) {
            System.out.println("Balance service unavailable: " + e.getMessage());
            return null;
        }
    }

    private BigDecimal fetchHardhatBalance(String address) {
        final BigInteger balanceWei = fetchBalanceWei(HARDHAT_RPC_ENDPOINT, address);
        if (balanceWei == null) {
            return null;
        }
        return new BigDecimal(balanceWei).divide(WEI_IN_ETH, 18, RoundingMode.DOWN);
    }

    private BigInteger fetchBalanceWei(String rpcEndpoint, String address) {
        final String payload = String.format(Locale.US,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"%s\",\"latest\"],\"id\":1}",
                address);
        try {
            final String response = httpPost(rpcEndpoint, payload);
            final String resultHex = parseStringField(response, "result");
            final BigInteger balance = hexToBigInteger(resultHex);
            if (balance != null) {
                return balance;
            }
            final String error = parseErrorMessage(response);
            System.out.println((error != null ? error : "Unable to fetch balance from RPC.") + "");
        } catch (IOException e) {
            System.out.println("Balance RPC unavailable: " + e.getMessage());
        }
        return null;
    }

    private BigInteger fetchTransactionCount(String rpcEndpoint, String address) throws IOException {
        final String payload = String.format(Locale.US,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionCount\",\"params\":[\"%s\",\"latest\"],\"id\":1}",
                address);
        final String response = httpPost(rpcEndpoint, payload);
        final String resultHex = parseStringField(response, "result");
        final BigInteger nonce = hexToBigInteger(resultHex);
        if (nonce != null) {
            return nonce;
        }
        final String error = parseErrorMessage(response);
        throw new IOException(error != null ? error : "RPC missing transaction count result.");
    }

    private BigInteger resolveGasPrice(String rpcEndpoint) {
        final String payload = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}";
        try {
            final String response = httpPost(rpcEndpoint, payload);
            final String resultHex = parseStringField(response, "result");
            final BigInteger gasPrice = hexToBigInteger(resultHex);
            if (gasPrice != null) {
                return gasPrice;
            }
            final String error = parseErrorMessage(response);
            if (error != null) {
                System.out.println("Gas price RPC error: " + error + ". Using fallback value.");
            }
        } catch (IOException e) {
            System.out.println("Unable to fetch gas price: " + e.getMessage() + ". Using fallback value.");
        }
        return FALLBACK_GAS_PRICE_WEI;
    }

    private BigInteger toWei(BigDecimal amount) {
        try {
            return amount.multiply(WEI_IN_ETH).toBigIntegerExact();
        } catch (ArithmeticException ex) {
            return amount.multiply(WEI_IN_ETH).toBigInteger();
        }
    }

    private String sendRawTransaction(String rpcEndpoint, String rawTxHex) throws IOException {
        final String payload = String.format(Locale.US,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendRawTransaction\",\"params\":[\"%s\"],\"id\":1}",
                rawTxHex);
        final String response = httpPost(rpcEndpoint, payload);
        final String result = parseStringField(response, "result");
        if (result != null) {
            return result;
        }
        final String error = parseErrorMessage(response);
        throw new IOException(error != null ? error : "RPC missing transaction hash.");
    }

    private SignatureValues buildSignatureValues(byte[] derSignature, byte[] messageHash,
            byte[] publicKey) {
        final DerSignatureComponents components = parseDerSignature(derSignature);
        final byte[] expectedKey = getPublicKeyXY(publicKey);
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            final byte[] recovered = recoverPublicKeyCoordinates(i, components.r, components.s, messageHash);
            if (recovered != null && Arrays.equals(recovered, expectedKey)) {
                recId = i;
                break;
            }
        }
        if (recId == -1) {
            throw new IllegalStateException("Unable to derive recovery identifier for signature.");
        }
        System.out.println("Derived recId from card signature: " + recId);
        BigInteger canonicalS = components.s;
        int canonicalRecId = recId;
        if (canonicalS.compareTo(HALF_CURVE_ORDER) > 0) {
            canonicalS = SECP256K1.getN().subtract(canonicalS);
            canonicalRecId ^= 1;
        }
        System.out.println("Canonicalized recId: " + canonicalRecId);
        final byte[] finalKey = recoverPublicKeyCoordinates(canonicalRecId, components.r, canonicalS, messageHash);
        if (finalKey == null || !Arrays.equals(finalKey, expectedKey)) {
            throw new IllegalStateException("Signature normalization failed integrity check.");
        }
        final int parityBit = canonicalRecId & 1;
        final BigInteger v = BigInteger.valueOf(parityBit + 27L);
        return new SignatureValues(components.r, canonicalS, v, parityBit);
    }

    private Sign.SignatureData toSignatureData(SignatureValues signatureValues, long chainId) {
        final byte[] rBytes = Numeric.toBytesPadded(signatureValues.r, 32);
        final byte[] sBytes = Numeric.toBytesPadded(signatureValues.s, 32);
        final BigInteger vValue = chainId > 0
                ? BigInteger.valueOf(chainId * 2L + 35L + signatureValues.parityBit)
                : signatureValues.v;
        final byte[] vBytes = toMinimalBytes(vValue);
        return new Sign.SignatureData(vBytes, rBytes, sBytes);
    }

    private DerSignatureComponents parseDerSignature(byte[] derSignature) {
        if (derSignature == null || derSignature.length < 8 || derSignature[0] != 0x30) {
            throw new IllegalArgumentException("Invalid DER signature format.");
        }
        int offset = 2;
        if (offset >= derSignature.length || derSignature[offset] != 0x02) {
            throw new IllegalArgumentException("Invalid DER signature: missing R marker.");
        }
        final int rLength = derSignature[offset + 1] & 0xFF;
        final int rStart = offset + 2;
        if (rStart + rLength > derSignature.length) {
            throw new IllegalArgumentException("Invalid DER signature length for R component.");
        }
        final BigInteger r = new BigInteger(1, Arrays.copyOfRange(derSignature, rStart, rStart + rLength));

        int sMarker = rStart + rLength;
        if (sMarker >= derSignature.length || derSignature[sMarker] != 0x02) {
            throw new IllegalArgumentException("Invalid DER signature: missing S marker.");
        }
        final int sLength = derSignature[sMarker + 1] & 0xFF;
        final int sStart = sMarker + 2;
        if (sStart + sLength > derSignature.length) {
            throw new IllegalArgumentException("Invalid DER signature length for S component.");
        }
        final BigInteger s = new BigInteger(1, Arrays.copyOfRange(derSignature, sStart, sStart + sLength));
        return new DerSignatureComponents(r, s);
    }

    private byte[] getPublicKeyXY(byte[] publicKey) {
        if (publicKey == null || publicKey.length < 64) {
            throw new IllegalArgumentException("Invalid public key length.");
        }
        if (publicKey.length == 65 && (publicKey[0] == 0x04 || publicKey[0] == 4)) {
            return Arrays.copyOfRange(publicKey, 1, 65);
        }
        return Arrays.copyOf(publicKey, 64);
    }

    private BigInteger hexToBigInteger(String hex) {
        if (hex == null) {
            return null;
        }
        final String cleaned = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        if (cleaned.isEmpty()) {
            return BigInteger.ZERO;
        }
        return new BigInteger(cleaned, 16);
    }

    private byte[] toMinimalBytes(BigInteger value) {
        if (value == null) {
            return new byte[] { 0x00 };
        }
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0x00) {
            raw = Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw.length == 0 ? new byte[] { 0x00 } : raw;
    }

    private String parseErrorMessage(String json) {
        final int errorIndex = json.indexOf("\"error\"");
        if (errorIndex == -1) {
            return null;
        }
        return parseStringField(json, "message", errorIndex);
    }

    private byte[] recoverPublicKeyCoordinates(int recId, BigInteger r, BigInteger s, byte[] messageHash) {
        if (recId < 0 || recId > 3) {
            return null;
        }
        final ECDomainParameters params = SECP256K1;
        final BigInteger n = params.getN();
        final BigInteger i = BigInteger.valueOf(recId / 2);
        final BigInteger x = r.add(i.multiply(n));
        final BigInteger prime = params.getCurve().getField().getCharacteristic();
        if (x.compareTo(prime) >= 0) {
            return null;
        }
        final ECPoint R = decompressKey(x, (recId & 1) == 1);
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        final BigInteger e = new BigInteger(1, messageHash);
        final BigInteger rInv = r.modInverse(n);
        final BigInteger srInv = s.multiply(rInv).mod(n);
        final BigInteger eNeg = n.subtract(e.mod(n)).mod(n);
        final BigInteger eInvrInv = eNeg.multiply(rInv).mod(n);
        final ECPoint q = params.getG().multiply(eInvrInv).add(R.multiply(srInv)).normalize();
        if (q.isInfinity()) {
            return null;
        }
        final byte[] xBytes = bigIntegerToBytes(q.getAffineXCoord().toBigInteger(), 32);
        final byte[] yBytes = bigIntegerToBytes(q.getAffineYCoord().toBigInteger(), 32);
        final byte[] out = new byte[64];
        System.arraycopy(xBytes, 0, out, 0, 32);
        System.arraycopy(yBytes, 0, out, 32, 32);
        return out;
    }

    private ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        final byte[] compEnc = new byte[33];
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        final byte[] xBytes = bigIntegerToBytes(xBN, 32);
        System.arraycopy(xBytes, 0, compEnc, 1, 32);
        return SECP256K1.getCurve().decodePoint(compEnc);
    }

    private static ECDomainParameters createSecp256k1Domain() {
        final X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        return new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    private byte[] bigIntegerToBytes(BigInteger value, int length) {
        final byte[] src = value.toByteArray();
        if (src.length == length) {
            return src;
        }
        final byte[] dst = new byte[length];
        final int copyStart = Math.max(0, src.length - length);
        final int copyLength = Math.min(length, src.length);
        System.arraycopy(src, copyStart, dst, length - copyLength, copyLength);
        return dst;
    }

    private String formatWei(BigInteger wei) {
        return new BigDecimal(wei)
                .divide(WEI_IN_ETH, 18, RoundingMode.DOWN)
                .stripTrailingZeros()
                .toPlainString();
    }

    private String httpGet(String endpoint) throws IOException {
        final URL url = new URL(endpoint);
        final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        final int status = connection.getResponseCode();
        final InputStream stream = status >= 200 && status < 300
                ? connection.getInputStream()
                : connection.getErrorStream();

        if (stream == null) {
            connection.disconnect();
            throw new IOException("Server returned no response");
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            final StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            if (status >= 200 && status < 300) {
                return sb.toString();
            }
            throw new IOException("HTTP " + status + ": " + sb);
        } finally {
            connection.disconnect();
        }
    }

    private String httpPost(String endpoint, String payload) throws IOException {
        final URL url = new URL(endpoint);
        final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        final int status = connection.getResponseCode();
        final InputStream stream = status >= 200 && status < 300
                ? connection.getInputStream()
                : connection.getErrorStream();

        if (stream == null) {
            connection.disconnect();
            throw new IOException("Server returned no response");
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            final StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            if (status >= 200 && status < 300) {
                return sb.toString();
            }
            throw new IOException("HTTP " + status + ": " + sb);
        } finally {
            connection.disconnect();
        }
    }

    private BigInteger parseBigIntegerField(String json, String fieldName) {
        final String token = '"' + fieldName + '"' + ':';
        int index = json.indexOf(token);
        if (index == -1) {
            return null;
        }
        index += token.length();
        while (index < json.length() && Character.isWhitespace(json.charAt(index))) {
            index++;
        }
        final int start = index;
        while (index < json.length() && Character.isDigit(json.charAt(index))) {
            index++;
        }
        if (start == index) {
            return null;
        }
        return new BigInteger(json.substring(start, index));
    }

    private String parseStringField(String json, String fieldName) {
        return parseStringField(json, fieldName, 0);
    }

    private String parseStringField(String json, String fieldName, int fromIndex) {
        final String token = '"' + fieldName + '"';
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
        final StringBuilder builder = new StringBuilder();
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

    private void handleCardError(String action, Exception e) {
        System.out.printf("Error while %s: %s%n", action, e.getMessage());
    }

    private static final class DerSignatureComponents {
        private final BigInteger r;
        private final BigInteger s;

        private DerSignatureComponents(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }
    }

    private static final class SignatureValues {
        private final BigInteger r;
        private final BigInteger s;
        private final BigInteger v;
        private final int parityBit;

        private SignatureValues(BigInteger r, BigInteger s, BigInteger v, int parityBit) {
            this.r = r;
            this.s = s;
            this.v = v;
            this.parityBit = parityBit;
        }
    }

    private static byte[] keccak256(byte[] input) {
        final KeccakDigest digest = new KeccakDigest(256);
        if (input != null && input.length > 0) {
            digest.update(input, 0, input.length);
        }
        final byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    private enum TransactionNetwork {
        MAINNET("Ethereum mainnet", MAINNET_RPC_ENDPOINT, 1L),
        HARDHAT("Hardhat local node", HARDHAT_RPC_ENDPOINT, 31_337L);

        final String displayName;
        final String rpcEndpoint;
        final long chainId;

        TransactionNetwork(String displayName, String rpcEndpoint, long chainId) {
            this.displayName = displayName;
            this.rpcEndpoint = rpcEndpoint;
            this.chainId = chainId;
        }
    }

    private enum BalanceProvider {
        BLOCKCYPHER,
        HARDHAT
    }
}
