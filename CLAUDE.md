# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Chainora is a JavaCard wallet applet for Ethereum. It consists of two modules:
- **applet**: The JavaCard applet (`com.chainora.wallet.ChainoraWallet`) that stores secp256k1 keys and signs transactions on-card
- **client**: A desktop Java client that communicates with the card and broadcasts Ethereum transactions

## Build Commands

```bash
# Build the JavaCard CAP file
./gradlew :applet:buildJavaCard --info --rerun-tasks

# Install applet on a physical card
./gradlew :applet:installJavaCard --info --rerun-tasks

# List installed applets on card
./gradlew :applet:listJavaCard

# Run the desktop client (connects to card via CLI menu)
./gradlew :client:run

# Run applet unit tests
./gradlew :applet:test --info --rerun-tasks
```

## Applet Configuration

- Applet AID: `f0:56:4e:43:48:57:01` (configured in `applet/build.gradle`)
- Target JavaCard version: 3.0.5u3 (JC305u3)
- Minimum Java version: 8-u271

## Architecture

### Applet (`applet/src/main/java/com/chainora/wallet/`)

The applet has been refactored to follow SOLID principles:

**Core Classes (Orchestration)**
- `ChainoraWallet.java`: Main applet entry point, handles applet lifecycle and command dispatching

**Abstractions (Dependency Inversion)**
- `CommandHandler.java`: Interface for command handlers; enables extensibility

**Command Dispatcher (Open-Closed Principle)**
- `CommandDispatcher.java`: Routes APDU commands to handlers via registry pattern; new commands = new handlers, no modification needed

**Command Handlers (Single Responsibility Principle)**
- `PinCommandHandler.java`: Handles all PIN operations (INS 0x10-0x14)
- `KeyCommandHandler.java`: Handles key pair generation and public key retrieval (INS 0x20-0x21)
- `SignCommandHandler.java`: Handles hash signing (INS 0x22)

**Utilities (DRY Principle)**
- `PinValidator.java`: Centralized PIN validation logic (eliminates duplication)
- `ApduUtils.java`: Common APDU utility methods for data reception/sending

**Data Classes (Unchanged)**
- `Secp256k1.java`: secp256k1 curve parameters
- `Configuration.java`: PIN limits, key length constants

**APDU Protocol**

| INS | Function | Data | Response |
|-----|----------|------|----------|
| 0x10 | INIT_PIN | PIN bytes | SW=0x9000 or 0x6985 |
| 0x11 | VERIFY_PIN | PIN bytes | SW=0x9000 or 0x6982/0x6983 |
| 0x12 | UPDATE_PIN | New PIN | SW=0x9000 |
| 0x13 | RESET_PIN | - | SW=0x9000 |
| 0x14 | IS_PIN_INITIALIZED | - | 1 byte (0/1) + SW=0x9000 |
| 0x20 | GEN_KEY_PAIR | - | SW=0x9000 |
| 0x21 | GET_PUBLIC_KEY | - | 65 bytes + SW=0x9000 |
| 0x22 | SIGN_HASH | 32-byte hash | DER signature + SW=0x9000 |

All operations except INIT_PIN and IS_PIN_INITIALIZED require PIN validation.

### Client (`client/src/main/java/`)

- `ChainoraClient.java`: Main entry point with CLI menu system
- `BaseApduManager.java`: Base class for APDU communication with the card
- `PinManager.java`: PIN operations wrapper
- `KeyManager.java`: Key pair and public key operations
- `WalletManager.java`: Ethereum wallet operations (balance, transaction signing, broadcasting)
- Uses `cz.muni.fi.crocs.rcard.client.CardManager` for card communication
- Uses `org.web3j` for Ethereum transaction encoding and RPC calls

## Key Files

### Applet Files
- `ChainoraWallet.java`: Main applet class (orchestration only)
- `CommandHandler.java`: Interface for command handlers
- `CommandDispatcher.java`: Routes INS to handlers via registry
- `PinCommandHandler.java`: PIN operations (INS 0x10-0x14)
- `KeyCommandHandler.java`: Key operations (INS 0x20-0x21)
- `SignCommandHandler.java`: Signing operation (INS 0x22)
- `PinValidator.java`: Centralized PIN validation
- `ApduUtils.java`: Common APDU utilities
- `Secp256k1.java`: secp256k1 curve parameters
- `Configuration.java`: PIN limits, key length
- `docs/apdu-command.md`: Full APDU documentation

## Design Principles Applied

1. **Single Responsibility**: Each handler has one clear responsibility
2. **Open-Closed**: New commands added via new handlers, not modifying dispatcher
3. **Dependency Inversion**: Handlers depend on `CommandHandler` interface
4. **DRY**: PIN validation and APDU patterns centralized
