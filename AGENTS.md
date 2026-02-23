# AGENTS.md
Repository guidance for autonomous coding agents working in `chainora-applet`.

## 1) Scope
- This is a Gradle multi-module Java project.
- Modules:
  - `applet/` - JavaCard applet logic (on-card).
  - `client/` - Java CLI client for card + Ethereum workflows.
- Key docs:
  - `README.md`
  - `docs/apdu-command.md`
  - `docs/developer-guide.md`
- Vendor code:
  - `libs-sdks/` is an Oracle JavaCard SDK submodule; avoid editing unless explicitly requested.

## 2) Cursor/Copilot Rules Status
Checked and not found:
- `.cursor/rules/`
- `.cursorrules`
- `.github/copilot-instructions.md`
No extra Cursor/Copilot instruction files currently apply.

## 3) Environment
- Use Gradle wrapper (`gradlew` / `gradlew.bat`), not a globally installed Gradle.
- Wrapper version: Gradle 6.6.
- Applet module targets Java 8 (`sourceCompatibility = 1.8`).
- Project docs call out Java 8u271+ as minimum practical baseline.

## 4) Build and Run Commands
```bash
# Build modules
./gradlew :applet:build :client:build

# Build JavaCard CAP
./gradlew :applet:buildJavaCard --info --rerun-tasks

# Install/list applet on physical card
./gradlew :applet:installJavaCard --info --rerun-tasks
./gradlew :applet:listJavaCard

# Run CLI client
./gradlew :client:run

# Clean
./gradlew :applet:clean :client:clean

# List all tasks
./gradlew tasks --all
```

## 5) Lint / Verification Commands
There is no dedicated Checkstyle/Spotless/PMD config in this repo.
Use `check`, compile, and tests as verification gates.
```bash
# Verification
./gradlew :applet:check :client:check

# Compile-only sanity check
./gradlew :applet:compileJava :client:compileJava

# Legacy CI baseline (.travis.yml)
./gradlew check --info
./gradlew buildJavaCard --info
```

## 6) Test Commands (Single Test Included)
Primary tests are in `applet/src/test/java/tests/AppletTest.java`.
```bash
# All applet tests
./gradlew :applet:test --info --rerun-tasks

# Single class
./gradlew :applet:test --tests "tests.AppletTest" --info --rerun-tasks

# Single method
./gradlew :applet:test --tests "tests.AppletTest.signHash_SignatureIsLowSNormalized" --info --rerun-tasks

# Multiple targeted methods
./gradlew :applet:test --tests "tests.AppletTest.getPublicKey_PinVerified_ReturnsPublicKey" --tests "tests.AppletTest.signData_PinVerified_ReturnsSignature"
```
Test behavior in this repo:
- Tests are configured for physical card (`CardType.PHYSICAL`).
- Card state may persist between tests/runs; setup helpers reset expected state.
- If state is inconsistent, reinstall applet and re-run tests.

## 7) APDU/Protocol Change Rules
- Keep instruction constants in `client/src/main/java/com/chainora/client/ApduConstants.java`.
- Current INS ranges:
  - PIN: `0x10`-`0x14`
  - Key: `0x20`-`0x21`
  - Sign: `0x22`
- When changing APDU behavior, update in one change set:
  - applet handlers and dispatcher registration
  - client APDU adapters/constants
  - tests
  - `docs/apdu-command.md`

## 8) Code Style - Imports and Structure
- No wildcard imports.
- Keep imports grouped with one blank line between groups:
  1. `java.*` / `javax.*`
  2. third-party (`org.*`, `javacard.*`, `cz.muni.*`, etc.)
  3. `com.chainora.*`
- One top-level public class per file.
- Utility-only classes should be `final` with private constructors.
- Keep package names lowercase (`com.chainora...`).

## 9) Code Style - Formatting and Naming
- 4-space indentation, no tabs.
- Opening brace on the same line.
- Prefer small focused methods; extract repeated logic.
- Prefer named constants over magic numbers (especially APDU/SW/crypto values).
- Naming:
  - Classes/interfaces: `PascalCase`
  - Methods/fields/locals: `camelCase`
  - Constants: `UPPER_SNAKE_CASE`
  - Tests: descriptive scenario names (repo often uses underscore-separated names)
- Keep Javadoc on public APIs and non-obvious security/crypto logic.

## 10) Types and JavaCard Practices
- Maintain Java 8 compatibility.
- In applet code, prefer primitives (`byte`, `short`) and fixed-size arrays.
- Validate APDU lengths/offsets before accessing buffers.
- Avoid unnecessary allocations in APDU hot paths.
- Keep curve and protocol constants centralized (`Configuration`, `Secp256k1`, etc.).

## 11) Error Handling
Applet side:
- Use `ISOException.throwIt(...)` with correct status words.
- Prefer `ISO7816` constants for standard SW values.
- Fail fast for invalid lengths, unsupported INS, or missing PIN state.
Client side:
- Wrap non-success card responses in `CardOperationException` and keep SW code.
- In UI flows, catch exceptions and show concise user-facing errors.
- For RPC/network calls, follow existing fallback/null behavior patterns.

## 12) Security Expectations
- Never expose private key material.
- Sign only precomputed 32-byte hashes.
- Preserve Low-S normalization behavior.
- Keep recovery-id / EIP-155 handling consistent with current `SignatureBuilder` logic.
- Never log PINs or secret material.

## 13) Agent Workflow Checklist
- Read related module files + docs before editing.
- Keep applet and client protocol behavior in sync.
- Prefer minimal diffs over broad refactors.
- Run the narrowest relevant command first, then broader verification.
- If hardware-dependent tests cannot run, clearly state what was validated and what was not.
