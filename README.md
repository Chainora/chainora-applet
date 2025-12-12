# Chainora Wallet Applet

## Building cap

- Setup your Applet ID (`AID`) in the `./applet/build.gradle`.

- Run the `buildJavaCard` task:

```bash
./gradlew :applet:buildJavaCard  --info --rerun-tasks
```

Generates a new cap file `./applet/out/cap/applet.cap`

Note: `--rerun-tasks` is to force re-run the task even though the cached input/output seems to be up to date.

Typical output:

```
[ant:cap] [ INFO: ] Converter [v3.0.5]
[ant:cap] [ INFO: ]     Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
[ant:cap]
[ant:cap]
[ant:cap] [ INFO: ] conversion completed with 0 errors and 0 warnings.
[ant:verify] XII 10, 2017 10:45:05 ODP.
[ant:verify] INFO: Verifier [v3.0.5]
[ant:verify] XII 10, 2017 10:45:05 ODP.
[ant:verify] INFO:     Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
[ant:verify]
[ant:verify]
[ant:verify] XII 10, 2017 10:45:05 ODP.
[ant:verify] INFO: Verifying CAP file /Users/dusanklinec/workspace/jcard/applet/out/cap/applet.cap
[ant:verify] javacard/framework/Applet
[ant:verify] XII 10, 2017 10:45:05 ODP.
[ant:verify] INFO: Verification completed with 0 warnings and 0 errors.
```

## Installation on a (physical) card

```bash
./gradlew :applet:installJavaCard --info --rerun-tasks
```

Or inspect already installed applets:

```bash
./gradlew :applet:listJavaCard
```

## Running on a (physical) card

As simple as:

```bash
./gradlew :client:run
```

## Running tests

```bash
./gradlew :applet:test --info --rerun-tasks
```

Output:

```
Running test: Test method hello(AppletTest)

Gradle suite > Gradle test > AppletTest.hello STANDARD_OUT
    Connecting to card... Done.
    --> [00C00000080000000000000000] 13
    <-- 51373E8B6FDEC284DB569204CA13D2CAA23BD1D85DCAB02A0E3D50461E73F1BB 9000 (32)
    ResponseAPDU: 34 bytes, SW=9000
```

## Dependencies

This project uses mainly:

- https://github.com/bertrandmartel/javacard-gradle-plugin
- https://github.com/martinpaljak/ant-javacard
- https://github.com/martinpaljak/oracle_javacard_sdks
- https://github.com/licel/jcardsim
- Petr Svenda scripts

### JavaCard support

Thanks to Martin Paljak's [ant-javacard] and [oracle_javacard_sdks] we support:

- JavaCard 2.1.2
- JavaCard 2.2.1
- JavaCard 2.2.2
- JavaCard 3.0.3
- JavaCard 3.0.4
- JavaCard 3.0.5u1
- JavaCard 3.1.0b43

## Supported Java versions

Java 8-u271 is the minimal version supported.

Make sure you have up to date java version (`-u` version) as older java 8 versions
have problems with recognizing some certificates as valid.

Only some Java versions are supported by the JavaCard SDKs.
Check the following compatibility table for more info:
https://github.com/martinpaljak/ant-javacard/wiki/Version-compatibility

## Contributions

Community feedback is highly appreciated - pull requests are welcome!

[JCardSim]: https://jcardsim.org/
[ant-javacard]: https://github.com/martinpaljak/ant-javacard
[oracle_javacard_sdks]: https://github.com/martinpaljak/oracle_javacard_sdks
