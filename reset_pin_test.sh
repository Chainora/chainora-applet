#!/bin/bash
# Reset PIN on card before running tests

echo "Resetting PIN on card..."
# Connect to card and reset PIN
./gradlew :applet:installJavaCard --info --rerun-tasks 2>&1 | grep -E "CAP loaded|BUILD"

echo "Running tests..."
./gradlew :applet:test --info --rerun-tasks 2>&1 | grep -E "tests.AppletTest|PASSED|FAILED|completed" | head -15
