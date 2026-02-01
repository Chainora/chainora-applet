package com.chainora.client.ui;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * Result wrapper for user input from console prompts.
 *
 * @param <T> the type of the result value
 */
public class PromptResult<T> {
    private final T value;
    private final boolean cancelled;

    private PromptResult(T value, boolean cancelled) {
        this.value = value;
        this.cancelled = cancelled;
    }

    /**
     * Creates a successful result with a value.
     */
    public static <T> PromptResult<T> success(T value) {
        return new PromptResult<>(value, false);
    }

    /**
     * Creates a cancelled result.
     */
    public static <T> PromptResult<T> cancelled() {
        return new PromptResult<>(null, true);
    }

    /**
     * Returns the value if present.
     *
     * @return the value or null if cancelled
     */
    public T getValue() {
        return value;
    }

    /**
     * Returns true if the prompt was cancelled.
     */
    public boolean isCancelled() {
        return cancelled;
    }

    /**
     * Returns the value or throws if cancelled.
     *
     * @return the value
     * @throws IllegalStateException if cancelled
     */
    public T getOrThrow() {
        if (cancelled) {
            throw new IllegalStateException("Prompt was cancelled");
        }
        return value;
    }
}
