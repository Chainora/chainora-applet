package com.chainora.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Command dispatcher that routes APDU commands to appropriate handlers.
 * Uses a registry pattern for extensibility - new commands can be added
 * by registering new handlers without modifying this class.
 *
 * Note: Uses fixed arrays instead of java.util collections for JavaCard compatibility.
 */
public final class CommandDispatcher {
    private static final short SW_INS_NOT_SUPPORTED = ISO7816.SW_INS_NOT_SUPPORTED;

    private static final byte MAX_HANDLERS = 16;

    private final CommandHandler[] handlers;
    private final byte[] instructionCodes;
    private final byte handlerCount;

    private CommandDispatcher(CommandHandler[] handlers, byte[] instructionCodes, byte handlerCount) {
        this.handlers = handlers;
        this.instructionCodes = instructionCodes;
        this.handlerCount = handlerCount;
    }

    /**
     * Creates a new dispatcher with the given handlers.
     *
     * @param builder The builder containing handlers and instruction codes
     * @return Configured CommandDispatcher
     */
    public static CommandDispatcher create(CommandDispatcherBuilder builder) {
        CommandHandler[] handlerArray = new CommandHandler[builder.handlerCount];
        byte[] insArray = new byte[builder.handlerCount];
        for (byte i = 0; i < builder.handlerCount; i++) {
            handlerArray[i] = builder.handlers[i];
            insArray[i] = builder.instructionCodes[i];
        }
        return new CommandDispatcher(handlerArray, insArray, builder.handlerCount);
    }

    /**
     * Dispatches an APDU command to the appropriate handler.
     *
     * @param apdu The APDU containing the command
     * @param ins  The instruction byte
     * @return Status word from handler
     */
    public short dispatch(APDU apdu, byte ins) {
        for (byte i = 0; i < handlerCount; i++) {
            if (instructionCodes[i] == ins) {
                return handlers[i].process(apdu, ins);
            }
        }
        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        return SW_INS_NOT_SUPPORTED;
    }

    /**
     * Builder class for constructing CommandDispatcher instances.
     */
    public static class CommandDispatcherBuilder {
        CommandHandler[] handlers = new CommandHandler[MAX_HANDLERS];
        byte[] instructionCodes = new byte[MAX_HANDLERS];
        byte handlerCount = 0;

        /**
         * Registers a handler for a specific instruction code.
         *
         * @param ins     The instruction byte
         * @param handler The handler for this instruction
         * @return this builder for chaining
         */
        public CommandDispatcherBuilder register(byte ins, CommandHandler handler) {
            if (handlerCount >= MAX_HANDLERS) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            handlers[handlerCount] = handler;
            instructionCodes[handlerCount] = ins;
            handlerCount++;
            return this;
        }

        /**
         * Builds the CommandDispatcher.
         *
         * @return Configured CommandDispatcher
         */
        public CommandDispatcher build() {
            return CommandDispatcher.create(this);
        }
    }

    /**
     * Creates a new builder instance.
     *
     * @return New builder
     */
    public static CommandDispatcherBuilder builder() {
        return new CommandDispatcherBuilder();
    }
}
