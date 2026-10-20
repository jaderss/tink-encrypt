package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.EncryptionContext;
import java.util.Objects;

public record PlaintextRequest(EncryptionContext context, String plaintext) {

    public PlaintextRequest {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(plaintext, "plaintext");
    }

    @Override
    public String toString() {
        return "PlaintextRequest[context=" + context + ", plaintext=***]";
    }
}
