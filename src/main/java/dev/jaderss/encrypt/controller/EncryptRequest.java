package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.EncryptionContext;
import java.util.Objects;

public record EncryptRequest(EncryptionContext context, String plaintext) {

    public EncryptRequest {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(plaintext, "plaintext");
    }
}
