package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.EncryptionContext;
import java.util.Objects;

public record CiphertextRequest(EncryptionContext context, String ciphertext) {

    public CiphertextRequest {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(ciphertext, "ciphertext");
    }
}
