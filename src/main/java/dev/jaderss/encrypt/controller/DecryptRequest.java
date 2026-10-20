package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.EncryptionContext;
import java.util.Objects;

public record DecryptRequest(EncryptionContext context, String ciphertext) {

    public DecryptRequest {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(ciphertext, "ciphertext");
    }
}
