package dev.jaderss.encrypt.service;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.regex.Pattern;

public record EncryptionContext(String tenantId, String field) {

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z0-9_.-]{1,64}");

    public EncryptionContext {
        requireIdentifier("tenantId", tenantId);
        requireIdentifier("field", field);
    }

    byte[] associatedData() {
        return (tenantId + ":" + field).getBytes(StandardCharsets.UTF_8);
    }

    private static void requireIdentifier(String name, String value) {
        Objects.requireNonNull(value, name);
        if (!IDENTIFIER.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must match " + IDENTIFIER.pattern());
        }
    }
}
