package dev.jaderss.encrypt;

import dev.jaderss.encrypt.service.EncryptionContext;
import java.util.stream.Stream;

public final class Samples {

    public static final EncryptionContext CONTEXT = new EncryptionContext("acme", "ssn");

    private Samples() {}

    public static Stream<String> plaintexts() {
        return Stream.of(
                "",
                "Hello World!",
                "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?\\",
                "Unicode: 你好世界 🌍 émojis",
                "This is a long text for testing encryption and decryption. ".repeat(100));
    }
}
