package dev.jaderss.encrypt;

import java.util.stream.Stream;

public final class SamplePlaintexts {

    private SamplePlaintexts() {}

    public static Stream<String> nonEmpty() {
        return Stream.of(
                "Hello World!",
                "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
                "Unicode: 你好世界 🌍 émojis",
                "This is a long text for testing encryption and decryption. "
                        .repeat(100)
                        .strip());
    }
}
