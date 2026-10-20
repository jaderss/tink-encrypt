package dev.jaderss.encrypt.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "encrypt")
public record EncryptProperties(@NotBlank String keyset) {

    @Override
    public String toString() {
        return "EncryptProperties[keyset=***]";
    }
}
