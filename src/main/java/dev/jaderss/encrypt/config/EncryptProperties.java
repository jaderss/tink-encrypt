package dev.jaderss.encrypt.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "encrypt")
public record EncryptProperties(String keyset, @Valid Kms kms) {

    public record Kms(@NotBlank String keyArn, @NotBlank String encryptedKeyset) {}

    @AssertTrue(message = "set exactly one of encrypt.keyset or encrypt.kms")
    public boolean isExactlyOneKeySource() {
        boolean hasKeyset = keyset != null && !keyset.isBlank();
        return hasKeyset != (kms != null);
    }

    @Override
    public String toString() {
        return "EncryptProperties[keyset=***, kms=" + kms + "]";
    }
}
