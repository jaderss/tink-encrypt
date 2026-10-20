package dev.jaderss.encrypt.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import dev.jaderss.encrypt.keyset.Keysets;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class SecurityConfigTest {

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner().withUserConfiguration(SecurityConfig.class);

    @Test
    void aeadEncryptsAndDecryptsWithConfiguredKeyset() throws Exception {
        contextRunner.withPropertyValues("encrypt.keyset=" + Keysets.generate()).run(context -> {
            Aead aead = context.getBean(Aead.class);
            byte[] plaintext = "Test message".getBytes(StandardCharsets.UTF_8);
            assertThat(aead.decrypt(aead.encrypt(plaintext, new byte[0]), new byte[0]))
                    .isEqualTo(plaintext);
        });
    }

    @Test
    void startupFailsWhenKeysetIsMissing() {
        contextRunner.run(context -> assertThat(context)
                .hasFailed()
                .getFailure()
                .hasRootCauseInstanceOf(BindValidationException.class)
                .rootCause()
                .hasMessageContaining("keyset"));
    }

    @Test
    void startupFailsWhenKeysetIsBlank() {
        contextRunner
                .withPropertyValues("encrypt.keyset= ")
                .run(context -> assertThat(context)
                        .hasFailed()
                        .getFailure()
                        .hasRootCauseInstanceOf(BindValidationException.class));
    }

    @Test
    void startupFailsWhenKeysetHoldsNoAeadKey() throws Exception {
        MacConfig.register();
        String macKeyset = Keysets.encode(KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG));

        contextRunner
                .withPropertyValues("encrypt.keyset=" + macKeyset)
                .run(context -> assertThat(context)
                        .hasFailed()
                        .getFailure()
                        .hasRootCauseInstanceOf(GeneralSecurityException.class));
    }

    @Test
    void startupFailsWhenBothKeysetAndKmsAreSet() throws Exception {
        contextRunner
                .withSystemProperties("aws.region=us-east-1")
                .withPropertyValues(
                        "encrypt.keyset=" + Keysets.generate(),
                        "encrypt.kms.key-arn=arn:aws:kms:us-east-1:000000000000:key/test",
                        "encrypt.kms.encrypted-keyset=wrapped")
                .run(context -> assertThat(context)
                        .hasFailed()
                        .getFailure()
                        .hasRootCauseInstanceOf(BindValidationException.class)
                        .rootCause()
                        .hasMessageContaining("exactly one"));
    }

    @Test
    void startupFailsWhenKmsKeyArnIsBlank() {
        contextRunner
                .withSystemProperties("aws.region=us-east-1")
                .withPropertyValues("encrypt.kms.key-arn= ", "encrypt.kms.encrypted-keyset=wrapped")
                .run(context -> assertThat(context)
                        .hasFailed()
                        .getFailure()
                        .hasRootCauseInstanceOf(BindValidationException.class)
                        .rootCause()
                        .hasMessageContaining("keyArn"));
    }

    @Test
    void propertiesHideKeysetFromToString() {
        assertThat(new EncryptProperties("secret-keyset", null, "secret-hybrid"))
                .hasToString("EncryptProperties[keyset=***, kms=null, hybridKeyset=***]");
    }
}
