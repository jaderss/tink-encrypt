package dev.jaderss.encrypt.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.Aead;
import dev.jaderss.encrypt.SamplePlaintexts;
import dev.jaderss.encrypt.TestKeysetConfig;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class SecurityServiceTest {

    private final SecurityService securityService;

    SecurityServiceTest() throws GeneralSecurityException {
        securityService = new SecurityService(TestKeysetConfig.newKeysetHandle().getPrimitive(Aead.class));
    }

    static Stream<String> plaintexts() {
        return Stream.concat(Stream.of(""), SamplePlaintexts.nonEmpty());
    }

    @ParameterizedTest
    @MethodSource("plaintexts")
    void decryptRestoresEncryptedPlaintext(String plaintext) throws GeneralSecurityException {
        assertThat(securityService.decrypt(securityService.encrypt(plaintext))).isEqualTo(plaintext);
    }

    @Test
    void encryptReturnsBase64CiphertextThatDiffersFromPlaintext() throws GeneralSecurityException {
        assertThat(securityService.encrypt("Hello World!")).isBase64().isNotEqualTo("Hello World!");
    }

    @Test
    void encryptProducesDifferentCiphertextForSamePlaintext() throws GeneralSecurityException {
        assertThat(securityService.encrypt("Hello World!")).isNotEqualTo(securityService.encrypt("Hello World!"));
    }

    @Test
    void decryptRejectsInvalidBase64() {
        assertThatIllegalArgumentException().isThrownBy(() -> securityService.decrypt("invalid-base64!@#"));
    }

    @Test
    void decryptRejectsBase64ThatIsNotCiphertext() {
        String notCiphertext = Base64.getEncoder().encodeToString("not a ciphertext".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> securityService.decrypt(notCiphertext)).isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void decryptRejectsCiphertextFromAnotherKeyset() throws GeneralSecurityException {
        SecurityService otherService =
                new SecurityService(TestKeysetConfig.newKeysetHandle().getPrimitive(Aead.class));
        String foreignCiphertext = otherService.encrypt("Hello World!");

        assertThatThrownBy(() -> securityService.decrypt(foreignCiphertext))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void encryptRejectsNullPlaintext() {
        assertThatNullPointerException().isThrownBy(() -> securityService.encrypt(null));
    }

    @Test
    void decryptRejectsNullCiphertext() {
        assertThatNullPointerException().isThrownBy(() -> securityService.decrypt(null));
    }
}
