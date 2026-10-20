package dev.jaderss.encrypt.service;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.Aead;
import dev.jaderss.encrypt.TestKeysetConfig;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class SecurityServiceTest {

    private final SecurityService securityService = newService();

    @ParameterizedTest
    @MethodSource("dev.jaderss.encrypt.Samples#plaintexts")
    void decryptRestoresPlaintextEncryptedInSameContext(String plaintext) throws GeneralSecurityException {
        assertThat(securityService.decrypt(CONTEXT, securityService.encrypt(CONTEXT, plaintext)))
                .isEqualTo(plaintext);
    }

    @ParameterizedTest
    @CsvSource({"other-tenant, ssn", "acme, email"})
    void decryptRejectsCiphertextMovedToAnotherContext(String tenantId, String field) throws GeneralSecurityException {
        String ciphertext = securityService.encrypt(CONTEXT, "123-45-6789");

        assertThatThrownBy(() -> securityService.decrypt(new EncryptionContext(tenantId, field), ciphertext))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void encryptReturnsBase64CiphertextThatDiffersFromPlaintext() throws GeneralSecurityException {
        assertThat(securityService.encrypt(CONTEXT, "Hello World!")).isBase64().isNotEqualTo("Hello World!");
    }

    @Test
    void encryptProducesDifferentCiphertextForSamePlaintext() throws GeneralSecurityException {
        assertThat(securityService.encrypt(CONTEXT, "Hello World!"))
                .isNotEqualTo(securityService.encrypt(CONTEXT, "Hello World!"));
    }

    @Test
    void decryptRejectsInvalidBase64() {
        assertThatIllegalArgumentException().isThrownBy(() -> securityService.decrypt(CONTEXT, "invalid-base64!@#"));
    }

    @Test
    void decryptRejectsBase64ThatIsNotCiphertext() {
        String notCiphertext = Base64.getEncoder().encodeToString("not a ciphertext".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> securityService.decrypt(CONTEXT, notCiphertext))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void decryptRejectsCiphertextFromAnotherKeyset() throws GeneralSecurityException {
        String foreignCiphertext = newService().encrypt(CONTEXT, "Hello World!");

        assertThatThrownBy(() -> securityService.decrypt(CONTEXT, foreignCiphertext))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void encryptRejectsMissingContext() {
        assertThatNullPointerException()
                .isThrownBy(() -> securityService.encrypt(null, "Hello World!"))
                .withMessage("context");
    }

    @Test
    void encryptRejectsMissingPlaintext() {
        assertThatNullPointerException()
                .isThrownBy(() -> securityService.encrypt(CONTEXT, null))
                .withMessage("plaintext");
    }

    @Test
    void decryptRejectsMissingCiphertext() {
        assertThatNullPointerException()
                .isThrownBy(() -> securityService.decrypt(CONTEXT, null))
                .withMessage("ciphertext");
    }

    private static SecurityService newService() {
        try {
            return new SecurityService(TestKeysetConfig.newKeysetHandle().getPrimitive(Aead.class));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
