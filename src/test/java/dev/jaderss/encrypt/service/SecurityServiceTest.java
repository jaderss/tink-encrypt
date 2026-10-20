package dev.jaderss.encrypt.service;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.Aead;
import dev.jaderss.encrypt.keyset.Keysets;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class SecurityServiceTest {

    private final String keyset = unchecked(Keysets::generate);
    private final SecurityService securityService = serviceFor(keyset);

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
        String foreignCiphertext = serviceFor(Keysets.generate()).encrypt(CONTEXT, "Hello World!");

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

    @Nested
    class KeyRotation {

        private final String rotatedKeyset = unchecked(() -> Keysets.rotate(keyset));
        private final SecurityService rotatedService = serviceFor(rotatedKeyset);

        @Test
        void ciphertextFromBeforeRotationStillDecrypts() throws GeneralSecurityException {
            String ciphertext = securityService.encrypt(CONTEXT, "123-45-6789");

            assertThat(rotatedService.decrypt(CONTEXT, ciphertext)).isEqualTo("123-45-6789");
        }

        @Test
        void newCiphertextIsEncryptedWithNewPrimaryKey() throws GeneralSecurityException {
            String ciphertext = rotatedService.encrypt(CONTEXT, "123-45-6789");

            assertThatThrownBy(() -> securityService.decrypt(CONTEXT, ciphertext))
                    .isInstanceOf(GeneralSecurityException.class);
        }

        @Test
        void reencryptedCiphertextSurvivesRetiringOldKeys() throws GeneralSecurityException {
            String oldCiphertext = securityService.encrypt(CONTEXT, "123-45-6789");
            String reencrypted = rotatedService.reencrypt(CONTEXT, oldCiphertext);
            SecurityService retiredService = serviceFor(Keysets.retire(rotatedKeyset));

            assertThat(retiredService.decrypt(CONTEXT, reencrypted)).isEqualTo("123-45-6789");
            assertThatThrownBy(() -> retiredService.decrypt(CONTEXT, oldCiphertext))
                    .isInstanceOf(GeneralSecurityException.class);
        }

        @Test
        void reencryptRejectsCiphertextFromAnotherContext() throws GeneralSecurityException {
            String ciphertext = securityService.encrypt(CONTEXT, "123-45-6789");

            assertThatThrownBy(() -> rotatedService.reencrypt(new EncryptionContext("other-tenant", "ssn"), ciphertext))
                    .isInstanceOf(GeneralSecurityException.class);
        }
    }

    private static SecurityService serviceFor(String keyset) {
        return unchecked(() -> new SecurityService(Keysets.parse(keyset).getPrimitive(Aead.class)));
    }

    private static <T> T unchecked(Callable<T> call) {
        try {
            return call.call();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
