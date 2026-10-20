package dev.jaderss.encrypt.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EncryptionContextTest {

    @Test
    void associatedDataJoinsTenantAndField() {
        assertThat(new EncryptionContext("acme", "ssn").associatedData())
                .isEqualTo("acme:ssn".getBytes(StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "acme:ssn", "acme ssn", "acmé", "tenant/1"})
    void rejectsTenantIdOutsideIdentifierAlphabet(String tenantId) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new EncryptionContext(tenantId, "ssn"))
                .withMessageContaining("tenantId");
    }

    @Test
    void rejectsFieldLongerThanSixtyFourCharacters() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new EncryptionContext("acme", "f".repeat(65)))
                .withMessageContaining("field");
    }

    @Test
    void acceptsFieldOfSixtyFourCharacters() {
        assertThat(new EncryptionContext("acme", "f".repeat(64)).field()).hasSize(64);
    }

    @Test
    void rejectsMissingField() {
        assertThatNullPointerException()
                .isThrownBy(() -> new EncryptionContext("acme", null))
                .withMessage("field");
    }
}
