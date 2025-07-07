package dev.jaderss.encrypt.config;

import com.google.crypto.tink.KeysetHandle;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
    "encrypt.key=REDACTED_KEYSET"
})
class SecurityConfigTest {

    @Autowired
    private KeysetHandle keysetHandle;

    @Test
    void keysetHandle_ShouldBeCreated_WhenValidKeyProvided() {
        // Then
        assertThat(keysetHandle).isNotNull();
    }

    @Test
    void keysetHandle_ShouldBeUsableForEncryption() throws Exception {
        // Given
        com.google.crypto.tink.Aead aead = keysetHandle.getPrimitive(com.google.crypto.tink.Aead.class);
        String plaintext = "Test message";

        // When
        byte[] ciphertext = aead.encrypt(plaintext.getBytes(), new byte[0]);
        byte[] decrypted = aead.decrypt(ciphertext, new byte[0]);

        // Then
        assertThat(new String(decrypted)).isEqualTo(plaintext);
    }
}