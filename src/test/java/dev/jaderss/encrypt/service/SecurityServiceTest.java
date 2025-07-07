package dev.jaderss.encrypt.service;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.GeneralSecurityException;
import java.io.IOException;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SecurityServiceTest {

    private SecurityService securityService;
    private KeysetHandle keysetHandle;

    @BeforeEach
    void setUp() throws GeneralSecurityException {
        // Register AEAD configuration
        AeadConfig.register();
        // Generate a test key for each test
        keysetHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
        securityService = new SecurityService(keysetHandle);
    }

    @Test
    void encrypt_ShouldReturnBase64EncodedString_WhenGivenPlaintext() throws GeneralSecurityException {
        // Given
        String plaintext = "Hello World!";

        // When
        String encrypted = securityService.encrypt(plaintext);

        // Then
        assertThat(encrypted).isNotNull();
        assertThat(encrypted).isNotEmpty();
        assertThat(encrypted).isNotEqualTo(plaintext);

        // Verify it's valid Base64
        assertThatCode(() -> Base64.getDecoder().decode(encrypted))
                .doesNotThrowAnyException();
    }

    @Test
    void encrypt_ShouldReturnDifferentResults_ForSameInput() throws GeneralSecurityException {
        // Given
        String plaintext = "Hello World!";

        // When
        String encrypted1 = securityService.encrypt(plaintext);
        String encrypted2 = securityService.encrypt(plaintext);

        // Then
        assertThat(encrypted1).isNotEqualTo(encrypted2);
    }

    @Test
    void encrypt_ShouldHandleEmptyString() throws GeneralSecurityException {
        // Given
        String plaintext = "";

        // When
        String encrypted = securityService.encrypt(plaintext);

        // Then
        assertThat(encrypted).isNotNull();
        assertThat(encrypted).isNotEmpty();
    }

    @Test
    void encrypt_ShouldHandleSpecialCharacters() throws GeneralSecurityException {
        // Given
        String plaintext = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?";

        // When
        String encrypted = securityService.encrypt(plaintext);

        // Then
        assertThat(encrypted).isNotNull();
        assertThat(encrypted).isNotEmpty();
    }

    @Test
    void encrypt_ShouldHandleUnicodeCharacters() throws GeneralSecurityException {
        // Given
        String plaintext = "Unicode: 你好世界 🌍 émojis";

        // When
        String encrypted = securityService.encrypt(plaintext);

        // Then
        assertThat(encrypted).isNotNull();
        assertThat(encrypted).isNotEmpty();
    }

    @Test
    void decrypt_ShouldReturnOriginalPlaintext_WhenGivenValidCiphertext() throws GeneralSecurityException {
        // Given
        String originalText = "Hello World!";
        String encrypted = securityService.encrypt(originalText);

        // When
        String decrypted = securityService.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(originalText);
    }

    @Test
    void decrypt_ShouldHandleEmptyStringEncryption() throws GeneralSecurityException {
        // Given
        String originalText = "";
        String encrypted = securityService.encrypt(originalText);

        // When
        String decrypted = securityService.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(originalText);
    }

    @Test
    void decrypt_ShouldHandleSpecialCharacters() throws GeneralSecurityException {
        // Given
        String originalText = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?";
        String encrypted = securityService.encrypt(originalText);

        // When
        String decrypted = securityService.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(originalText);
    }

    @Test
    void decrypt_ShouldHandleUnicodeCharacters() throws GeneralSecurityException {
        // Given
        String originalText = "Unicode: 你好世界 🌍 émojis";
        String encrypted = securityService.encrypt(originalText);

        // When
        String decrypted = securityService.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(originalText);
    }

    @Test
    void decrypt_ShouldThrowException_WhenGivenInvalidBase64() {
        // Given
        String invalidBase64 = "invalid-base64!@#";

        // When & Then
        assertThatThrownBy(() -> securityService.decrypt(invalidBase64))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decrypt_ShouldThrowException_WhenGivenInvalidCiphertext() {
        // Given
        String invalidCiphertext = Base64.getEncoder().encodeToString("invalid ciphertext".getBytes());

        // When & Then
        assertThatThrownBy(() -> securityService.decrypt(invalidCiphertext))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void generateKey_ShouldReturnValidBase64EncodedKey() throws GeneralSecurityException, IOException {
        // When
        String generatedKey = securityService.generateKey();

        // Then
        assertThat(generatedKey).isNotNull();
        assertThat(generatedKey).isNotEmpty();

        // Verify it's valid Base64
        assertThatCode(() -> Base64.getDecoder().decode(generatedKey))
                .doesNotThrowAnyException();
    }

    @Test
    void generateKey_ShouldReturnDifferentKeys_OnMultipleCalls() throws GeneralSecurityException, IOException {
        // When
        String key1 = securityService.generateKey();
        String key2 = securityService.generateKey();

        // Then
        assertThat(key1).isNotEqualTo(key2);
    }

    @Test
    void encryptDecrypt_ShouldWorkWithLongText() throws GeneralSecurityException {
        // Given
        StringBuilder longText = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longText.append("This is a long text for testing encryption and decryption. ");
        }
        String originalText = longText.toString();

        // When
        String encrypted = securityService.encrypt(originalText);
        String decrypted = securityService.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(originalText);
    }

    @Test
    void encrypt_ShouldThrowException_WhenGivenNullInput() {
        // When & Then
        assertThatThrownBy(() -> securityService.encrypt(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void decrypt_ShouldThrowException_WhenGivenNullInput() {
        // When & Then
        assertThatThrownBy(() -> securityService.decrypt(null))
                .isInstanceOf(NullPointerException.class);
    }
}
