package dev.jaderss.encrypt.integration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import dev.jaderss.encrypt.TestKeysetConfig;
import org.springframework.context.annotation.Import;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestKeysetConfig.class)
class EncryptionIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private String getBaseUrl() {
        return "http://localhost:" + port;
    }

    @Test
    void encryptAndDecrypt_ShouldWorkEndToEnd_WithSimpleText() {
        // Given
        String originalText = "Hello World!";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        // When - Encrypt
        HttpEntity<String> encryptRequest = new HttpEntity<>(originalText, headers);
        ResponseEntity<String> encryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/encrypt", encryptRequest, String.class);

        // Then - Verify encryption
        assertThat(encryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(encryptResponse.getBody()).isNotNull();
        assertThat(encryptResponse.getBody()).isNotEmpty();
        assertThat(encryptResponse.getBody()).isNotEqualTo(originalText);

        // When - Decrypt
        String encryptedText = encryptResponse.getBody();
        HttpEntity<String> decryptRequest = new HttpEntity<>(encryptedText, headers);
        ResponseEntity<String> decryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/decrypt", decryptRequest, String.class);

        // Then - Verify decryption
        assertThat(decryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decryptResponse.getBody()).isEqualTo(originalText);
    }

    @Test
    void encryptAndDecrypt_ShouldWorkEndToEnd_WithSpecialCharacters() {
        // Given
        String originalText = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        // When - Encrypt
        HttpEntity<String> encryptRequest = new HttpEntity<>(originalText, headers);
        ResponseEntity<String> encryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/encrypt", encryptRequest, String.class);

        // Then - Verify encryption
        assertThat(encryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(encryptResponse.getBody()).isNotNull();
        assertThat(encryptResponse.getBody()).isNotEmpty();
        assertThat(encryptResponse.getBody()).isNotEqualTo(originalText);

        // When - Decrypt
        String encryptedText = encryptResponse.getBody();
        HttpEntity<String> decryptRequest = new HttpEntity<>(encryptedText, headers);
        ResponseEntity<String> decryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/decrypt", decryptRequest, String.class);

        // Then - Verify decryption
        assertThat(decryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decryptResponse.getBody()).isEqualTo(originalText);
    }

    @Test
    void encryptAndDecrypt_ShouldWorkEndToEnd_WithUnicodeCharacters() {
        // Given
        String originalText = "Unicode: 你好世界 🌍 émojis";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        // When - Encrypt
        HttpEntity<String> encryptRequest = new HttpEntity<>(originalText, headers);
        ResponseEntity<String> encryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/encrypt", encryptRequest, String.class);

        // Then - Verify encryption
        assertThat(encryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(encryptResponse.getBody()).isNotNull();
        assertThat(encryptResponse.getBody()).isNotEmpty();
        assertThat(encryptResponse.getBody()).isNotEqualTo(originalText);

        // When - Decrypt
        String encryptedText = encryptResponse.getBody();
        HttpEntity<String> decryptRequest = new HttpEntity<>(encryptedText, headers);
        ResponseEntity<String> decryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/decrypt", decryptRequest, String.class);

        // Then - Verify decryption
        assertThat(decryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decryptResponse.getBody()).isEqualTo(originalText);
    }

    @Test
    void encryptAndDecrypt_ShouldWorkEndToEnd_WithLongText() {
        // Given
        StringBuilder longText = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            longText.append("This is a long text for testing encryption and decryption. ");
        }
        String originalText = longText.toString();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        // When - Encrypt
        HttpEntity<String> encryptRequest = new HttpEntity<>(originalText, headers);
        ResponseEntity<String> encryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/encrypt", encryptRequest, String.class);

        // Then - Verify encryption
        assertThat(encryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(encryptResponse.getBody()).isNotNull();
        assertThat(encryptResponse.getBody()).isNotEmpty();
        assertThat(encryptResponse.getBody()).isNotEqualTo(originalText);

        // When - Decrypt
        String encryptedText = encryptResponse.getBody();
        HttpEntity<String> decryptRequest = new HttpEntity<>(encryptedText, headers);
        ResponseEntity<String> decryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/decrypt", decryptRequest, String.class);

        // Then - Verify decryption
        assertThat(decryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decryptResponse.getBody()).isEqualTo(originalText.trim());
    }

    @Test
    void encrypt_ShouldTrimWhitespace() {
        // Given
        String originalText = "  Hello World!  ";
        String expectedTrimmed = "Hello World!";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        // When - Encrypt
        HttpEntity<String> encryptRequest = new HttpEntity<>(originalText, headers);
        ResponseEntity<String> encryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/encrypt", encryptRequest, String.class);

        // Then - Verify encryption
        assertThat(encryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(encryptResponse.getBody()).isNotNull();
        assertThat(encryptResponse.getBody()).isNotEmpty();

        // When - Decrypt to verify trimming occurred
        String encryptedText = encryptResponse.getBody();
        HttpEntity<String> decryptRequest = new HttpEntity<>(encryptedText, headers);
        ResponseEntity<String> decryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/decrypt", decryptRequest, String.class);

        // Then - Verify decryption returns trimmed text
        assertThat(decryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decryptResponse.getBody()).isEqualTo(expectedTrimmed);
    }

    @Test
    void decrypt_ShouldTrimWhitespace() {
        // Given
        String originalText = "Hello World!";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        // First encrypt the text
        HttpEntity<String> encryptRequest = new HttpEntity<>(originalText, headers);
        ResponseEntity<String> encryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/encrypt", encryptRequest, String.class);
        String encryptedText = encryptResponse.getBody();

        // When - Decrypt with whitespace
        String encryptedTextWithSpaces = "  " + encryptedText + "  ";
        HttpEntity<String> decryptRequest = new HttpEntity<>(encryptedTextWithSpaces, headers);
        ResponseEntity<String> decryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/decrypt", decryptRequest, String.class);

        // Then - Verify decryption works despite whitespace
        assertThat(decryptResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decryptResponse.getBody()).isEqualTo(originalText);
    }

    @Test
    void decrypt_ShouldReturn500_WhenGivenInvalidCiphertext() {
        // Given
        String invalidCiphertext = "invalid-ciphertext";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        // When
        HttpEntity<String> decryptRequest = new HttpEntity<>(invalidCiphertext, headers);
        ResponseEntity<String> decryptResponse = restTemplate.postForEntity(
                getBaseUrl() + "/decrypt", decryptRequest, String.class);

        // Then
        assertThat(decryptResponse.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void encrypt_ShouldReturn415_WhenWrongContentType() {
        // Given
        String jsonContent = "{\"text\":\"Hello World!\"}";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // When
        HttpEntity<String> request = new HttpEntity<>(jsonContent, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(
                getBaseUrl() + "/encrypt", request, String.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
    }
}
