package dev.jaderss.encrypt.integration;

import static org.assertj.core.api.Assertions.assertThat;

import dev.jaderss.encrypt.TestKeysetConfig;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestKeysetConfig.class)
class EncryptionIntegrationTest {

    private static final MediaType TEXT_PLAIN_UTF8 = new MediaType(MediaType.TEXT_PLAIN, StandardCharsets.UTF_8);

    private final RestClient client;

    EncryptionIntegrationTest(@LocalServerPort int port) {
        client = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @ParameterizedTest
    @MethodSource("dev.jaderss.encrypt.SamplePlaintexts#nonEmpty")
    void decryptRestoresPlaintextEncryptedOverHttp(String plaintext) {
        ResponseEntity<String> encrypted = post("/encrypt", TEXT_PLAIN_UTF8, plaintext);
        assertThat(encrypted.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(encrypted.getBody()).isBase64().isNotEqualTo(plaintext);

        ResponseEntity<String> decrypted = post("/decrypt", TEXT_PLAIN_UTF8, encrypted.getBody());
        assertThat(decrypted.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decrypted.getBody()).isEqualTo(plaintext);
    }

    @Test
    void encryptStoresTrimmedPlaintext() {
        assertThat(decrypt(encrypt("  Hello World!  "))).isEqualTo("Hello World!");
    }

    @Test
    void decryptAcceptsCiphertextSurroundedByWhitespace() {
        assertThat(decrypt("  " + encrypt("Hello World!") + "  ")).isEqualTo("Hello World!");
    }

    @Test
    void decryptReturnsServerErrorForInvalidCiphertext() {
        assertThat(post("/decrypt", TEXT_PLAIN_UTF8, "invalid-ciphertext").getStatusCode())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void encryptRejectsJsonContentType() {
        assertThat(post("/encrypt", MediaType.APPLICATION_JSON, "{\"text\":\"Hello\"}")
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
    }

    private String encrypt(String plaintext) {
        return post("/encrypt", TEXT_PLAIN_UTF8, plaintext).getBody();
    }

    private String decrypt(String ciphertext) {
        return post("/decrypt", TEXT_PLAIN_UTF8, ciphertext).getBody();
    }

    private ResponseEntity<String> post(String path, MediaType contentType, String body) {
        return client.post()
                .uri(path)
                .contentType(contentType)
                .body(body)
                .retrieve()
                .toEntity(String.class);
    }
}
