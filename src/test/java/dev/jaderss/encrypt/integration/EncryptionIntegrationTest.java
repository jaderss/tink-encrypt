package dev.jaderss.encrypt.integration;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;

import dev.jaderss.encrypt.TestKeysetConfig;
import dev.jaderss.encrypt.controller.CiphertextRequest;
import dev.jaderss.encrypt.controller.CiphertextResponse;
import dev.jaderss.encrypt.controller.PlaintextRequest;
import dev.jaderss.encrypt.controller.PlaintextResponse;
import dev.jaderss.encrypt.service.EncryptionContext;
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

    private final RestClient client;

    EncryptionIntegrationTest(@LocalServerPort int port) {
        client = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @ParameterizedTest
    @MethodSource("dev.jaderss.encrypt.Samples#plaintexts")
    void decryptRestoresPlaintextEncryptedOverHttp(String plaintext) {
        ResponseEntity<CiphertextResponse> encrypted =
                post("/encrypt", new PlaintextRequest(CONTEXT, plaintext), CiphertextResponse.class);
        assertThat(encrypted.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<PlaintextResponse> decrypted = post(
                "/decrypt", new CiphertextRequest(CONTEXT, encrypted.getBody().ciphertext()), PlaintextResponse.class);
        assertThat(decrypted.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decrypted.getBody()).isEqualTo(new PlaintextResponse(plaintext));
    }

    @Test
    void reencryptReturnsNewCiphertextForSamePlaintext() {
        String ciphertext = post("/encrypt", new PlaintextRequest(CONTEXT, "123-45-6789"), CiphertextResponse.class)
                .getBody()
                .ciphertext();

        String reencrypted = post("/reencrypt", new CiphertextRequest(CONTEXT, ciphertext), CiphertextResponse.class)
                .getBody()
                .ciphertext();

        assertThat(reencrypted).isNotEqualTo(ciphertext);
        assertThat(post("/decrypt", new CiphertextRequest(CONTEXT, reencrypted), PlaintextResponse.class)
                        .getBody())
                .isEqualTo(new PlaintextResponse("123-45-6789"));
    }

    @Test
    void decryptFailsWhenCiphertextIsMovedToAnotherTenant() {
        String ciphertext = post("/encrypt", new PlaintextRequest(CONTEXT, "123-45-6789"), CiphertextResponse.class)
                .getBody()
                .ciphertext();
        EncryptionContext otherTenant = new EncryptionContext("other-tenant", CONTEXT.field());

        assertThat(post("/decrypt", new CiphertextRequest(otherTenant, ciphertext), String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void encryptRejectsContextWithSeparatorInTenantId() {
        String body = "{\"context\":{\"tenantId\":\"acme:ssn\",\"field\":\"x\"},\"plaintext\":\"Hello\"}";

        assertThat(post("/encrypt", body, String.class).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void hybridEndpointsAreAbsentWithoutHybridKeyset() {
        assertThat(client.get()
                        .uri("/hybrid/public-key")
                        .retrieve()
                        .toBodilessEntity()
                        .getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    private <T> ResponseEntity<T> post(String path, Object request, Class<T> responseType) {
        return client.post()
                .uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .toEntity(responseType);
    }
}
