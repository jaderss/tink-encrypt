package dev.jaderss.encrypt.integration;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;

import dev.jaderss.encrypt.TestKeysetConfig;
import dev.jaderss.encrypt.controller.DecryptRequest;
import dev.jaderss.encrypt.controller.DecryptResponse;
import dev.jaderss.encrypt.controller.EncryptRequest;
import dev.jaderss.encrypt.controller.EncryptResponse;
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
        ResponseEntity<EncryptResponse> encrypted =
                post("/encrypt", new EncryptRequest(CONTEXT, plaintext), EncryptResponse.class);
        assertThat(encrypted.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<DecryptResponse> decrypted =
                post("/decrypt", new DecryptRequest(CONTEXT, encrypted.getBody().ciphertext()), DecryptResponse.class);
        assertThat(decrypted.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(decrypted.getBody()).isEqualTo(new DecryptResponse(plaintext));
    }

    @Test
    void decryptFailsWhenCiphertextIsMovedToAnotherTenant() {
        String ciphertext = post("/encrypt", new EncryptRequest(CONTEXT, "123-45-6789"), EncryptResponse.class)
                .getBody()
                .ciphertext();
        EncryptionContext otherTenant = new EncryptionContext("other-tenant", CONTEXT.field());

        assertThat(post("/decrypt", new DecryptRequest(otherTenant, ciphertext), String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void encryptRejectsContextWithSeparatorInTenantId() {
        String body = "{\"context\":{\"tenantId\":\"acme:ssn\",\"field\":\"x\"},\"plaintext\":\"Hello\"}";

        assertThat(post("/encrypt", body, String.class).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
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
